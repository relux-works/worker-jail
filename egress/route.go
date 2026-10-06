package egress

import (
	"regexp"
	"strings"

	"github.com/relux-works/worker-jail/jail"
)

// Denial codes (egress.md §5).
const (
	CodeNoPolicy = "no-policy"
	CodeMode     = "mode"
	CodeMethod   = "method"
	CodeGrammar  = "grammar"
	CodeModule   = "module"
	CodeHost     = "host"
	CodePort     = "port"
	CodeGuard    = "guard"
	CodeRate     = "rate"
	CodeSize     = "size"
	CodeUpstream = "upstream"
)

// Handlers a request can be routed to.
const (
	handlerModules = "modules"
	handlerConnect = "connect" // generic: CONNECT host:port
	handlerHTTP    = "http"    // generic: absolute-URI GET or HEAD
)

// route applies the routing table of egress.md §3 to a request on a listener of the given mode.
// It returns the handler, or "" and the denial code. A modules listener serves only the origin form, a generic listener
// (allowlist, denylist, all) only CONNECT and the absolute form; the other forms are mode. Methods other than CONNECT,
// GET and HEAD are method (a generic listener forwards no request body). On a listener of any other mode every request
// is mode (no such listener is opened; this is the second line of defence).
func route(mode string, req *Request) (handler, code string) {
	generic := mode == jail.NetAllowlist || mode == jail.NetDenylist || mode == jail.NetAll
	if mode != jail.NetModules && !generic {
		return "", CodeMode
	}
	h := ""
	switch {
	case req.Method == "CONNECT":
		h = handlerConnect
	case req.Method != "GET" && req.Method != "HEAD":
		return "", CodeMethod
	case strings.HasPrefix(req.Target, "/"):
		h = handlerModules
	case absoluteForm(req.Target):
		h = handlerHTTP
	default:
		return "", CodeMethod
	}
	if (h == handlerModules) != generic {
		return h, ""
	}
	return "", CodeMode
}

var schemeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

func absoluteForm(target string) bool { return schemeRE.MatchString(target) }

// Path kinds of the modules grammar.
const (
	kindList      = "list"
	kindInfo      = "info"
	kindMod       = "mod"
	kindZip       = "zip"
	kindLatest    = "latest"
	kindSupported = "sumdb-supported"
	kindSumLatest = "sumdb-latest"
	kindLookup    = "sumdb-lookup"
	kindTile      = "sumdb-tile"
)

// Upstream hosts, fixed in code (egress.md §4).
const (
	proxyHost = "proxy.golang.org"
	sumHost   = "sum.golang.org"
)

const maxPathBytes = 1 << 10

// modPath is a request path that passed the modules grammar.
type modPath struct {
	Kind     string
	Module   string // unescaped module path; empty for supported, latest and tiles
	Version  string // unescaped version, for info, mod, zip and lookup
	Upstream string // proxyHost, sumHost, or "" when the service answers itself
	Rest     string // path on the upstream, still escaped as received, with a leading /
}

// Immutable reports whether the object can be cached: a version's files and sumdb tiles.
func (p modPath) Immutable() bool {
	switch p.Kind {
	case kindInfo, kindMod, kindZip, kindTile:
		return true
	}
	return false
}

type grammarError string

func (e grammarError) Error() string { return string(e) }

var tileRE = regexp.MustCompile(`^([1-9]|[12][0-9]|30)/(data|[0-9]|[1-9][0-9])/((?:x[0-9]{3}/)*[0-9]{3})(?:\.p/([1-9][0-9]{0,8}))?$`)

// parseModulesPath validates an origin-form target against the modules grammar (egress.md §4):
//
//	/gomod/<module>/@v/list
//	/gomod/<module>/@v/<version>.info|.mod|.zip
//	/gomod/<module>/@latest
//	/gomod/sumdb/sum.golang.org/supported|latest
//	/gomod/sumdb/sum.golang.org/lookup/<module>@<version>
//	/gomod/sumdb/sum.golang.org/tile/<H>/<L>/<K>[.p/<W>]
//
// Module paths and versions are in the proxy's escaped form (`!x` for `X`) and are unescaped. Rejected before
// anything leaves: a path over 1 KiB, any '%', '?', '#' or '\', empty, '.' or '..' elements, a non-canonical version,
// and any sumdb name but sum.golang.org.
func parseModulesPath(target string) (modPath, error) {
	var p modPath
	if len(target) > maxPathBytes {
		return p, grammarError("path exceeds 1 KiB")
	}
	if strings.ContainsAny(target, "%?#\\") {
		return p, grammarError("encoded, query or fragment characters")
	}
	rest, ok := strings.CutPrefix(target, "/gomod/")
	if !ok {
		return p, grammarError("not under /gomod/")
	}
	for _, el := range strings.Split(rest, "/") {
		if el == "" || el == "." || el == ".." {
			return p, grammarError("empty, . or .. element")
		}
	}
	p.Rest = "/" + rest
	if sum, ok := strings.CutPrefix(rest, "sumdb/"); ok {
		name, op, _ := strings.Cut(sum, "/")
		if name != sumHost {
			return p, grammarError("sumdb other than " + sumHost)
		}
		p.Upstream, p.Rest = sumHost, "/"+op
		switch {
		case op == "supported":
			p.Kind, p.Upstream = kindSupported, ""
		case op == "latest":
			p.Kind = kindSumLatest
		case strings.HasPrefix(op, "lookup/"):
			mv := strings.TrimPrefix(op, "lookup/")
			mod, ver, ok := strings.Cut(mv, "@")
			if !ok {
				return p, grammarError("lookup needs module@version")
			}
			var err error
			if p.Module, err = unescapeModule(mod); err != nil {
				return p, err
			}
			if p.Version, err = unescapeVersion(ver); err != nil {
				return p, err
			}
			p.Kind = kindLookup
		case strings.HasPrefix(op, "tile/"):
			if !tileRE.MatchString(strings.TrimPrefix(op, "tile/")) {
				return p, grammarError("tile path")
			}
			p.Kind = kindTile
		default:
			return p, grammarError("unknown sumdb operation")
		}
		return p, nil
	}
	p.Upstream = proxyHost
	if mod, ok := strings.CutSuffix(rest, "/@latest"); ok {
		var err error
		p.Kind = kindLatest
		p.Module, err = unescapeModule(mod)
		return p, err
	}
	mod, file, ok := strings.Cut(rest, "/@v/")
	if !ok {
		return p, grammarError("neither @v nor @latest")
	}
	var err error
	if p.Module, err = unescapeModule(mod); err != nil {
		return p, err
	}
	if file == "list" {
		p.Kind = kindList
		return p, nil
	}
	for _, k := range []string{kindInfo, kindMod, kindZip} {
		if ver, ok := strings.CutSuffix(file, "."+k); ok {
			p.Kind = k
			p.Version, err = unescapeVersion(ver)
			return p, err
		}
	}
	return p, grammarError("unknown @v file")
}

// unescapeModule decodes a proxy-escaped module path and checks it as Go does for module paths:
// slash-separated elements of [A-Za-z0-9-._~], none empty, none starting or ending with a dot,
// a first element with a dot, lowercase, not starting with a dash.
func unescapeModule(esc string) (string, error) {
	m, ok := unescape(esc)
	if !ok {
		return "", grammarError("module path escaping")
	}
	elems := strings.Split(m, "/")
	for i, el := range elems {
		if el == "" || el[0] == '.' || el[len(el)-1] == '.' {
			return "", grammarError("module path element")
		}
		for j := 0; j < len(el); j++ {
			c := el[j]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
				return "", grammarError("module path character")
			}
		}
		if i == 0 && (!strings.Contains(el, ".") || el[0] == '-' || strings.ToLower(el) != el) {
			return "", grammarError("module path first element")
		}
	}
	return m, nil
}

var versionRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+incompatible)?$`)

// unescapeVersion decodes a proxy-escaped version and accepts only a canonical semantic version
// (a pseudo-version is one): no build metadata but +incompatible, no leading zeros, no short forms.
func unescapeVersion(esc string) (string, error) {
	v, ok := unescape(esc)
	if !ok || len(v) > 128 || !versionRE.MatchString(v) {
		return "", grammarError("version is not canonical semver")
	}
	return v, nil
}

// unescape reverses the module proxy's case escaping: `!x` is `X`; an upper-case letter or a `!` not
// followed by a lower-case letter is invalid.
func unescape(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			return "", false
		case c == '!':
			if i+1 >= len(s) || s[i+1] < 'a' || s[i+1] > 'z' {
				return "", false
			}
			i++
			b.WriteByte(s[i] - 'a' + 'A')
		case c >= 0x80 || c <= ' ':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// masks are a policy's go_modules, anchored as the jail matches them: ^(?:mask)$.
type masks []*regexp.Regexp

func compileMasks(ms []string) (masks, error) {
	out := make(masks, 0, len(ms))
	for _, m := range ms {
		re, err := regexp.Compile(`^(?:` + m + `)$`)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

// allows reports whether p may be served under the masks. Every kind that names a module is masked
// (@v files, list, @latest and sumdb lookup); supported, sumdb latest and tiles name none.
func (ms masks) allows(p modPath) bool {
	if p.Module == "" {
		return p.Kind == kindSupported || p.Kind == kindSumLatest || p.Kind == kindTile
	}
	for _, re := range ms {
		if re.MatchString(p.Module) {
			return true
		}
	}
	return false
}
