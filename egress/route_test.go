package egress

import (
	"strings"
	"testing"

	"github.com/relux-works/remote-workplace/workplace"
)

// The routing table of egress.md §3 per mode (E2): in modules only origin-form GET and HEAD reach a handler, and
// CONNECT and absolute URIs are mode; in the generic modes only CONNECT and absolute-URI GET and HEAD reach a handler,
// and the origin form is mode; other methods are method in both; on a none listener every request is mode.
func TestRoute(t *testing.T) {
	cases := []struct {
		method, target string
		modules        string // handler, or the denial code, on a modules listener
		generic        string // on an allowlist, denylist or all listener
	}{
		{"GET", "/gomod/golang.org/x/text/@v/list", handlerModules, CodeMode},
		{"HEAD", "/gomod/golang.org/x/text/@v/list", handlerModules, CodeMode},
		{"GET", "/", handlerModules, CodeMode},
		{"CONNECT", "proxy.golang.org:443", CodeMode, handlerConnect},
		{"CONNECT", "/gomod/x", CodeMode, handlerConnect}, // the CONNECT handler refuses the target (grammar)
		{"GET", "http://proxy.golang.org/golang.org/x/text/@v/list", CodeMode, handlerHTTP},
		{"HEAD", "http://example.com/", CodeMode, handlerHTTP},
		{"GET", "HTTPS://example.com/", CodeMode, handlerHTTP}, // the HTTP handler refuses the scheme (grammar)
		{"POST", "/gomod/golang.org/x/text/@v/list", CodeMethod, CodeMethod},
		{"POST", "http://example.com/", CodeMethod, CodeMethod},
		{"PUT", "http://example.com/", CodeMethod, CodeMethod},
		{"DELETE", "http://example.com/", CodeMethod, CodeMethod},
		{"OPTIONS", "*", CodeMethod, CodeMethod},
		{"get", "/gomod/x", CodeMethod, CodeMethod},
		{"connect", "example.com:443", CodeMethod, CodeMethod},
		{"GET", "example.com:443", CodeMethod, CodeMethod},
	}
	for _, c := range cases {
		for _, m := range []struct{ mode, want string }{{workplace.NetModules, c.modules}, {workplace.NetAllowlist, c.generic},
			{workplace.NetDenylist, c.generic}, {workplace.NetAll, c.generic}, {workplace.NetNone, CodeMode}, {"bogus", CodeMode}} {
			h, code := route(m.mode, &Request{Method: c.method, Target: c.target})
			got := h + code
			if got != m.want || h != "" && code != "" {
				t.Errorf("%s %s on %s: handler %q code %q, want %q", c.method, c.target, m.mode, h, code, m.want)
			}
		}
	}
}

// The full modules grammar (E3): every accepted path kind with its unescaped module and version, next to the
// refused forms (traversal, encodings, other sumdbs, non-canonical versions, oversized paths, bad module paths).
func TestModulesGrammar(t *testing.T) {
	good := []struct {
		target, kind, module, version, upstream, rest string
	}{
		{"/gomod/golang.org/x/text/@v/list", kindList, "golang.org/x/text", "", proxyHost, "/golang.org/x/text/@v/list"},
		{"/gomod/golang.org/x/text/@v/v0.14.0.info", kindInfo, "golang.org/x/text", "v0.14.0", proxyHost, "/golang.org/x/text/@v/v0.14.0.info"},
		{"/gomod/golang.org/x/text/@v/v0.14.0.mod", kindMod, "golang.org/x/text", "v0.14.0", proxyHost, "/golang.org/x/text/@v/v0.14.0.mod"},
		{"/gomod/golang.org/x/text/@v/v0.14.0.zip", kindZip, "golang.org/x/text", "v0.14.0", proxyHost, "/golang.org/x/text/@v/v0.14.0.zip"},
		{"/gomod/github.com/!burnt!sushi/toml/@v/v1.3.2.info", kindInfo, "github.com/BurntSushi/toml", "v1.3.2", proxyHost, "/github.com/!burnt!sushi/toml/@v/v1.3.2.info"},
		{"/gomod/golang.org/x/text/@v/v0.0.0-20191109021931-daa7c04131f5.zip", kindZip, "golang.org/x/text", "v0.0.0-20191109021931-daa7c04131f5", proxyHost, ""},
		{"/gomod/github.com/a/b/@v/v2.0.0+incompatible.mod", kindMod, "github.com/a/b", "v2.0.0+incompatible", proxyHost, ""},
		{"/gomod/github.com/a/b/@v/v1.0.0-!r!c1.info", kindInfo, "github.com/a/b", "v1.0.0-RC1", proxyHost, ""},
		{"/gomod/golang.org/x/text/@latest", kindLatest, "golang.org/x/text", "", proxyHost, "/golang.org/x/text/@latest"},
		{"/gomod/sumdb/sum.golang.org/supported", kindSupported, "", "", "", "/supported"},
		{"/gomod/sumdb/sum.golang.org/latest", kindSumLatest, "", "", sumHost, "/latest"},
		{"/gomod/sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0", kindLookup, "golang.org/x/text", "v0.14.0", sumHost, "/lookup/golang.org/x/text@v0.14.0"},
		{"/gomod/sumdb/sum.golang.org/lookup/github.com/!burnt!sushi/toml@v1.3.2", kindLookup, "github.com/BurntSushi/toml", "v1.3.2", sumHost, ""},
		{"/gomod/sumdb/sum.golang.org/tile/8/0/x123/456", kindTile, "", "", sumHost, "/tile/8/0/x123/456"},
		{"/gomod/sumdb/sum.golang.org/tile/8/1/007.p/12", kindTile, "", "", sumHost, ""},
		{"/gomod/sumdb/sum.golang.org/tile/8/data/x001/x234/567", kindTile, "", "", sumHost, ""},
	}
	for _, g := range good {
		p, err := parseModulesPath(g.target)
		if err != nil {
			t.Errorf("%s: refused: %v", g.target, err)
			continue
		}
		if p.Kind != g.kind || p.Module != g.module || p.Version != g.version || p.Upstream != g.upstream || g.rest != "" && p.Rest != g.rest {
			t.Errorf("%s: parsed %+v", g.target, p)
		}
	}
	bad := []string{
		"/gomod/golang.org/x/text/@v/../../../etc/passwd",
		"/gomod/golang.org/x/../x/text/@v/list",
		"/gomod/golang.org/x/./text/@v/list",
		"/gomod/golang.org//x/text/@v/list",
		"/gomod/golang.org%2fx%2ftext/@v/list",
		"/gomod/golang.org/x/text/@v/v0.14.0%2einfo",
		"/gomod/golang.org/x/text/@v/list?x=1",
		"/gomod/golang.org/x/text/@v/list#f",
		"/gomod/golang.org\\x/text/@v/list",
		"/gomod/sumdb/sum.example.com/lookup/golang.org/x/text@v0.14.0",
		"/gomod/sumdb/sum.golang.org.evil.io/latest",
		"/gomod/sumdb/sum.golang.org/../latest",
		"/gomod/sumdb/sum.golang.org/lookup/golang.org/x/text",
		"/gomod/sumdb/sum.golang.org/lookup/golang.org/x/text@latest",
		"/gomod/sumdb/sum.golang.org/tile/31/0/123",
		"/gomod/sumdb/sum.golang.org/tile/8/0/x12/345",
		"/gomod/sumdb/sum.golang.org/tile/8/0/123.p/0",
		"/gomod/sumdb/sum.golang.org/tile/8/0/123.p/",
		"/gomod/sumdb/sum.golang.org/other",
		"/gomod/sumdb/sum.golang.org",
		"/gomod/golang.org/x/text/@v/v0.14.info",
		"/gomod/golang.org/x/text/@v/0.14.0.info",
		"/gomod/golang.org/x/text/@v/v01.14.0.info",
		"/gomod/golang.org/x/text/@v/v0.14.0+build.info",
		"/gomod/golang.org/x/text/@v/v0.14.0-01.info",
		"/gomod/golang.org/x/text/@v/latest.info",
		"/gomod/golang.org/x/text/@v/v0.14.0.txt",
		"/gomod/golang.org/x/text/@v/",
		"/gomod/golang.org/x/text/@v/v0.14.0-R.info", // upper case must be escaped
		"/gomod/golang.org/x/Text/@v/list",           // upper case must be escaped
		"/gomod/golang.org/x/!/@v/list",
		"/gomod/golang.org/x/te!1xt/@v/list",
		"/gomod/golang.org/x/te$t/@v/list",
		"/gomod/golang.org/x/.text/@v/list",
		"/gomod/golang.org/x/text./@v/list",
		"/gomod/localhost/x/@v/list",
		"/gomod/-golang.org/x/@v/list",
		"/gomod/golang.org/x/text/@latest/x",
		"/gomod/golang.org/x/text",
		"/gomod/",
		"/gomod",
		"/golang.org/x/text/@v/list",
		"/gomod/golang.org/x/text/@v/list/",
		"/gomod/" + strings.Repeat("a", maxPathBytes) + ".org/@v/list",
	}
	for _, b := range bad {
		if p, err := parseModulesPath(b); err == nil {
			t.Errorf("%s: accepted as %+v", b, p)
		}
	}
}

// Module masks apply to every path kind that names a module: @v files, list, @latest and sumdb lookup (the draft
// masked only @v). The kinds that name none pass; an unlisted module is refused on each kind, a listed one passes.
func TestMasksEveryKind(t *testing.T) {
	ms, err := compileMasks([]string{`golang\.org/x/.*`, `github\.com/relux-works/.*`})
	if err != nil {
		t.Fatal(err)
	}
	for _, mod := range []struct {
		esc   string
		allow bool
	}{{"golang.org/x/text", true}, {"github.com/relux-works/remote-workplace", true}, {"github.com/evil/x", false},
		{"golang.org/x/net/deeper/path", true},
		{"github.com/relux-works.evil.io/x", false}, {"evil.io/golang.org/x/text", false}} {
		for _, target := range []string{
			"/gomod/" + mod.esc + "/@v/list", "/gomod/" + mod.esc + "/@v/v1.0.0.info", "/gomod/" + mod.esc + "/@v/v1.0.0.mod",
			"/gomod/" + mod.esc + "/@v/v1.0.0.zip", "/gomod/" + mod.esc + "/@latest",
			"/gomod/sumdb/sum.golang.org/lookup/" + mod.esc + "@v1.0.0",
		} {
			p, err := parseModulesPath(target)
			if err != nil {
				t.Fatalf("%s: %v", target, err)
			}
			if got := ms.allows(p); got != mod.allow {
				t.Errorf("%s: allows=%v, want %v", target, got, mod.allow)
			}
		}
	}
	for _, target := range []string{"/gomod/sumdb/sum.golang.org/supported", "/gomod/sumdb/sum.golang.org/latest",
		"/gomod/sumdb/sum.golang.org/tile/8/0/000"} {
		p, _ := parseModulesPath(target)
		if !ms.allows(p) {
			t.Errorf("%s: refused, but it names no module", target)
		}
	}
	// A path kind the grammar does not produce never passes without a module.
	if ms.allows(modPath{Kind: kindInfo}) {
		t.Error("module-less info allowed")
	}
}
