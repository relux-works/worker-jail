package workplace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Policy bounds (docs/design/v2/policy.md §2 to §5).
const (
	PolicyMaxBytes = 64 << 10
	maskMaxBytes   = 256
	maskMaxCount   = 64
	noteMaxBytes   = 200
)

// Network modes. whitelist and blacklist are accepted as aliases and normalised (design-owner decision 1).
const (
	NetNone      = "none"
	NetModules   = "modules"
	NetAllowlist = "allowlist"
	NetDenylist  = "denylist"
	NetAll       = "all"
)

var netAliases = map[string]string{"whitelist": NetAllowlist, "blacklist": NetDenylist}

// ToolRegistry is the list of tools a policy may name. A new tool is a workplace release.
var ToolRegistry = []string{"read_file", "search", "write_file", "apply_patch", "bash"}

// Policy is one worker's policy. Every field is explicit; only Note is optional.
type Policy struct {
	Version   int             `json:"version"`
	Project   string          `json:"project"`
	Worker    string          `json:"worker"`
	Note      string          `json:"note,omitzero"`
	Tools     ToolsPolicy     `json:"tools"`
	Workspace WorkspacePolicy `json:"workspace"`
	Network   NetworkPolicy   `json:"network"`
	Limits    PolicyLimits    `json:"limits"`

	id string // sha256 of the canonical form, set by ParsePolicy
}

// ToolsPolicy is the harness-enforced tool exposure. Allow and Settings are nil under yolo.
type ToolsPolicy struct {
	Mode     string                  `json:"mode"` // allowlist | yolo
	Allow    []string                `json:"allow,omitzero"`
	Settings map[string]ToolSettings `json:"settings,omitzero"`
}

// ToolSettings holds the settings of one tool; which keys exist depends on the tool (policy.md §4).
type ToolSettings struct {
	Paths      []string `json:"paths,omitzero"`
	MaxBytes   int64    `json:"max_bytes,omitzero"`
	MaxResults int64    `json:"max_results,omitzero"`
	Allow      []string `json:"allow,omitzero"`
	Deny       []string `json:"deny,omitzero"`
}

// WorkspacePolicy is the mount mode of /work and the scope apply accepts.
type WorkspacePolicy struct {
	Access     string   `json:"access"` // read-write | read-only
	WriteScope []string `json:"write_scope"`
}

// NetworkPolicy is the call's egress (served by the egress service since v2.1).
type NetworkPolicy struct {
	Mode      string      `json:"mode"`
	GoModules []string    `json:"go_modules,omitzero"`
	Hosts     []string    `json:"hosts,omitzero"`
	Ports     *PortSet    `json:"ports,omitzero"`
	Rate      *RatePolicy `json:"rate,omitzero"`
}

// PortSet is either every port (["*"]) or an explicit list.
type PortSet struct {
	Any   bool
	Ports []int
}

func (p PortSet) MarshalJSON() ([]byte, error) {
	if p.Any {
		return []byte(`["*"]`), nil
	}
	return json.Marshal(p.Ports)
}

// RatePolicy bounds a worker's egress.
type RatePolicy struct {
	RequestsPerMin int64 `json:"requests_per_min"`
	MaxConns       int64 `json:"max_conns"`
	BytesPerDay    int64 `json:"bytes_per_day"`
}

// PolicyLimits are the per-call limits Run applies, plus the harness's soft disk quota.
type PolicyLimits struct {
	CPUs           float64 `json:"cpus"`
	MemoryMiB      int64   `json:"memory_mib"`
	Pids           int64   `json:"pids"`
	CallTimeoutS   int64   `json:"call_timeout_s"`
	MaxOutputBytes int64   `json:"max_output_bytes"`
	DiskSoftMiB    int64   `json:"disk_soft_mib"`
}

// ID is the sha256 hex of the policy's canonical form (keys sorted, no whitespace).
func (p Policy) ID() string { return p.id }

// Exec reports whether the policy exposes an exec tool (bash, or yolo).
func (p Policy) Exec() bool {
	return p.Tools.Mode == "yolo" || slices.Contains(p.Tools.Allow, "bash")
}

// PolicyError is a policy rule violation. It wraps ErrPolicyInvalid and names the field path and the rule.
type PolicyError struct{ Field, Rule string }

func (e *PolicyError) Error() string {
	return ErrPolicyInvalid.Error() + ": " + e.Field + ": " + e.Rule
}
func (e *PolicyError) Unwrap() error { return ErrPolicyInvalid }

func perr(field, format string, a ...any) error {
	return &PolicyError{Field: field, Rule: fmt.Sprintf(format, a...)}
}

// ParsePolicy decodes and validates a policy file and computes its id.
func ParsePolicy(data []byte) (Policy, error) {
	p, _, err := parsePolicy(data)
	return p, err
}

// CanonicalPolicy returns the canonical form of a valid policy file: aliases normalised, keys sorted, no whitespace.
func CanonicalPolicy(data []byte) ([]byte, error) {
	_, c, err := parsePolicy(data)
	return c, err
}

func parsePolicy(data []byte) (Policy, []byte, error) {
	tree, err := decodeStrict(data)
	if err != nil {
		return Policy{}, nil, err
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return Policy{}, nil, perr("$", "must be an object")
	}
	if n, ok := root["network"].(map[string]any); ok {
		if m, ok := n["mode"].(string); ok && netAliases[m] != "" {
			n["mode"] = netAliases[m]
		}
	}
	p, err := validatePolicy(root)
	if err != nil {
		return Policy{}, nil, err
	}
	var buf bytes.Buffer
	canonical(&buf, root)
	sum := sha256.Sum256(buf.Bytes())
	p.id = hex.EncodeToString(sum[:])
	return p, buf.Bytes(), nil
}

// decodeStrict reads one JSON value through the token stream, so duplicate keys and null are seen
// at any depth. Objects become map[string]any, numbers json.Number.
func decodeStrict(data []byte) (any, error) {
	if len(data) > PolicyMaxBytes {
		return nil, perr("$", "exceeds 64 KiB")
	}
	if !utf8.Valid(data) {
		return nil, perr("$", "not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, "$")
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, perr("$", "trailing data after the policy object")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, path string) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, perr(path, "malformed JSON: %v", err)
	}
	switch t := tok.(type) {
	case nil:
		return nil, perr(path, "null is not allowed")
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, perr(path, "malformed JSON: %v", err)
				}
				k, _ := kt.(string)
				kp := joinPath(path, k)
				if _, dup := m[k]; dup {
					return nil, perr(kp, "duplicate key")
				}
				if m[k], err = decodeValue(dec, kp); err != nil {
					return nil, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return nil, perr(path, "malformed JSON: %v", err)
			}
			return m, nil
		case '[':
			l := []any{}
			for dec.More() {
				v, err := decodeValue(dec, fmt.Sprintf("%s[%d]", path, len(l)))
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, perr(path, "malformed JSON: %v", err)
			}
			return l, nil
		}
		return nil, perr(path, "malformed JSON: unexpected %v", t)
	default:
		return t, nil // string, json.Number or bool
	}
}

func joinPath(path, key string) string {
	if path == "$" {
		return key
	}
	return path + "." + key
}

var intLiteralRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// canonical writes v with sorted keys and no whitespace. Integer literals are kept; other numbers
// are written in their shortest decimal form, so 1.0 and 1e0 canonicalise to 1.
func canonical(buf *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			canonicalString(buf, k)
			buf.WriteByte(':')
			canonical(buf, t[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			canonical(buf, e)
		}
		buf.WriteByte(']')
	case string:
		canonicalString(buf, t)
	case json.Number:
		s := string(t)
		if !intLiteralRE.MatchString(s) {
			f, _ := strconv.ParseFloat(s, 64)
			s = strconv.FormatFloat(f, 'f', -1, 64)
		}
		buf.WriteString(s)
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	}
}

func canonicalString(buf *bytes.Buffer, s string) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	buf.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
}

// Validation helpers. Each names the field path in its error.

func asObject(v any, path string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, perr(path, "must be an object")
	}
	return m, nil
}

// checkKeys rejects keys outside known, then any missing key of req.
func checkKeys(m map[string]any, path string, known, req []string) error {
	var unknown []string
	for k := range m {
		if !slices.Contains(known, k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return perr(joinPath(path, unknown[0]), "unknown key")
	}
	for _, k := range req {
		if _, ok := m[k]; !ok {
			return perr(joinPath(path, k), "required")
		}
	}
	return nil
}

func asString(v any, path string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", perr(path, "must be a string")
	}
	return s, nil
}

func asEnum(v any, path string, allowed ...string) (string, error) {
	s, err := asString(v, path)
	if err != nil {
		return "", err
	}
	if !slices.Contains(allowed, s) {
		return "", perr(path, "must be one of %s, not %q", strings.Join(allowed, ", "), s)
	}
	return s, nil
}

func asInt(v any, path string, lo, hi int64) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, perr(path, "must be an integer")
	}
	if !intLiteralRE.MatchString(string(n)) {
		return 0, perr(path, "must be an integer, not %s", n)
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i < lo || i > hi {
		return 0, perr(path, "must be in %d..%d", lo, hi)
	}
	return i, nil
}

func asList(v any, path string, lo, hi int) ([]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, perr(path, "must be a list")
	}
	if len(l) < lo || len(l) > hi {
		return nil, perr(path, "must have %d..%d entries, not %d", lo, hi, len(l))
	}
	return l, nil
}

// asStrings returns a list of unique strings.
func asStrings(v any, path string, lo, hi int) ([]string, error) {
	l, err := asList(v, path, lo, hi)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(l))
	for i, e := range l {
		s, err := asString(e, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		if slices.Contains(out, s) {
			return nil, perr(fmt.Sprintf("%s[%d]", path, i), "duplicate %q", s)
		}
		out = append(out, s)
	}
	return out, nil
}

// asMasks returns lo..64 unique masks, each compiled alone and then anchored.
func asMasks(v any, path string, lo int) ([]string, error) {
	masks, err := asStrings(v, path, lo, maskMaxCount)
	if err != nil {
		return nil, err
	}
	for i, m := range masks {
		if err := checkMask(m); err != nil {
			return nil, perr(fmt.Sprintf("%s[%d]", path, i), "%v", err)
		}
	}
	return masks, nil
}

// checkMask compiles a mask on its own first: a mask such as `a)|(?:b` would otherwise un-anchor ^(?:mask)$.
func checkMask(m string) error {
	if m == "" {
		return errors.New("empty mask")
	}
	if len(m) > maskMaxBytes {
		return fmt.Errorf("mask exceeds %d bytes", maskMaxBytes)
	}
	if _, err := regexp.Compile(m); err != nil {
		return fmt.Errorf("mask does not compile alone: %v", err)
	}
	if _, err := regexp.Compile(anchorMask(m)); err != nil {
		return fmt.Errorf("mask does not compile anchored: %v", err)
	}
	return nil
}

func anchorMask(m string) string { return `^(?:` + m + `)$` }

// maskMatches reports whether mask matches s as the workplace does: ^(?:mask)$. A mask that does not
// compile alone matches everything, so a caller that skipped validation fails towards more risk.
func maskMatches(mask, s string) bool {
	if checkMask(mask) != nil {
		return true
	}
	return regexp.MustCompile(anchorMask(mask)).MatchString(s)
}

var policyKeys = []string{"version", "project", "worker", "tools", "workspace", "network", "limits"}

func validatePolicy(root map[string]any) (Policy, error) {
	var p Policy
	if err := checkKeys(root, "$", append(policyKeys, "note"), policyKeys); err != nil {
		return p, err
	}
	v, err := asInt(root["version"], "version", 1, 1)
	if err != nil {
		return p, perr("version", "must be 1")
	}
	p.Version = int(v)
	for _, f := range []struct {
		key string
		dst *string
	}{{"project", &p.Project}, {"worker", &p.Worker}} {
		s, err := asString(root[f.key], f.key)
		if err != nil {
			return p, err
		}
		if !nameRE.MatchString(s) {
			return p, perr(f.key, "must match [a-z0-9][a-z0-9-]{0,31}, not %q", s)
		}
		*f.dst = s
	}
	if n, ok := root["note"]; ok {
		if p.Note, err = asString(n, "note"); err != nil {
			return p, err
		}
		if len(p.Note) > noteMaxBytes {
			return p, perr("note", "exceeds %d bytes", noteMaxBytes)
		}
	}
	if p.Tools, err = validateTools(root["tools"]); err != nil {
		return p, err
	}
	if p.Workspace, err = validateWorkspace(root["workspace"]); err != nil {
		return p, err
	}
	if p.Network, err = validateNetwork(root["network"], p); err != nil {
		return p, err
	}
	if p.Limits, err = validateLimits(root["limits"]); err != nil {
		return p, err
	}
	return p, nil
}

// toolKeys are the required settings keys of each registry tool.
var toolKeys = map[string][]string{
	"read_file":   {"paths", "max_bytes"},
	"search":      {"paths", "max_results"},
	"write_file":  {"paths", "max_bytes"},
	"apply_patch": {"paths"},
	"bash":        {"allow", "deny"},
}

func validateTools(v any) (ToolsPolicy, error) {
	var t ToolsPolicy
	m, err := asObject(v, "tools")
	if err != nil {
		return t, err
	}
	if err := checkKeys(m, "tools", []string{"mode", "allow", "settings"}, []string{"mode"}); err != nil {
		return t, err
	}
	if t.Mode, err = asEnum(m["mode"], "tools.mode", "allowlist", "yolo"); err != nil {
		return t, err
	}
	if t.Mode == "yolo" {
		for _, k := range []string{"allow", "settings"} {
			if _, ok := m[k]; ok {
				return t, perr("tools."+k, "must be absent with mode yolo")
			}
		}
		return t, nil
	}
	if err := checkKeys(m, "tools", []string{"mode", "allow", "settings"}, []string{"allow", "settings"}); err != nil {
		return t, err
	}
	if t.Allow, err = asStrings(m["allow"], "tools.allow", 1, 16); err != nil {
		return t, err
	}
	for i, name := range t.Allow {
		if !slices.Contains(ToolRegistry, name) {
			return t, perr(fmt.Sprintf("tools.allow[%d]", i), "unknown tool %q (registry: %s)", name, strings.Join(ToolRegistry, ", "))
		}
	}
	sm, err := asObject(m["settings"], "tools.settings")
	if err != nil {
		return t, err
	}
	for _, k := range slices.Sorted(maps.Keys(sm)) {
		if !slices.Contains(t.Allow, k) {
			return t, perr("tools.settings."+k, "has no entry in tools.allow")
		}
	}
	t.Settings = map[string]ToolSettings{}
	for _, name := range t.Allow {
		path := "tools.settings." + name
		v, ok := sm[name]
		if !ok {
			return t, perr(path, "required for an allowed tool")
		}
		tm, err := asObject(v, path)
		if err != nil {
			return t, err
		}
		if err := checkKeys(tm, path, toolKeys[name], toolKeys[name]); err != nil {
			return t, err
		}
		var s ToolSettings
		for _, k := range toolKeys[name] {
			kp := path + "." + k
			switch k {
			case "paths":
				s.Paths, err = asMasks(tm[k], kp, 0)
			case "max_bytes":
				s.MaxBytes, err = asInt(tm[k], kp, 1, 64<<20)
			case "max_results":
				s.MaxResults, err = asInt(tm[k], kp, 1, 64<<20)
			case "allow":
				s.Allow, err = asMasks(tm[k], kp, 1)
			case "deny":
				s.Deny, err = asMasks(tm[k], kp, 0)
			}
			if err != nil {
				return t, err
			}
		}
		t.Settings[name] = s
	}
	return t, nil
}

func validateWorkspace(v any) (WorkspacePolicy, error) {
	var w WorkspacePolicy
	m, err := asObject(v, "workspace")
	if err != nil {
		return w, err
	}
	keys := []string{"access", "write_scope"}
	if err := checkKeys(m, "workspace", keys, keys); err != nil {
		return w, err
	}
	if w.Access, err = asEnum(m["access"], "workspace.access", "read-write", "read-only"); err != nil {
		return w, err
	}
	l, err := asList(m["write_scope"], "workspace.write_scope", 0, 1<<16)
	if err != nil {
		return w, err
	}
	w.WriteScope = make([]string, 0, len(l))
	for i, e := range l {
		path := fmt.Sprintf("workspace.write_scope[%d]", i)
		s, err := asString(e, path)
		if err != nil {
			return w, err
		}
		switch {
		case s == "*" && len(l) != 1:
			return w, perr(path, `"*" must be the only entry`)
		case s == "*":
		case strings.Contains(s, "*"):
			return w, perr(path, `"*" is allowed only as the whole scope`)
		case validateWriteScope([]string{s}) != nil:
			return w, perr(path, "must be a repository-relative prefix: no leading /, no . or .., nothing under .git, not %q", s)
		}
		for _, prev := range w.WriteScope {
			if strings.EqualFold(prev, s) {
				return w, perr(path, "duplicate %q", s)
			}
		}
		w.WriteScope = append(w.WriteScope, s)
	}
	if w.Access == "read-only" && len(w.WriteScope) != 0 {
		return w, perr("workspace.write_scope", "must be [] with access read-only")
	}
	return w, nil
}

var netKeys = map[string][]string{
	NetNone:      {"mode"},
	NetModules:   {"mode", "go_modules", "rate"},
	NetAllowlist: {"mode", "hosts", "ports", "rate"},
	NetDenylist:  {"mode", "hosts", "ports", "rate"},
	NetAll:       {"mode", "ports", "rate"},
}

func validateNetwork(v any, p Policy) (NetworkPolicy, error) {
	var n NetworkPolicy
	m, err := asObject(v, "network")
	if err != nil {
		return n, err
	}
	all := []string{"mode", "go_modules", "hosts", "ports", "rate"}
	if err := checkKeys(m, "network", all, []string{"mode"}); err != nil {
		return n, err
	}
	if n.Mode, err = asEnum(m["mode"], "network.mode", NetNone, NetModules, NetAllowlist, NetDenylist, NetAll); err != nil {
		return n, err
	}
	for _, k := range all {
		_, has := m[k]
		want := slices.Contains(netKeys[n.Mode], k)
		if has && !want {
			return n, perr("network."+k, "not allowed with mode %s", n.Mode)
		}
		if !has && want {
			return n, perr("network."+k, "required with mode %s", n.Mode)
		}
	}
	if n.Mode == NetNone {
		return n, nil
	}
	if !p.Exec() {
		return n, perr("network.mode", "mode %s needs an exec tool (bash or yolo)", n.Mode)
	}
	switch n.Mode {
	case NetModules:
		if p.Workspace.Access != "read-write" {
			return n, perr("network.mode", "mode modules requires workspace.access read-write")
		}
		if n.GoModules, err = asMasks(m["go_modules"], "network.go_modules", 1); err != nil {
			return n, err
		}
	case NetAllowlist, NetDenylist:
		if l, ok := m["hosts"].([]any); ok && len(l) == 0 && n.Mode == NetDenylist {
			return n, perr("network.hosts", "an empty denylist must be written as mode all")
		}
		if n.Hosts, err = asMasks(m["hosts"], "network.hosts", 1); err != nil {
			return n, err
		}
	}
	if n.Mode != NetModules {
		if n.Ports, err = validatePorts(m["ports"], n.Mode); err != nil {
			return n, err
		}
	}
	if n.Rate, err = validateRate(m["rate"]); err != nil {
		return n, err
	}
	return n, nil
}

func validatePorts(v any, mode string) (*PortSet, error) {
	l, err := asList(v, "network.ports", 1, 16)
	if err != nil {
		return nil, err
	}
	if s, ok := l[0].(string); ok && s == "*" {
		if len(l) != 1 {
			return nil, perr("network.ports", `"*" must be the only entry`)
		}
		if mode == NetAllowlist {
			return nil, perr("network.ports", "mode allowlist must list its ports")
		}
		return &PortSet{Any: true}, nil
	}
	ps := &PortSet{}
	for i, e := range l {
		path := fmt.Sprintf("network.ports[%d]", i)
		port, err := asInt(e, path, 1, 65535)
		if err != nil {
			return nil, err
		}
		if slices.Contains(ps.Ports, int(port)) {
			return nil, perr(path, "duplicate %d", port)
		}
		ps.Ports = append(ps.Ports, int(port))
	}
	return ps, nil
}

func validateRate(v any) (*RatePolicy, error) {
	m, err := asObject(v, "network.rate")
	if err != nil {
		return nil, err
	}
	keys := []string{"requests_per_min", "max_conns", "bytes_per_day"}
	if err := checkKeys(m, "network.rate", keys, keys); err != nil {
		return nil, err
	}
	r := &RatePolicy{}
	if r.RequestsPerMin, err = asInt(m["requests_per_min"], "network.rate.requests_per_min", 1, 6000); err != nil {
		return nil, err
	}
	if r.MaxConns, err = asInt(m["max_conns"], "network.rate.max_conns", 1, 64); err != nil {
		return nil, err
	}
	if r.BytesPerDay, err = asInt(m["bytes_per_day"], "network.rate.bytes_per_day", 1, 1<<62); err != nil {
		return nil, err
	}
	return r, nil
}

func validateLimits(v any) (PolicyLimits, error) {
	var l PolicyLimits
	m, err := asObject(v, "limits")
	if err != nil {
		return l, err
	}
	keys := []string{"cpus", "memory_mib", "pids", "call_timeout_s", "max_output_bytes", "disk_soft_mib"}
	if err := checkKeys(m, "limits", keys, keys); err != nil {
		return l, err
	}
	n, ok := m["cpus"].(json.Number)
	if !ok {
		return l, perr("limits.cpus", "must be a number")
	}
	if l.CPUs, err = strconv.ParseFloat(string(n), 64); err != nil || l.CPUs < 0.25 || l.CPUs > 4 {
		return l, perr("limits.cpus", "must be in 0.25..4")
	}
	for _, f := range []struct {
		key    string
		lo, hi int64
		dst    *int64
	}{
		{"memory_mib", 256, 8192, &l.MemoryMiB},
		{"pids", 16, 4096, &l.Pids},
		{"call_timeout_s", 1, 3600, &l.CallTimeoutS},
		{"max_output_bytes", 1024, 64 << 20, &l.MaxOutputBytes},
		{"disk_soft_mib", 64, 65536, &l.DiskSoftMiB},
	} {
		if *f.dst, err = asInt(m[f.key], "limits."+f.key, f.lo, f.hi); err != nil {
			return l, err
		}
	}
	return l, nil
}
