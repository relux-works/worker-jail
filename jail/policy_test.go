package jail

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// The three examples of docs/design/v2/policy.md §11, verbatim.
const (
	reviewerExample = `{"version":1,"project":"worker-jail","worker":"rev-1",
 "tools":{"mode":"allowlist","allow":["read_file","search"],
  "settings":{"read_file":{"paths":[".*"],"max_bytes":1048576},"search":{"paths":[".*"],"max_results":200}}},
 "workspace":{"access":"read-only","write_scope":[]},
 "network":{"mode":"none"},
 "limits":{"cpus":1,"memory_mib":1024,"pids":256,"call_timeout_s":300,"max_output_bytes":4194304,"disk_soft_mib":2048}}`

	developerExample = `{"version":1,"project":"remote-worker-harness","worker":"rwh-codex-rwh","note":"story 2b",
 "tools":{"mode":"allowlist","allow":["read_file","search","write_file","apply_patch","bash"],
  "settings":{"read_file":{"paths":[".*"],"max_bytes":1048576},"search":{"paths":[".*"],"max_results":200},
   "write_file":{"paths":["(internal|cmd|docs)/.*"],"max_bytes":1048576},"apply_patch":{"paths":["(internal|cmd|docs)/.*"]},
   "bash":{"allow":["go (build|test|vet)( .*)?","git (status|diff|log)( .*)?"],"deny":["curl .*","wget .*"]}}},
 "workspace":{"access":"read-write","write_scope":["internal/","cmd/","docs/"]},
 "network":{"mode":"modules","go_modules":["golang\\.org/x/.*","github\\.com/relux-works/.*"],
  "rate":{"requests_per_min":600,"max_conns":8,"bytes_per_day":2147483648}},
 "limits":{"cpus":2,"memory_mib":2048,"pids":512,"call_timeout_s":600,"max_output_bytes":4194304,"disk_soft_mib":4096}}`

	yoloExample = `{"version":1,"project":"webapp","worker":"npm-1",
 "tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},
 "network":{"mode":"allowlist","hosts":["registry\\.npmjs\\.org"],"ports":[443],
  "rate":{"requests_per_min":300,"max_conns":16,"bytes_per_day":5368709120}},
 "limits":{"cpus":2,"memory_mib":4096,"pids":1024,"call_timeout_s":1200,"max_output_bytes":4194304,"disk_soft_mib":8192}}`
)

// edit changes a decoded policy tree.
type edit func(m map[string]any)

// walk returns the object holding the last component of a dotted path.
func walk(m map[string]any, path string) (map[string]any, string) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		m = m[p].(map[string]any)
	}
	return m, parts[len(parts)-1]
}

func set(path string, v any) edit {
	return func(m map[string]any) { o, k := walk(m, path); o[k] = v }
}

func del(path string) edit {
	return func(m map[string]any) { o, k := walk(m, path); delete(o, k) }
}

// raw sets a value from JSON text, so numbers keep their literal form (2.0 stays 2.0).
func raw(path, text string) edit { return set(path, json.RawMessage(text)) }

// mut applies edits to base and returns the re-encoded file.
func mut(t *testing.T, base string, edits ...edit) []byte {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(base))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	for _, e := range edits {
		e(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func strs(n int, f func(i int) string) []string {
	var s []string
	for i := range n {
		s = append(s, f(i))
	}
	return s
}

// The three §11 examples are valid (positive controls for every negative case below).
func TestParsePolicyExamples(t *testing.T) {
	for _, ex := range []string{reviewerExample, developerExample, yoloExample} {
		p, err := ParsePolicy([]byte(ex))
		if err != nil {
			t.Fatalf("example rejected: %v\n%s", err, ex)
		}
		if len(p.ID()) != 64 {
			t.Fatalf("id %q", p.ID())
		}
	}
	p, _ := ParsePolicy([]byte(developerExample))
	if p.Note != "story 2b" || p.Limits.CPUs != 2 || p.Network.Rate.BytesPerDay != 2147483648 ||
		p.Tools.Settings["bash"].Deny[1] != "wget .*" || p.Workspace.WriteScope[2] != "docs/" {
		t.Fatalf("decoded %+v", p)
	}
}

type invalidCase struct {
	data        []byte
	field, rule string
}

func checkInvalid(t *testing.T, cases []invalidCase) {
	t.Helper()
	for i, c := range cases {
		_, err := ParsePolicy(c.data)
		var pe *PolicyError
		if !errors.Is(err, ErrPolicyInvalid) || !errors.As(err, &pe) {
			t.Errorf("case %d (%s): err %v, want ErrPolicyInvalid", i, c.field, err)
			continue
		}
		if pe.Field != c.field || !strings.Contains(pe.Rule, c.rule) {
			t.Errorf("case %d: got %q / %q, want %q / %q", i, pe.Field, pe.Rule, c.field, c.rule)
		}
		if !strings.Contains(err.Error(), c.field) {
			t.Errorf("case %d: message %q does not name %q", i, err, c.field)
		}
	}
}

// §2 format rules: strict JSON, size, duplicates, null, unknown keys, types, integers, required keys.
func TestParsePolicyFormat(t *testing.T) {
	big := append([]byte(reviewerExample), bytes.Repeat([]byte(" "), PolicyMaxBytes-len(reviewerExample))...)
	if _, err := ParsePolicy(big); err != nil {
		t.Fatalf("control: exactly 64 KiB rejected: %v", err)
	}
	checkInvalid(t, []invalidCase{
		// One byte over 64 KiB is rejected before parsing.
		{append(big, ' '), "$", "exceeds 64 KiB"},
		// Comments are not JSON.
		{[]byte("// c\n" + reviewerExample), "$", "malformed JSON"},
		// A trailing comma in an object is rejected.
		{[]byte(strings.Replace(reviewerExample, `"disk_soft_mib":2048}`, `"disk_soft_mib":2048,}`, 1)), "limits", "malformed JSON"},
		// A trailing comma in a list is rejected.
		{[]byte(strings.Replace(reviewerExample, `["read_file","search"]`, `["read_file","search",]`, 1)), "tools.allow[2]", "malformed JSON"},
		// NaN is not a JSON number.
		{[]byte(strings.Replace(reviewerExample, `"cpus":1`, `"cpus":NaN`, 1)), "limits.cpus", "malformed JSON"},
		// A duplicate key at the top level.
		{[]byte(strings.Replace(reviewerExample, `"version":1,`, `"version":1,"version":1,`, 1)), "version", "duplicate key"},
		// A duplicate key two levels down, even with the same value.
		{[]byte(strings.Replace(reviewerExample, `"pids":256`, `"pids":256,"pids":256`, 1)), "limits.pids", "duplicate key"},
		// A duplicate key four levels down, spelled with an escape.
		{[]byte(strings.Replace(reviewerExample, `"max_bytes":1048576}`, `"max_bytes":1048576,"max_bytes":1}`, 1)), "tools.settings.read_file.max_bytes", "duplicate key"},
		// null for the optional note is not "absent".
		{mut(t, reviewerExample, raw("note", "null")), "note", "null"},
		// null for a nested required number.
		{mut(t, reviewerExample, raw("limits.cpus", "null")), "limits.cpus", "null"},
		// null inside a list.
		{mut(t, reviewerExample, raw("tools.allow", `["read_file",null]`)), "tools.allow[1]", "null"},
		// Unknown key at the top level.
		{mut(t, reviewerExample, set("extra", 1)), "extra", "unknown key"},
		// Unknown key in limits.
		{mut(t, reviewerExample, set("limits.swap", 1)), "limits.swap", "unknown key"},
		// Unknown key in a tool's settings.
		{mut(t, reviewerExample, set("tools.settings.read_file.depth", 1)), "tools.settings.read_file.depth", "unknown key"},
		// A string where an integer is required.
		{mut(t, reviewerExample, set("version", "1")), "version", "must be 1"},
		// A number where a string is required.
		{mut(t, reviewerExample, set("project", 5)), "project", "must be a string"},
		// A string where a list is required.
		{mut(t, reviewerExample, set("tools.allow", "read_file")), "tools.allow", "must be a list"},
		// A string where an integer is required, nested.
		{mut(t, reviewerExample, set("limits.memory_mib", "1024")), "limits.memory_mib", "must be an integer"},
		// A bool where a number is required.
		{mut(t, reviewerExample, set("limits.cpus", true)), "limits.cpus", "must be a number"},
		// A list where an object is required.
		{mut(t, reviewerExample, set("workspace", []any{})), "workspace", "must be an object"},
		// 2.0 is a float where an integer is required.
		{mut(t, reviewerExample, raw("limits.pids", "2.0")), "limits.pids", "must be an integer"},
		// An exponent is a float where an integer is required.
		{mut(t, reviewerExample, raw("limits.pids", "5e2")), "limits.pids", "must be an integer"},
		// Invalid UTF-8.
		{[]byte(strings.Replace(reviewerExample, "rev-1", "rev-\xff", 1)), "$", "UTF-8"},
		// A second value after the policy.
		{[]byte(reviewerExample + " {}"), "$", "trailing data"},
		// The policy must be an object.
		{[]byte(`[1]`), "$", "must be an object"},
		// Every required key must be present: limits is missing.
		{mut(t, reviewerExample, del("limits")), "limits", "required"},
		// A required nested key is missing.
		{mut(t, reviewerExample, del("limits.disk_soft_mib")), "limits.disk_soft_mib", "required"},
		// An absent list is an error; [] must be written out.
		{mut(t, reviewerExample, del("workspace.write_scope")), "workspace.write_scope", "required"},
		// An absent deny list is an error too.
		{mut(t, developerExample, del("tools.settings.bash.deny")), "tools.settings.bash.deny", "required"},
	})
	for _, k := range []string{"version", "project", "worker", "tools", "workspace", "network", "limits"} {
		checkInvalid(t, []invalidCase{{mut(t, reviewerExample, del(k)), k, "required"}}) // each top-level key is required
	}
	for _, e := range [][]byte{
		mut(t, reviewerExample, raw("limits.cpus", "0.5")), // a fraction where a number is allowed
		mut(t, reviewerExample, raw("limits.cpus", "1.0")), // a float spelling of an integer where a number is allowed
		mut(t, reviewerExample, del("note")),               // note is the only optional key
	} {
		if _, err := ParsePolicy(e); err != nil {
			t.Errorf("control rejected: %v\n%s", err, e)
		}
	}
}

// §2 masks: compile alone, anchored matching, length, count, emptiness and duplicates.
func TestParsePolicyMasks(t *testing.T) {
	const breakout = `a)|(?:b`
	if _, err := regexp.Compile(anchorMask(breakout)); err != nil {
		t.Fatalf("control: the wrapped breakout must compile, or the test proves nothing: %v", err)
	}
	if !regexp.MustCompile(anchorMask(breakout)).MatchString("a-then-anything") {
		t.Fatal("control: the wrapped breakout must be un-anchored")
	}
	m256 := strings.Repeat("a", 256)
	p := "tools.settings.read_file.paths"
	checkInvalid(t, []invalidCase{
		// The breakout compiles only inside the wrapper, so compiling alone rejects it.
		{mut(t, reviewerExample, set(p, []string{breakout})), p + "[0]", "does not compile alone"},
		// A plain syntax error.
		{mut(t, reviewerExample, set(p, []string{"("})), p + "[0]", "does not compile alone"},
		// 257 bytes is over the limit.
		{mut(t, reviewerExample, set(p, []string{m256 + "a"})), p + "[0]", "exceeds 256 bytes"},
		// An empty mask.
		{mut(t, reviewerExample, set(p, []string{"ok", ""})), p + "[1]", "empty mask"},
		// A duplicate mask.
		{mut(t, reviewerExample, set(p, []string{"a", "a"})), p + "[1]", "duplicate"},
		// 65 masks are over the count limit.
		{mut(t, reviewerExample, set(p, strs(65, func(i int) string { return "m" + strings.Repeat("x", i) }))), p, "must have 0..64 entries"},
		// The same rules apply to module masks.
		{mut(t, developerExample, set("network.go_modules", []string{breakout})), "network.go_modules[0]", "does not compile alone"},
		// ... and to bash masks.
		{mut(t, developerExample, set("tools.settings.bash.deny", []string{"x", m256 + "b"})), "tools.settings.bash.deny[1]", "exceeds 256 bytes"},
		// ... and to host masks.
		{mut(t, yoloExample, set("network.hosts", []string{"[a-"})), "network.hosts[0]", "does not compile alone"},
	})
	for _, e := range [][]byte{
		mut(t, reviewerExample, set(p, []string{m256})),                                                       // exactly 256 bytes
		mut(t, reviewerExample, set(p, strs(64, func(i int) string { return "m" + strings.Repeat("x", i) }))), // exactly 64 masks
		mut(t, reviewerExample, set(p, []string{})),                                                           // an empty path list (reads nothing)
	} {
		if _, err := ParsePolicy(e); err != nil {
			t.Errorf("control rejected: %v", err)
		}
	}
	// Anchored matching: an escaped host mask does not match a longer host, nor a host with any character for '.'.
	for _, c := range []struct {
		mask, s string
		want    bool
	}{
		{`github\.com`, "github.com", true},
		{`github\.com`, "github.com.evil.io", false},
		{`github\.com`, "evil.github.com", false},
		{`github\.com`, "githubxcom", false},
		{`github.com`, "githubxcom", true},  // why check warns on an unescaped '.'
		{breakout, "a-then-anything", true}, // an invalid mask fails towards "matches everything"
	} {
		if got := maskMatches(c.mask, c.s); got != c.want {
			t.Errorf("maskMatches(%q, %q) = %v", c.mask, c.s, got)
		}
	}
}

// §3 fields: version, names, note, workspace and limits bounds.
func TestParsePolicyFields(t *testing.T) {
	checkInvalid(t, []invalidCase{
		// Only schema version 1 exists.
		{mut(t, reviewerExample, set("version", 2)), "version", "must be 1"},
		// Upper case is not a valid name.
		{mut(t, reviewerExample, set("project", "Worker-Jail")), "project", "must match"},
		// A leading dash is not a valid name.
		{mut(t, reviewerExample, set("worker", "-rev")), "worker", "must match"},
		// 33 characters are too long for a name.
		{mut(t, reviewerExample, set("worker", strings.Repeat("a", 33))), "worker", "must match"},
		// A note over 200 bytes.
		{mut(t, reviewerExample, set("note", strings.Repeat("n", 201))), "note", "exceeds 200 bytes"},
		// access has two values only.
		{mut(t, reviewerExample, set("workspace.access", "rw")), "workspace.access", "must be one of"},
		// read-only with a write scope is a contradiction.
		{mut(t, reviewerExample, set("workspace.write_scope", []string{"docs/"})), "workspace.write_scope", "must be [] with access read-only"},
		// read-only with the whole repository is a contradiction too.
		{mut(t, reviewerExample, set("workspace.write_scope", []string{"*"})), "workspace.write_scope", "must be [] with access read-only"},
		// "*" must stand alone.
		{mut(t, developerExample, set("workspace.write_scope", []string{"*", "docs/"})), "workspace.write_scope[0]", "only entry"},
		// "*" is not a glob inside an entry.
		{mut(t, developerExample, set("workspace.write_scope", []string{"docs/*"})), "workspace.write_scope[0]", "whole scope"},
		// No leading '/'.
		{mut(t, developerExample, set("workspace.write_scope", []string{"/etc/"})), "workspace.write_scope[0]", "repository-relative"},
		// No '..'.
		{mut(t, developerExample, set("workspace.write_scope", []string{"docs/../x"})), "workspace.write_scope[0]", "repository-relative"},
		// Nothing under .git, in any spelling.
		{mut(t, developerExample, set("workspace.write_scope", []string{"sub/.GIT/"})), "workspace.write_scope[0]", "repository-relative"},
		// Entries are unique, case-insensitively (apply matches case-insensitively).
		{mut(t, developerExample, set("workspace.write_scope", []string{"docs/", "Docs/"})), "workspace.write_scope[1]", "duplicate"},
		// cpus below 0.25.
		{mut(t, reviewerExample, raw("limits.cpus", "0.2")), "limits.cpus", "0.25..4"},
		// cpus above 4.
		{mut(t, reviewerExample, raw("limits.cpus", "4.5")), "limits.cpus", "0.25..4"},
		// memory_mib below 256.
		{mut(t, reviewerExample, set("limits.memory_mib", 255)), "limits.memory_mib", "256..8192"},
		// memory_mib above 8192.
		{mut(t, reviewerExample, set("limits.memory_mib", 8193)), "limits.memory_mib", "256..8192"},
		// pids below 16.
		{mut(t, reviewerExample, set("limits.pids", 15)), "limits.pids", "16..4096"},
		// pids above 4096.
		{mut(t, reviewerExample, set("limits.pids", 4097)), "limits.pids", "16..4096"},
		// call_timeout_s of 0.
		{mut(t, reviewerExample, set("limits.call_timeout_s", 0)), "limits.call_timeout_s", "1..3600"},
		// call_timeout_s above the protocol maximum of 60 min.
		{mut(t, reviewerExample, set("limits.call_timeout_s", 3601)), "limits.call_timeout_s", "1..3600"},
		// max_output_bytes below 1024.
		{mut(t, reviewerExample, set("limits.max_output_bytes", 1023)), "limits.max_output_bytes", "1024..67108864"},
		// max_output_bytes above 64 MiB.
		{mut(t, reviewerExample, set("limits.max_output_bytes", 67108865)), "limits.max_output_bytes", "1024..67108864"},
		// disk_soft_mib below 64.
		{mut(t, reviewerExample, set("limits.disk_soft_mib", 63)), "limits.disk_soft_mib", "64..65536"},
		// disk_soft_mib above 65536.
		{mut(t, reviewerExample, set("limits.disk_soft_mib", 65537)), "limits.disk_soft_mib", "64..65536"},
	})
	for _, e := range [][]byte{
		mut(t, reviewerExample, set("note", strings.Repeat("n", 200))),                                     // a 200-byte note
		mut(t, reviewerExample, set("worker", strings.Repeat("a", 32))),                                    // a 32-character name
		mut(t, developerExample, set("workspace.write_scope", []string{"*"})),                              // rw with the whole repository
		mut(t, developerExample, set("workspace.write_scope", []string{})),                                 // rw with nothing to apply
		mut(t, developerExample, set("workspace.write_scope", []string{"Makefile", ".github/", "a.git/"})), // exact file, review-required dir, a.git
		mut(t, reviewerExample, raw("limits.cpus", "0.25"), set("limits.memory_mib", 256), set("limits.pids", 16),
			set("limits.call_timeout_s", 1), set("limits.max_output_bytes", 1024), set("limits.disk_soft_mib", 64)), // every lower bound
		mut(t, reviewerExample, raw("limits.cpus", "4"), set("limits.memory_mib", 8192), set("limits.pids", 4096),
			set("limits.call_timeout_s", 3600), set("limits.max_output_bytes", 67108864), set("limits.disk_soft_mib", 65536)), // every upper bound
	} {
		if _, err := ParsePolicy(e); err != nil {
			t.Errorf("control rejected: %v", err)
		}
	}
}

// §4 tools: modes, registry, allow list and per-tool settings.
func TestParsePolicyTools(t *testing.T) {
	checkInvalid(t, []invalidCase{
		// Two modes only.
		{mut(t, reviewerExample, set("tools.mode", "auto")), "tools.mode", "must be one of"},
		// yolo with settings: a silently ignored rule is refused.
		{mut(t, yoloExample, set("tools.settings", map[string]any{})), "tools.settings", "must be absent with mode yolo"},
		// yolo with an allow list.
		{mut(t, yoloExample, set("tools.allow", []string{"bash"})), "tools.allow", "must be absent with mode yolo"},
		// allowlist without allow.
		{mut(t, reviewerExample, del("tools.allow")), "tools.allow", "required"},
		// allowlist without settings.
		{mut(t, reviewerExample, del("tools.settings")), "tools.settings", "required"},
		// An empty allow list.
		{mut(t, reviewerExample, set("tools.allow", []string{}), set("tools.settings", map[string]any{})), "tools.allow", "1..16"},
		// More than 16 names.
		{mut(t, reviewerExample, set("tools.allow", strs(17, func(int) string { return "bash" }))), "tools.allow", "1..16"},
		// A name outside the registry.
		{mut(t, reviewerExample, set("tools.allow", []string{"read_file", "curl"})), "tools.allow[1]", "unknown tool"},
		// A duplicate name.
		{mut(t, reviewerExample, set("tools.allow", []string{"read_file", "read_file"})), "tools.allow[1]", "duplicate"},
		// An allowed tool without settings.
		{mut(t, reviewerExample, del("tools.settings.search")), "tools.settings.search", "required for an allowed tool"},
		// Settings for a registry tool that is not allowed.
		{mut(t, reviewerExample, set("tools.settings.bash", map[string]any{"allow": []string{".*"}, "deny": []string{}})), "tools.settings.bash", "no entry in tools.allow"},
		// Settings for a tool outside the registry.
		{mut(t, reviewerExample, set("tools.settings.foo", map[string]any{})), "tools.settings.foo", "no entry in tools.allow"},
		// Every key of a present tool is required.
		{mut(t, reviewerExample, del("tools.settings.read_file.max_bytes")), "tools.settings.read_file.max_bytes", "required"},
		// A key of another tool is unknown here.
		{mut(t, reviewerExample, set("tools.settings.search.max_bytes", 1)), "tools.settings.search.max_bytes", "unknown key"},
		// bash allow must be non-empty.
		{mut(t, developerExample, set("tools.settings.bash.allow", []string{})), "tools.settings.bash.allow", "1..64"},
		// A size cap of 0.
		{mut(t, reviewerExample, set("tools.settings.read_file.max_bytes", 0)), "tools.settings.read_file.max_bytes", "1..67108864"},
		// A result cap of 0.
		{mut(t, reviewerExample, set("tools.settings.search.max_results", 0)), "tools.settings.search.max_results", "1..67108864"},
		// settings must be an object.
		{mut(t, reviewerExample, set("tools.settings", []string{})), "tools.settings", "must be an object"},
	})
	if _, err := ParsePolicy(mut(t, developerExample, set("tools.settings.bash.deny", []string{}))); err != nil {
		t.Errorf("control: an empty deny list is allowed: %v", err)
	}
}

// §5 network: modes and aliases, keys per mode, masks, ports, rate, and the exec requirement.
func TestParsePolicyNetwork(t *testing.T) {
	rate := map[string]any{"requests_per_min": 60, "max_conns": 4, "bytes_per_day": 1 << 20}
	all := func(e ...edit) []byte {
		return mut(t, yoloExample, append([]edit{set("network", map[string]any{"mode": "all", "ports": []any{"*"}, "rate": rate})}, e...)...)
	}
	checkInvalid(t, []invalidCase{
		// An unknown mode.
		{mut(t, reviewerExample, set("network.mode", "proxy")), "network.mode", "must be one of"},
		// Aliases are exact: case matters.
		{mut(t, reviewerExample, set("network.mode", "Whitelist")), "network.mode", "must be one of"},
		// none allows nothing else.
		{mut(t, reviewerExample, set("network.hosts", []string{"x"})), "network.hosts", "not allowed with mode none"},
		// An unknown network key.
		{mut(t, reviewerExample, set("network.proxy", "x")), "network.proxy", "unknown key"},
		// modules needs a rate.
		{mut(t, developerExample, del("network.rate")), "network.rate", "required with mode modules"},
		// modules has no ports.
		{mut(t, developerExample, set("network.ports", []int{443})), "network.ports", "not allowed with mode modules"},
		// modules needs at least one mask.
		{mut(t, developerExample, set("network.go_modules", []string{})), "network.go_modules", "1..64"},
		// modules allows at most 64 masks.
		{mut(t, developerExample, set("network.go_modules", strs(65, func(i int) string { return "m" + strings.Repeat("x", i) }))), "network.go_modules", "1..64"},
		// modules requires a read-write workspace.
		{mut(t, developerExample, set("workspace.access", "read-only"), set("workspace.write_scope", []string{})), "network.mode", "requires workspace.access read-write"},
		// Any mode other than none needs an exec tool.
		{mut(t, developerExample, set("tools.allow", []string{"read_file", "search", "write_file", "apply_patch"}), del("tools.settings.bash")), "network.mode", "needs an exec tool"},
		// allowlist needs hosts.
		{mut(t, yoloExample, del("network.hosts")), "network.hosts", "required with mode allowlist"},
		// allowlist needs at least one host.
		{mut(t, yoloExample, set("network.hosts", []string{})), "network.hosts", "1..64"},
		// allowlist must list its ports.
		{mut(t, yoloExample, set("network.ports", []any{"*"})), "network.ports", "must list its ports"},
		// ports is required.
		{mut(t, yoloExample, del("network.ports")), "network.ports", "required with mode allowlist"},
		// At least one port.
		{mut(t, yoloExample, set("network.ports", []int{})), "network.ports", "1..16"},
		// At most 16 ports.
		{mut(t, yoloExample, set("network.ports", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})), "network.ports", "1..16"},
		// Port 0.
		{mut(t, yoloExample, set("network.ports", []int{0})), "network.ports[0]", "1..65535"},
		// Port 65536.
		{mut(t, yoloExample, set("network.ports", []int{443, 65536})), "network.ports[1]", "1..65535"},
		// A duplicate port.
		{mut(t, yoloExample, set("network.ports", []int{443, 443})), "network.ports[1]", "duplicate"},
		// A float port.
		{mut(t, yoloExample, raw("network.ports", "[443.0]")), "network.ports[0]", "must be an integer"},
		// "*" alone only.
		{all(set("network.ports", []any{"*", 443})), "network.ports", "only entry"},
		// A port as a string.
		{all(set("network.ports", []any{"443"})), "network.ports[0]", "must be an integer"},
		// An empty denylist must be written as all.
		{mut(t, yoloExample, set("network.mode", "denylist"), set("network.hosts", []string{})), "network.hosts", "written as mode all"},
		// The same through the alias.
		{mut(t, yoloExample, set("network.mode", "blacklist"), set("network.hosts", []string{})), "network.hosts", "written as mode all"},
		// all has no hosts.
		{all(set("network.hosts", []string{"x"})), "network.hosts", "not allowed with mode all"},
		// all needs ports.
		{all(del("network.ports")), "network.ports", "required with mode all"},
		// requests_per_min of 0.
		{mut(t, yoloExample, set("network.rate.requests_per_min", 0)), "network.rate.requests_per_min", "1..6000"},
		// requests_per_min above 6000.
		{mut(t, yoloExample, set("network.rate.requests_per_min", 6001)), "network.rate.requests_per_min", "1..6000"},
		// max_conns above 64.
		{mut(t, yoloExample, set("network.rate.max_conns", 65)), "network.rate.max_conns", "1..64"},
		// bytes_per_day of 0.
		{mut(t, yoloExample, set("network.rate.bytes_per_day", 0)), "network.rate.bytes_per_day", "1.."},
		// Every rate key is required.
		{mut(t, yoloExample, del("network.rate.max_conns")), "network.rate.max_conns", "required"},
		// No unknown rate key.
		{mut(t, yoloExample, set("network.rate.burst", 1)), "network.rate.burst", "unknown key"},
	})
	for _, e := range [][]byte{
		all(), // all with every port
		mut(t, yoloExample, set("network.mode", "whitelist")),                                               // alias of allowlist
		mut(t, yoloExample, set("network.mode", "denylist"), set("network.ports", []any{"*"})),              // denylist may use every port
		mut(t, yoloExample, set("network.mode", "blacklist")),                                               // alias of denylist
		mut(t, yoloExample, set("workspace.access", "read-only"), set("workspace.write_scope", []string{})), // allowlist with a read-only workspace
	} {
		if _, err := ParsePolicy(e); err != nil {
			t.Errorf("control rejected: %v\n%s", err, e)
		}
	}
}

// The id is the sha256 of the canonical form: stable under reformatting, key order, escapes and number
// spelling, equal for the aliases, and different for any change of content.
func TestPolicyID(t *testing.T) {
	id := policyID(t, []byte(yoloExample))
	var compact bytes.Buffer
	json.Compact(&compact, []byte(yoloExample))
	var indented bytes.Buffer
	json.Indent(&indented, []byte(yoloExample), "", "\t")
	reordered := `{"limits":{"disk_soft_mib":8192,"max_output_bytes":4194304,"call_timeout_s":1200,"pids":1024,"memory_mib":4096,"cpus":2.0},
 "network":{"rate":{"bytes_per_day":5368709120,"max_conns":16,"requests_per_min":300},"ports":[443],"hosts":["registry\\.npmjs\\.org"],"mode":"allowlist"},
 "workspace":{"write_scope":["*"],"access":"read-write"},"tools":{"mode":"yolo"},"worker":"npm-1","project":"webapp","version":1}`
	for i, d := range [][]byte{compact.Bytes(), indented.Bytes(), []byte(reordered),
		[]byte(strings.Replace(yoloExample, `"allowlist"`, `"whitelist"`, 1))} {
		if got := policyID(t, d); got != id {
			t.Errorf("variant %d: id %s, want %s", i, got, id)
		}
	}
	c, err := CanonicalPolicy([]byte(strings.Replace(yoloExample, `"allowlist"`, `"whitelist"`, 1)))
	if err != nil || bytes.ContainsAny(c, " \n\t") || !bytes.HasPrefix(c, []byte(`{"limits":{"call_timeout_s":1200,`)) {
		t.Fatalf("canonical %s err %v", c, err)
	}
	if bytes.Contains(c, []byte("whitelist")) || !bytes.Contains(c, []byte(`"mode":"allowlist"`)) {
		t.Fatalf("alias not normalised in the canonical form: %s", c)
	}
	deny := policyID(t, mut(t, yoloExample, set("network.mode", "denylist")))
	if policyID(t, mut(t, yoloExample, set("network.mode", "blacklist"))) != deny {
		t.Error("blacklist and denylist differ")
	}
	for i, d := range [][]byte{
		mut(t, yoloExample, set("note", "x")),
		mut(t, yoloExample, set("limits.pids", 1023)),
		mut(t, yoloExample, set("network.mode", "denylist")),
	} {
		if policyID(t, d) == id {
			t.Errorf("change %d kept the id", i)
		}
	}
}
