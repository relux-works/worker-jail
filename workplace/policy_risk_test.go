package workplace

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/*.golden")

func mustParse(t *testing.T, data []byte) Policy {
	t.Helper()
	p, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	return p
}

// Each cell of the §6 table and each modifier, with the reasons and warnings that justify the level.
func TestEffectiveRisk(t *testing.T) {
	rate := map[string]any{"requests_per_min": 60, "max_conns": 4, "bytes_per_day": 1 << 20}
	ro := []edit{set("workspace.access", "read-only"), set("workspace.write_scope", []string{})}
	noExec := []edit{set("tools.allow", []string{"read_file", "search", "write_file", "apply_patch"}), del("tools.settings.bash")}
	hosts := func(mode string, h ...string) edit {
		return set("network", map[string]any{"mode": mode, "hosts": h, "ports": []int{443}, "rate": rate})
	}
	none := set("network", map[string]any{"mode": "none"})
	cases := []struct {
		name    string
		data    []byte
		want    Risk
		reason  string // a reason that must be present
		warning string // a warning that must be present ("" = no warnings)
	}{
		// none, rw + exec (bash).
		{"none rw bash", mut(t, developerExample, none), RiskMedium, "can plant code", ""},
		// none, rw + exec (yolo).
		{"none rw yolo", mut(t, yoloExample, none), RiskMedium, "yolo: no tool rules", ""},
		// none, read-only with an exec tool.
		{"none ro bash", mut(t, developerExample, append(ro, none)...), RiskLow, "read-only workspace or no exec tool", ""},
		// none, read-only with yolo: yolo does not raise a read-only none cell.
		{"none ro yolo", mut(t, yoloExample, append(ro, none)...), RiskLow, "yolo: no tool rules", ""},
		// none, rw without an exec tool.
		{"none rw no exec", mut(t, developerExample, append(noExec, none)...), RiskLow, "no exec tool", ""},
		// modules with narrow masks.
		{"modules narrow", []byte(developerExample), RiskMedium, "covert channel via module paths", ""},
		// modules with a mask that matches a canary path: HIGH.
		{"modules .*", mut(t, developerExample, set("network.go_modules", []string{`golang\.org/x/.*`, ".*"})), RiskHigh, `mask ".*" matches canary`, ""},
		// modules with a character-class mask broad enough to match a canary.
		{"modules class", mut(t, developerExample, set("network.go_modules", []string{`[a-z0-9.-]+/.*`})), RiskHigh, "matches canary", ""},
		// allowlist, rw + exec.
		{"allowlist rw", []byte(yoloExample), RiskHigh, "exfiltration to or through allowed hosts", ""},
		// allowlist, read-only: read-only does not lower the level.
		{"allowlist ro", mut(t, yoloExample, ro...), RiskHigh, "read-only workspace does not lower the level", ""},
		// allowlist with bash instead of yolo: the same level, so yolo never lowers it.
		{"allowlist bash", mut(t, developerExample, hosts("allowlist", `proxy\.golang\.org`)), RiskHigh, "allowlist", ""},
		// allowlist whose mask matches a canary host: CRITICAL.
		{"allowlist .*", mut(t, yoloExample, hosts("allowlist", `registry\.npmjs\.org`, `.*\.invalid`)), RiskCritical, "an allowlist that is all", "unescaped"},
		// allowlist admitting every IP literal: CRITICAL.
		{"allowlist ip", mut(t, yoloExample, hosts("allowlist", `[0-9.]+`)), RiskCritical, `matches canary "192.0.2.1"`, ""},
		// allowlist with a broad host adds a warning, not a level.
		{"allowlist github", mut(t, yoloExample, hosts("allowlist", `github\.com`)), RiskHigh, "allowlist", "broad host github.com"},
		// a subdomain of a broad host also warns.
		{"allowlist raw.githubusercontent", mut(t, yoloExample, hosts("allowlist", `raw\.githubusercontent\.com`)), RiskHigh, "allowlist", "broad host githubusercontent.com"},
		// an unescaped '.' warns (and here also admits the broad host).
		{"allowlist github.com", mut(t, yoloExample, hosts("allowlist", `github.com`)), RiskHigh, "allowlist", "unescaped '.'"},
		// denylist is CRITICAL.
		{"denylist", mut(t, yoloExample, hosts("denylist", `evil\.example`)), RiskCritical, "effectively all", ""},
		// denylist through the alias, read-only: still CRITICAL.
		{"blacklist ro", mut(t, yoloExample, append(ro, hosts("blacklist", `evil\.example`))...), RiskCritical, "effectively all", ""},
		// all is CRITICAL.
		{"all", mut(t, yoloExample, set("network", map[string]any{"mode": "all", "ports": []any{"*"}, "rate": rate})), RiskCritical, "everything the worker can read can leave", ""},
	}
	for _, c := range cases {
		p := mustParse(t, c.data)
		r := EffectiveRisk(p)
		if r.Level != c.want {
			t.Errorf("%s: level %s, want %s (%q)", c.name, r.Level, c.want, r.Reasons)
		}
		if !strings.Contains(strings.Join(r.Reasons, "\n"), c.reason) {
			t.Errorf("%s: reasons %q lack %q", c.name, r.Reasons, c.reason)
		}
		if w := strings.Join(r.Warnings, "\n"); c.warning == "" && w != "" || !strings.Contains(w, c.warning) {
			t.Errorf("%s: warnings %q, want %q", c.name, r.Warnings, c.warning)
		}
		if r.PolicyID != p.ID() {
			t.Errorf("%s: policy id %q", c.name, r.PolicyID)
		}
	}
	// The §11 examples carry the levels the spec states.
	for ex, want := range map[string]Risk{reviewerExample: RiskLow, developerExample: RiskMedium, yoloExample: RiskHigh} {
		if got := EffectiveRisk(mustParse(t, []byte(ex))).Level; got != want {
			t.Errorf("example level %s, want %s", got, want)
		}
	}
}

func TestParseRisk(t *testing.T) {
	for _, r := range []Risk{RiskLow, RiskMedium, RiskHigh, RiskCritical} {
		if got, err := ParseRisk(r.String()); err != nil || got != r {
			t.Errorf("%s: %v %v", r, got, err)
		}
	}
	if _, err := ParseRisk("critical"); err == nil {
		t.Error("lower-case level accepted")
	}
}

func templateSpec(name string) TemplateSpec {
	s := TemplateSpec{Name: name, Project: "remote-workplace", Worker: name}
	if name == "developer" {
		s.WriteScope = []string{"internal/", "cmd/", "docs/"}
		s.GoModules = []string{`golang\.org/x/.*`, `github\.com/relux-works/.*`}
	}
	return s
}

// Golden `policy check` output per template; each template is a complete, valid file at its stated level.
func TestPolicyCheckGolden(t *testing.T) {
	for name, want := range map[string]Risk{"reviewer": RiskLow, "developer": RiskMedium, "yolo-offline": RiskMedium} {
		data, err := PolicyTemplate(templateSpec(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p := mustParse(t, data)
		r := EffectiveRisk(p)
		if r.Level != want {
			t.Errorf("%s: level %s, want %s", name, r.Level, want)
		}
		got := FormatPolicyCheck(p, r)
		path := filepath.Join("testdata", "policy-check-"+name+".golden")
		if *updateGolden {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		golden, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(golden) {
			t.Errorf("%s: check output differs from %s:\n%s", name, path, got)
		}
	}
}

// Templates are explicit: every key is written, and a missing or misplaced flag is refused.
func TestPolicyTemplate(t *testing.T) {
	data, err := PolicyTemplate(templateSpec("developer"))
	if err != nil {
		t.Fatal(err)
	}
	p := mustParse(t, data)
	if p.Tools.Settings["write_file"].Paths[0] != `internal/.*` || p.Network.Rate.RequestsPerMin != 600 || p.Limits.CPUs != 2 {
		t.Fatalf("developer %s", data)
	}
	data, _ = PolicyTemplate(templateSpec("reviewer"))
	if !strings.Contains(string(data), `"write_scope": []`) {
		t.Fatalf("reviewer must write out an empty scope: %s", data)
	}
	for _, s := range []TemplateSpec{
		{Name: "developer", Project: "p", Worker: "w", GoModules: []string{"x"}},                              // developer without a write scope
		{Name: "developer", Project: "p", Worker: "w", WriteScope: []string{"docs/"}},                         // developer without go modules
		{Name: "reviewer", Project: "p", Worker: "w", WriteScope: []string{"docs/"}},                          // reviewer is read-only
		{Name: "yolo-offline", Project: "p", Worker: "w", GoModules: []string{"x"}},                           // yolo-offline is offline
		{Name: "admin", Project: "p", Worker: "w"},                                                            // unknown template
		{Name: "reviewer", Project: "P", Worker: "w"},                                                         // invalid name
		{Name: "developer", Project: "p", Worker: "w", WriteScope: []string{"../"}, GoModules: []string{"x"}}, // invalid scope
	} {
		if _, err := PolicyTemplate(s); err == nil {
			t.Errorf("template %+v accepted", s)
		}
	}
}
