package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const reviewer = `{"version":1,"project":"p1","worker":"w1",
 "tools":{"mode":"allowlist","allow":["read_file","search"],
  "settings":{"read_file":{"paths":[".*"],"max_bytes":1048576},"search":{"paths":[".*"],"max_results":200}}},
 "workspace":{"access":"read-only","write_scope":[]},
 "network":{"mode":"none"},
 "limits":{"cpus":1,"memory_mib":1024,"pids":256,"call_timeout_s":300,"max_output_bytes":4194304,"disk_soft_mib":2048}}`

const yoloAllowlist = `{"version":1,"project":"p1","worker":"w1","tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},
 "network":{"mode":"allowlist","hosts":["registry\\.npmjs\\.org"],"ports":[443],
  "rate":{"requests_per_min":300,"max_conns":16,"bytes_per_day":5368709120}},
 "limits":{"cpus":2,"memory_mib":4096,"pids":1024,"call_timeout_s":1200,"max_output_bytes":4194304,"disk_soft_mib":8192}}`

const yoloAll = `{"version":1,"project":"p1","worker":"w1","tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},
 "network":{"mode":"all","ports":["*"],"rate":{"requests_per_min":300,"max_conns":16,"bytes_per_day":5368709120}},
 "limits":{"cpus":2,"memory_mib":4096,"pids":1024,"call_timeout_s":1200,"max_output_bytes":4194304,"disk_soft_mib":8192}}`

// rwScope is a read-write, network-none policy with the given write_scope JSON.
func rwScope(scope string) string {
	return `{"version":1,"project":"p1","worker":"w1","tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":` + scope + `},"network":{"mode":"none"},
 "limits":{"cpus":2,"memory_mib":2048,"pids":512,"call_timeout_s":600,"max_output_bytes":4194304,"disk_soft_mib":4096}}`
}

type env struct {
	t     *testing.T
	state string
	dir   string
}

func newEnv(t *testing.T) *env { return &env{t: t, state: t.TempDir(), dir: t.TempDir()} }

func (e *env) file(name, content string) string {
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *env) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"--state-dir", e.state}, args...), nil, &out, &errb)
	return code, out.String(), errb.String()
}

// Exit codes of the policy commands (policy.md §8): 0 ok, 1 invalid, 2 usage, 3 not found, 4 risk, 5 egress.
func TestPolicyExitCodes(t *testing.T) {
	e := newEnv(t)
	rev, yolo, all := e.file("rev.json", reviewer), e.file("yolo.json", yoloAllowlist), e.file("all.json", yoloAll)
	bad := e.file("bad.json", strings.Replace(reviewer, `"pids":256`, `"pids":2.0`, 1))
	noteYolo := e.file("note.json", strings.Replace(yoloAllowlist, `"worker":"w1",`, `"worker":"w1","note":"registry",`, 1))
	other := e.file("other.json", strings.Replace(reviewer, `"p1"`, `"p2"`, 1))
	for _, c := range []struct {
		args []string
		code int
		out  string // substring of stdout, or of stderr when the code is not 0
	}{
		{[]string{"policy", "check", rev}, 0, "risk       LOW"},                                                                       // a valid file
		{[]string{"policy", "check", yolo}, 0, "risk       HIGH"},                                                                     // egress modes are still checked
		{[]string{"policy", "check", rev, "--json"}, 0, `"level": "LOW"`},                                                             // flags after FILE
		{[]string{"policy", "check", bad}, 1, "limits.pids"},                                                                          // invalid: names the field
		{[]string{"policy", "check", filepath.Join(e.dir, "missing.json")}, 3, "no such"},                                             // not found
		{[]string{"policy", "check"}, 2, "FILE"},                                                                                      // usage
		{[]string{"policy", "check", "--max-risk", "MEDIUM", yolo}, 4, "above --max-risk"},                                            // above the limit
		{[]string{"policy", "check", "--max-risk", "HIGH", yolo}, 0, "HIGH"},                                                          // at the limit
		{[]string{"policy", "check", "--max-risk", "high", yolo}, 2, "unknown risk"},                                                  // bad level
		{[]string{"policy", "show", "p1", "w1"}, 3, "no stored policy"},                                                               // nothing stored yet
		{[]string{"policy", "set", "--project", "p1", "--worker", "w1", yolo}, 4, "note"},                                             // HIGH without note
		{[]string{"policy", "set", "--project", "p1", "--worker", "w1", noteYolo}, 5, "egress not confirmed"},                         // HIGH with a note: stored, the service is absent
		{[]string{"policy", "set", "--project", "p1", "--worker", "w1", all}, 4, "accept-risk CRITICAL"},                              // CRITICAL
		{[]string{"policy", "set", "--project", "p1", "--worker", "w1", "--accept-risk", "CRITICAL", all}, 5, "egress not confirmed"}, // accepted: stored, the service is absent
		{[]string{"policy", "set", "--project", "p1", "--worker", "w1", "--accept-risk", "HIGH", all}, 2, "only CRITICAL"},
		{[]string{"policy", "set", "--project", "p1", "--worker", "w1", other}, 1, "project"}, // target mismatch
		{[]string{"policy", "set", "--project", "p1", rev}, 2, "--worker"},                    // usage
		{[]string{"policy", "set", "--project", "p1", "--worker", "w1", rev}, 0, "p1.w1 id="}, // stored
		{[]string{"policy", "show", "p1", "w1"}, 0, "stored     "},
		{[]string{"policy", "show", "p1", "w1", "--json"}, 0, `"policy_id"`},
		{[]string{"policy", "rm", "p1", "w1"}, 0, ""},
		{[]string{"policy", "rm", "p1", "w1"}, 3, "no stored policy"},
		{[]string{"policy", "template", "developer", "--project", "p1", "--worker", "w1"}, 2, "--write-scope"},
		{[]string{"policy", "template", "reviewer", "--project", "p1", "--worker", "w1", "--write-scope", "docs/"}, 2, "takes no"},
		{[]string{"policy", "template", "admin", "--project", "p1", "--worker", "w1"}, 2, "unknown template"},
		{[]string{"policy", "template", "reviewer", "--project", "P1", "--worker", "w1"}, 1, "project"},
		{[]string{"policy", "frobnicate"}, 2, "unknown policy command"},
	} {
		code, out, errb := e.run(c.args...)
		got := out
		if c.code != 0 {
			got = errb
		}
		if code != c.code || !strings.Contains(got, c.out) {
			t.Errorf("%q: exit %d, want %d; stdout %q stderr %q", c.args, code, c.code, out, errb)
		}
	}
	code, out, _ := e.run("policy", "check", rev, "--json")
	var r struct {
		Level    string   `json:"level"`
		Reasons  []string `json:"reasons"`
		Warnings []string `json:"warnings"`
		PolicyID string   `json:"policy_id"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r.Level != "LOW" || len(r.PolicyID) != 64 || r.Warnings == nil {
		t.Fatalf("json %q", out)
	}
}

// A template's output is a file that check accepts and set stores.
func TestPolicyTemplateRoundTrip(t *testing.T) {
	e := newEnv(t)
	code, out, errb := e.run("policy", "template", "developer", "--project", "p1", "--worker", "w1",
		"--write-scope", "internal/,docs/", "--go-modules", `golang\.org/x/.*`, "--go-modules", `example\.com/{1,2}x`)
	if code != 0 || !strings.Contains(out, `"example\\.com/{1,2}x"`) {
		t.Fatalf("exit %d %s %s", code, out, errb)
	}
	if code, out, _ := e.run("policy", "check", e.file("dev.json", out)); code != 0 || !strings.Contains(out, "MEDIUM") {
		t.Fatalf("check %d %s", code, out)
	}
	_, out, _ = e.run("policy", "template", "yolo-offline", "--project", "p1", "--worker", "w1")
	if code, out, errb := e.run("policy", "set", "--project", "p1", "--worker", "w1", e.file("yolo.json", out)); code != 0 {
		t.Fatalf("set %d %s %s", code, out, errb)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// apply --policy bounds the patch by the stored write_scope: [] refuses (exit 5, as --write-scope does),
// ["*"] applies, a missing policy is not found (3) and a malformed reference is a usage error (2).
func TestApplyPolicy(t *testing.T) {
	e := newEnv(t)
	repo := t.TempDir()
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "config", "commit.gpgsign", "false")
	os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "init")
	os.WriteFile(filepath.Join(repo, "README.md"), []byte("changed\n"), 0o644)
	patch := e.file("p.patch", git(t, repo, "diff", "--binary", "HEAD"))
	git(t, repo, "checkout", "-q", "--", ".")

	if code, _, errb := e.run("apply", "--repo", repo, "--policy", "p1.w1", patch); code != 3 || !strings.Contains(errb, "no stored policy") {
		t.Fatalf("missing policy: %d %s", code, errb)
	}
	if code, _, _ := e.run("apply", "--repo", repo, "--policy", "p1w1", patch); code != 2 {
		t.Fatalf("malformed --policy: %d", code)
	}
	e.run("policy", "set", "--project", "p1", "--worker", "w1", e.file("empty.json", rwScope(`[]`)))
	if code, _, errb := e.run("apply", "--repo", repo, "--policy", "p1.w1", patch); code != 5 || !strings.Contains(errb, "out of scope: README.md") {
		t.Fatalf("empty policy scope: %d %s", code, errb)
	}
	e.run("policy", "set", "--project", "p1", "--worker", "w1", e.file("all.json", rwScope(`["*"]`)))
	if code, _, errb := e.run("apply", "--repo", repo, "--policy", "p1.w1", "--write-scope", "docs/", patch); code != 5 {
		t.Fatalf("intersection with --write-scope: %d %s", code, errb)
	}
	if code, out, errb := e.run("apply", "--repo", repo, "--policy", "p1.w1", patch); code != 0 || out != "README.md\n" {
		t.Fatalf("whole-repository scope: %d %q %s", code, out, errb)
	}
}

// The worktree flags are usage errors (exit 2) before any docker call: exactly one of --repo and --from-worktree,
// the snapshot flags only with --from-worktree, --snapshot-tree only with --allow-dirty.
func TestWorktreeFlags(t *testing.T) {
	e := newEnv(t)
	patch := e.file("p.patch", "")
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"provision", "--project", "p1", "--worker", "w1"}, "--repo or --from-worktree"},
		{[]string{"provision", "--project", "p1", "--worker", "w1", "--from-worktree", e.dir, "--repo", e.dir}, "excludes --repo"},
		{[]string{"provision", "--project", "p1", "--worker", "w1", "--from-worktree", e.dir, "--ref", "main"}, "excludes --repo and --ref"},
		{[]string{"provision", "--project", "p1", "--worker", "w1", "--repo", e.dir, "--allow-secret-path", ".env"}, "need --from-worktree"},
		{[]string{"provision", "--project", "p1", "--worker", "w1", "--from-worktree", e.dir, "--max-untracked-mib", "-1"}, "negative"},
		{[]string{"seed-gomod", "--project", "p1"}, "--repo or --from-worktree"},
		{[]string{"seed-gomod", "--project", "p1", "--from-worktree", e.dir, "--repo", e.dir}, "excludes --repo"},
		{[]string{"apply", "--repo", e.dir, "--snapshot-tree", strings.Repeat("a", 40), patch}, "needs --allow-dirty"},
	} {
		if code, _, errb := e.run(c.args...); code != 2 || !strings.Contains(errb, c.msg) {
			t.Errorf("%q: exit %d %s", c.args, code, errb)
		}
	}
}

// apply --allow-dirty applies into a dirty linked worktree (exit 0, paths on stdout) and reports divergence from
// --snapshot-tree on stderr without blocking; the primary checkout is refused (exit 3); without the flag, dirty is exit 3.
func TestApplyAllowDirty(t *testing.T) {
	e := newEnv(t)
	repo := t.TempDir()
	git(t, repo, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "init")
	os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644)
	git(t, repo, "add", "-N", "a.txt")
	patch := e.file("p.patch", git(t, repo, "diff", "--binary", "HEAD"))
	git(t, repo, "rm", "-q", "--cached", "a.txt")
	os.Remove(filepath.Join(repo, "a.txt"))
	wt := filepath.Join(t.TempDir(), "wt")
	git(t, repo, "worktree", "add", "-q", "-b", "story", wt)
	os.WriteFile(filepath.Join(wt, "README.md"), []byte("dirty\n"), 0o644)

	if code, _, errb := e.run("apply", "--repo", wt, patch); code != 3 || !strings.Contains(errb, "dirty") {
		t.Fatalf("without --allow-dirty: %d %s", code, errb)
	}
	if code, _, errb := e.run("apply", "--repo", repo, "--allow-dirty", patch); code != 3 || !strings.Contains(errb, "primary checkout") {
		t.Fatalf("primary checkout: %d %s", code, errb)
	}
	code, out, errb := e.run("apply", "--repo", wt, "--allow-dirty", "--snapshot-tree", strings.Repeat("a", 40), patch)
	if code != 0 || out != "a.txt\n" || !strings.Contains(errb, "target diverged since snapshot: unknown number of paths") {
		t.Fatalf("dirty apply: %d %q %s", code, out, errb)
	}
	if b, _ := os.ReadFile(filepath.Join(wt, "README.md")); string(b) != "dirty\n" {
		t.Fatalf("unrelated change lost: %q", b)
	}
}

// The egress commands' usage errors exit 2 before any docker call.
func TestEgressUsage(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"egress"}, "up, down, status or log"},
		{[]string{"egress", "restart"}, "unknown egress command"},
		{[]string{"egress", "up", "now"}, "takes no arguments"},
		{[]string{"egress", "status", "--json"}, "flag provided but not defined"},
		{[]string{"egress", "log", "extra"}, "takes only flags"},
		{[]string{"egress", "log", "--tail", "5"}, "flag provided but not defined"},
	} {
		if code, _, errb := e.run(c.args...); code != 2 || !strings.Contains(errb, c.msg) {
			t.Errorf("%q: exit %d %s", c.args, code, errb)
		}
	}
}

// The production CLI takes migration before New: missing paths/images refuse
// with usage 2 and never implicitly initialize canonical host state.
func TestMigrationCLIRequiresExplicitInputs(t *testing.T) {
	for _, args := range [][]string{
		{"migrate-legacy"},
		{"migrate-legacy", "--source-state-dir", "/source"},
		{"--image", "remote-workplace/base:2", "migrate-legacy", "--source-state-dir", "/source"},
		{"migrate-legacy", "--source-state-dir", "/source", "--force"},
	} {
		var out, errout bytes.Buffer
		if code := run(context.Background(), args, nil, &out, &errout); code != 2 {
			t.Fatalf("%v: code=%d", args, code)
		}
	}
}

// Canonical environment selects the reserved state, making the production
// initialization refusal observable without contacting a daemon.
func TestCanonicalEnvironmentRefusesIncompleteState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "canonical")
	if err := os.WriteFile(state+".migration-incomplete", []byte("reserved\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RWP_STATE_DIR", state)
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"ls"}, nil, &out, &errout); code != 3 || !strings.Contains(errout.String(), "cold migration is not published") {
		t.Fatalf("code=%d err=%s", code, errout.String())
	}
}
