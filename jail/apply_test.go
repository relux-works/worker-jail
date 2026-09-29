package jail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func applyBytes(repo string, patch []byte, allow bool) (ApplyReport, error) {
	return Apply(context.Background(), repo, bytes.NewReader(patch), ApplyOptions{AllowReviewRequired: allow})
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// An ordinary patch applies to worktree and index, without a commit (positive control).
func TestApplyOrdinary(t *testing.T) {
	repo := newRepo(t)
	head := git(t, repo, "rev-parse", "HEAD")
	patch := makePatch(t, repo, func(d string) {
		writeFile(t, filepath.Join(d, "jail", "x.go"), "package jail\n")
		writeFile(t, filepath.Join(d, "README.md"), "changed\n")
	})
	rep, err := applyBytes(repo, patch, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Paths) != 2 || len(rep.Flagged) != 0 {
		t.Fatalf("report %+v", rep)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "README.md")); string(b) != "changed\n" {
		t.Fatalf("README %q", b)
	}
	if git(t, repo, "diff", "--cached", "--name-only") == "" || git(t, repo, "rev-parse", "HEAD") != head {
		t.Fatal("patch must be staged and never committed")
	}
}

const gitHookPatch = `diff --git a/.git/hooks/post-commit b/.git/hooks/post-commit
new file mode 100755
index 0000000..1111111
--- /dev/null
+++ b/.git/hooks/post-commit
@@ -0,0 +1,2 @@
+#!/bin/sh
+touch /tmp/pwned
`

// A patch writing under .git (any spelling) is refused even with the allow flag, and writes nothing.
func TestApplyRefusesGitPaths(t *testing.T) {
	for _, dir := range []string{".git", ".GIT", "sub/.Git"} {
		repo := newRepo(t)
		p := bytes.ReplaceAll([]byte(gitHookPatch), []byte(".git/hooks"), []byte(dir+"/hooks"))
		_, err := applyBytes(repo, p, true)
		if !errors.Is(err, ErrGitPath) {
			t.Fatalf("%s: err %v", dir, err)
		}
		if exists(filepath.Join(repo, dir, "hooks", "post-commit")) {
			t.Fatalf("%s: hook written", dir)
		}
		if git(t, repo, "status", "--porcelain") != "" {
			t.Fatalf("%s: repo changed", dir)
		}
	}
	if !isGitPath(".git/x") || !isGitPath("a/.GIT/x") || !isGitPath("a/.git./x") || isGitPath(".github/x") || isGitPath("a.git/x") {
		t.Fatal("isGitPath table wrong")
	}
}

// A symlink is flagged and refused, then applied with the allow flag.
func TestApplySymlink(t *testing.T) {
	repo := newRepo(t)
	patch := makePatch(t, repo, func(d string) {
		if err := os.Symlink("/etc/passwd", filepath.Join(d, "link")); err != nil {
			t.Fatal(err)
		}
	})
	rep, err := applyBytes(repo, patch, false)
	if !errors.Is(err, ErrReviewRequired) || len(rep.Flagged) != 1 || rep.Flagged[0].Reason != "symlink" || exists(filepath.Join(repo, "link")) {
		t.Fatalf("rep %+v err %v", rep, err)
	}
	if _, err := applyBytes(repo, patch, true); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(repo, "link")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink not applied: %v", err)
	}
}

// A gitlink (submodule entry) is flagged and refused.
func TestApplyGitlink(t *testing.T) {
	repo := newRepo(t)
	head := git(t, repo, "rev-parse", "HEAD")
	d := filepath.Join(t.TempDir(), "c")
	git(t, filepath.Dir(d), "clone", "-q", repo, d)
	git(t, d, "update-index", "--add", "--cacheinfo", "160000,"+head+",sub") // add -A would drop the entry
	patch := []byte(git(t, d, "diff", "--cached", "--binary", "--full-index", "HEAD") + "\n")
	rep, err := applyBytes(repo, patch, false)
	if !errors.Is(err, ErrReviewRequired) || len(rep.Flagged) != 1 || rep.Flagged[0].Reason != "gitlink" {
		t.Fatalf("rep %+v err %v", rep, err)
	}
}

// CI, git-behaviour and agent-instruction paths are refused without the flag, in any case and depth.
func TestApplyReviewRequiredPaths(t *testing.T) {
	for _, p := range []string{".github/workflows/x.yml", ".GitHub/workflows/x.yml", "docs/CLAUDE.md", ".gitattributes"} {
		repo := newRepo(t)
		patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, p), "x\n") })
		rep, err := applyBytes(repo, patch, false)
		if !errors.Is(err, ErrReviewRequired) || len(rep.Flagged) != 1 || exists(filepath.Join(repo, p)) {
			t.Fatalf("%s: rep %+v err %v", p, rep, err)
		}
		if git(t, repo, "status", "--porcelain") != "" {
			t.Fatalf("%s: repo changed", p)
		}
	}
}

// A dirty target (tracked change or untracked file) is refused with ErrDirty.
func TestApplyDirty(t *testing.T) {
	repo := newRepo(t)
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "a.txt"), "a\n") })
	writeFile(t, filepath.Join(repo, "untracked"), "u\n")
	if _, err := applyBytes(repo, patch, false); !errors.Is(err, ErrDirty) {
		t.Fatalf("untracked: %v", err)
	}
	os.Remove(filepath.Join(repo, "untracked"))
	writeFile(t, filepath.Join(repo, "README.md"), "edit\n")
	if _, err := applyBytes(repo, patch, false); !errors.Is(err, ErrDirty) {
		t.Fatalf("modified: %v", err)
	}
	if _, err := applyBytes(t.TempDir(), patch, false); err == nil {
		t.Fatal("non-repo accepted")
	}
}

// A patch that does not apply fails with git's error and leaves the repo unchanged.
func TestApplyConflict(t *testing.T) {
	repo := newRepo(t)
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "README.md"), "theirs\n") })
	writeFile(t, filepath.Join(repo, "README.md"), "ours\n")
	git(t, repo, "commit", "-q", "-am", "ours")
	if _, err := applyBytes(repo, patch, false); err == nil {
		t.Fatal("conflicting patch applied")
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "README.md")); string(b) != "ours\n" || git(t, repo, "status", "--porcelain") != "" {
		t.Fatal("repo changed by failed apply")
	}
	if _, err := applyBytes(repo, []byte("garbage"), false); err == nil {
		t.Fatal("garbage applied")
	}
}

// Target hooks never fire during Apply; control: plain `git apply --index` on a twin fires the same hook.
func TestApplyHooksNeverFire(t *testing.T) {
	repo := newRepo(t)
	twin := filepath.Join(t.TempDir(), "twin")
	git(t, filepath.Dir(twin), "clone", "-q", repo, twin)
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "a.txt"), "a\n") })
	install := func(r string) string {
		marker := filepath.Join(t.TempDir(), "marker")
		hook := filepath.Join(r, ".git", "hooks", "post-index-change")
		if err := os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return marker
	}
	m1, m2 := install(repo), install(twin)
	if _, err := applyBytes(repo, patch, false); err != nil {
		t.Fatal(err)
	}
	if exists(m1) {
		t.Fatal("hook fired during Apply")
	}
	cmd := exec.Command("git", "-C", twin, "apply", "--index", "-")
	cmd.Stdin = bytes.NewReader(patch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("control apply: %v %s", err, out)
	}
	if !exists(m2) {
		t.Fatal("control: hook did not fire on plain git apply --index; the test proves nothing")
	}
}

// reviewRequired flags the protocol's list, case-insensitively, and leaves ordinary paths alone.
func TestReviewRequired(t *testing.T) {
	flagged := []string{".github/workflows/ci.yml", ".GITHUB/x", "a/.circleci/config.yml", ".githooks/pre-commit", ".husky/pre-push",
		".vscode/tasks.json", ".claude/settings.json", "x/.codex/c", ".agents/skills/s.md", ".gitattributes", "sub/.gitmodules",
		".gitlab-ci.yml", ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".envrc", "AGENTS.md", "docs/Claude.md", ".mcp.json"}
	ordinary := []string{"README.md", "jail/x.go", "docs/agents-notes.md", "github/x", "src/claude.md.txt", "my.envrc.bak",
		"lefthook.yml.example", "gitattributes", "notes/.github-ish", "Makefile", ".gitignore"}
	for _, p := range flagged {
		if _, ok := reviewRequired(p); !ok {
			t.Errorf("%s not flagged", p)
		}
	}
	for _, p := range ordinary {
		if why, ok := reviewRequired(p); ok {
			t.Errorf("%s flagged: %s", p, why)
		}
	}
}

// Hunk lines that merely look like .git headers ("-- .git", "++ .git/config") apply fine; header paths with .git still fail.
func TestApplyGitPathOnlyInHeaders(t *testing.T) {
	repo := newRepo(t)
	writeFile(t, filepath.Join(repo, "notes.txt"), "-- .git\nkeep\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "notes")
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "notes.txt"), "keep\n++ .git/config\n") })
	if !bytes.Contains(patch, []byte("\n--- .git\n")) || !bytes.Contains(patch, []byte("\n+++ .git/config\n")) {
		t.Fatalf("fixture lacks the look-alike lines:\n%s", patch)
	}
	if _, err := applyBytes(repo, patch, false); err != nil {
		t.Fatalf("content lines treated as headers: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "notes.txt")); string(b) != "keep\n++ .git/config\n" {
		t.Fatalf("notes.txt %q", b)
	}
	if gitPathInHeaders([]byte(gitHookPatch)) == "" {
		t.Fatal("header .git path missed")
	}
}

// Inherited GIT_DIR / GIT_INDEX_FILE never redirect host git: Apply and resolveBase act on the intended repo.
func TestHostEnvIgnoresGitVars(t *testing.T) {
	repo := newRepo(t)
	decoy := newRepo(t)
	writeFile(t, filepath.Join(decoy, "d.txt"), "d\n")
	git(t, decoy, "add", "-A")
	git(t, decoy, "commit", "-q", "-m", "decoy")
	head := git(t, repo, "rev-parse", "HEAD")
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "a.txt"), "a\n") })
	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "bogus-index"))
	for _, kv := range hostEnv() {
		if strings.HasPrefix(kv, "GIT_") {
			t.Fatalf("hostEnv leaks %s", kv)
		}
	}
	base, _, err := resolveBase(context.Background(), repo, "HEAD")
	if err != nil || base != head {
		t.Fatalf("resolveBase %s %v, want %s", base, err, head)
	}
	if _, err := applyBytes(repo, patch, false); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(repo, "a.txt")) || exists(filepath.Join(decoy, "a.txt")) {
		t.Fatal("patch applied to the wrong repo")
	}
}

// A scope entry ending in "/" matches every path under that directory at a component boundary,
// any other entry matches exactly one file, both case-insensitively.
func TestInWriteScope(t *testing.T) {
	for _, c := range []struct {
		scope []string
		path  string
		want  bool
	}{
		{[]string{"jail/"}, "jail/x.go", true},
		{[]string{"jail/"}, "jail/sub/deep/x.go", true},
		{[]string{"JAIL/"}, "jail/x.go", true},
		{[]string{"jail/"}, "jailbreak.go", false},
		{[]string{"jail/"}, "jail", false},
		{[]string{"jail"}, "jailbreak.go", false},
		{[]string{"jail"}, "jail/x.go", false},
		{[]string{"Makefile"}, "makefile", true},
		{[]string{"Makefile"}, "sub/Makefile", false},
		{[]string{"docs/a/"}, "docs/b/x.md", false},
		{[]string{"docs/", "Makefile"}, "Makefile", true},
	} {
		if got := inWriteScope(c.scope, c.path); got != c.want {
			t.Errorf("inWriteScope(%q, %q) = %v, want %v", c.scope, c.path, got, c.want)
		}
	}
}

// Malformed or .git-naming scope entries are rejected before the repo is touched; canonical ones pass.
func TestValidateWriteScope(t *testing.T) {
	for _, e := range []string{"", "/", "/etc", "a//b", "./a", "a/./b", "a/..", "../x", "a//", ".git/", "sub/.GIT", ".Git"} {
		if validateWriteScope([]string{"ok/", e}) == nil {
			t.Errorf("entry %q accepted", e)
		}
		if _, err := Apply(context.Background(), "/nonexistent", bytes.NewReader(nil), ApplyOptions{WriteScope: []string{e}}); err == nil || !strings.Contains(err.Error(), "write-scope") {
			t.Errorf("Apply with entry %q: %v", e, err)
		}
	}
	if err := validateWriteScope([]string{"docs/", "Makefile", "jail/x_test.go", ".github/", "a.git/"}); err != nil {
		t.Fatal(err)
	}
}

func scopePatch(t *testing.T, repo string) []byte {
	return makePatch(t, repo, func(d string) {
		writeFile(t, filepath.Join(d, "Makefile"), "all:\n")
		writeFile(t, filepath.Join(d, "jail", "x_test.go"), "package jail\n")
	})
}

// A patch outside the scope is refused with ErrOutOfScope, even with AllowReviewRequired, and changes nothing.
func TestApplyOutOfScope(t *testing.T) {
	repo := newRepo(t)
	rep, err := Apply(context.Background(), repo, bytes.NewReader(scopePatch(t, repo)), ApplyOptions{AllowReviewRequired: true, WriteScope: []string{"docs/"}})
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("err %v", err)
	}
	if len(rep.OutOfScope) != 2 {
		t.Fatalf("out of scope %v", rep.OutOfScope)
	}
	if git(t, repo, "status", "--porcelain") != "" {
		t.Fatal("repo changed")
	}
}

// The same patch applies when the scope covers both paths (positive control).
func TestApplyInScope(t *testing.T) {
	repo := newRepo(t)
	rep, err := Apply(context.Background(), repo, bytes.NewReader(scopePatch(t, repo)), ApplyOptions{WriteScope: []string{"Makefile", "jail/"}})
	if err != nil || len(rep.OutOfScope) != 0 {
		t.Fatalf("err %v report %+v", err, rep)
	}
	if !exists(filepath.Join(repo, "jail", "x_test.go")) || !exists(filepath.Join(repo, "Makefile")) {
		t.Fatal("patch not applied")
	}
}

// A rename from inside the scope to outside it is refused: the added path is checked.
// The inside-to-inside rename is the control.
func TestApplyRenameAcrossScope(t *testing.T) {
	repo := newRepo(t)
	writeFile(t, filepath.Join(repo, "docs", "a.md"), "doc\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "docs")
	mv := func(to string) []byte {
		return makePatch(t, repo, func(d string) { git(t, d, "mv", "docs/a.md", to) })
	}
	rep, err := Apply(context.Background(), repo, bytes.NewReader(mv("b.md")), ApplyOptions{WriteScope: []string{"docs/"}})
	if !errors.Is(err, ErrOutOfScope) || len(rep.OutOfScope) != 1 || rep.OutOfScope[0] != "b.md" {
		t.Fatalf("err %v report %+v", err, rep)
	}
	if git(t, repo, "status", "--porcelain") != "" {
		t.Fatal("repo changed")
	}
	if _, err := Apply(context.Background(), repo, bytes.NewReader(mv("docs/b.md")), ApplyOptions{WriteScope: []string{"docs/"}}); err != nil {
		t.Fatal(err)
	}
}

// A nil scope keeps the old behaviour: the patch applies and nothing is reported out of scope.
func TestApplyNilScope(t *testing.T) {
	repo := newRepo(t)
	rep, err := applyBytes(repo, scopePatch(t, repo), false)
	if err != nil || rep.OutOfScope != nil || len(rep.Paths) != 2 {
		t.Fatalf("err %v report %+v", err, rep)
	}
}
