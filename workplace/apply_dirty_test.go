package workplace

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// linkedWorktree returns a repo and a linked worktree of it on branch story, at the repo's HEAD.
func linkedWorktree(t *testing.T) (repo, wt string) {
	t.Helper()
	repo = newRepo(t)
	writeFile(t, filepath.Join(repo, "src", "a.go"), "package src\n\nfunc A() int { return 1 }\n")
	writeFile(t, filepath.Join(repo, "notes.md"), "one\ntwo\nthree\n")
	commitAll(t, repo, "files")
	wt = filepath.Join(t.TempDir(), "story")
	git(t, repo, "worktree", "add", "-q", "-b", "story", wt)
	return repo, wt
}

func dirtyApply(wt string, patch []byte, o ApplyOptions) (ApplyReport, error) {
	o.AllowDirty = true
	return Apply(context.Background(), wt, bytes.NewReader(patch), o)
}

// gitState is what a dirty apply must never write: the worktree's index bytes, HEAD and every ref.
func gitState(t *testing.T, wt string) string {
	t.Helper()
	idx, err := os.ReadFile(git(t, wt, "rev-parse", "--path-format=absolute", "--git-path", "index"))
	if err != nil {
		t.Fatal(err)
	}
	return string(idx) + "\n" + git(t, wt, "rev-parse", "HEAD") + "\n" + git(t, wt, "for-each-ref")
}

// An unrelated dirty change, an untracked file and a staged change stay intact; the patch lands in the working
// tree only (index, HEAD and refs unchanged); the report lists its paths.
func TestApplyDirtyKeepsUnrelatedChanges(t *testing.T) {
	repo, wt := linkedWorktree(t)
	patch := makePatch(t, repo, func(d string) {
		writeFile(t, filepath.Join(d, "src", "a.go"), "package src\n\nfunc A() int { return 2 }\n")
		writeFile(t, filepath.Join(d, "src", "b.go"), "package src\n")
	})
	writeFile(t, filepath.Join(wt, "README.md"), "orchestrator edit\n")
	writeFile(t, filepath.Join(wt, "scratch.txt"), "untracked\n")
	writeFile(t, filepath.Join(wt, "notes.md"), "one\ntwo\nthree\nfour\n")
	git(t, wt, "add", "notes.md")
	state := gitState(t, wt)
	rep, err := dirtyApply(wt, patch, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Paths, ",") != "src/a.go,src/b.go" {
		t.Fatalf("paths %v", rep.Paths)
	}
	for p, want := range map[string]string{"README.md": "orchestrator edit\n", "scratch.txt": "untracked\n",
		"notes.md": "one\ntwo\nthree\nfour\n", "src/a.go": "package src\n\nfunc A() int { return 2 }\n", "src/b.go": "package src\n"} {
		if b, _ := os.ReadFile(filepath.Join(wt, p)); string(b) != want {
			t.Errorf("%s = %q, want %q", p, b, want)
		}
	}
	if gitState(t, wt) != state {
		t.Fatal("index, HEAD or refs changed")
	}
}

// A patch with one conflicting hunk is refused whole, and so is a new file that collides with an untracked one:
// the tree (and .git) is byte-identical afterwards. The non-conflicting half applies on its own (control).
func TestApplyDirtyConflictRefusedWhole(t *testing.T) {
	repo, wt := linkedWorktree(t)
	patch := makePatch(t, repo, func(d string) {
		writeFile(t, filepath.Join(d, "src", "a.go"), "package src\n\nfunc A() int { return 2 }\n")
		writeFile(t, filepath.Join(d, "notes.md"), "one\nTWO\nthree\n")
	})
	writeFile(t, filepath.Join(wt, "notes.md"), "one\nzwei\nthree\n")
	before := fingerprint(t, repo, wt)
	if _, err := dirtyApply(wt, patch, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "does not apply") {
		t.Fatalf("conflict: %v", err)
	}
	sameFingerprint(t, before, fingerprint(t, repo, wt))

	collide := makePatch(t, repo, func(d string) {
		writeFile(t, filepath.Join(d, "src", "a.go"), "package src\n\nfunc A() int { return 2 }\n")
		writeFile(t, filepath.Join(d, "new.txt"), "theirs\n")
	})
	writeFile(t, filepath.Join(wt, "new.txt"), "mine\n")
	before = fingerprint(t, repo, wt)
	if _, err := dirtyApply(wt, collide, ApplyOptions{}); err == nil {
		t.Fatal("untracked collision applied")
	}
	sameFingerprint(t, before, fingerprint(t, repo, wt))

	only := makePatch(t, repo, func(d string) {
		writeFile(t, filepath.Join(d, "src", "a.go"), "package src\n\nfunc A() int { return 2 }\n")
	})
	if _, err := dirtyApply(wt, only, ApplyOptions{}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// Hooks planted in the target (common hooks dir and a core.hooksPath) never fire during a dirty apply.
// Control: a plain `git apply --index` in the same target fires them.
func TestApplyDirtyHooksNeverFire(t *testing.T) {
	repo, wt := linkedWorktree(t)
	marker := filepath.Join(t.TempDir(), "marker")
	hooks := filepath.Join(t.TempDir(), "hooks")
	for _, h := range []string{"post-index-change", "pre-applypatch", "post-applypatch", "reference-transaction", "post-checkout"} {
		writeFile(t, filepath.Join(hooks, h), "#!/bin/sh\necho "+h+" >> "+marker+"\n")
		os.Chmod(filepath.Join(hooks, h), 0o755)
		writeFile(t, filepath.Join(repo, ".git", "hooks", h), "#!/bin/sh\necho "+h+" >> "+marker+"\n")
		os.Chmod(filepath.Join(repo, ".git", "hooks", h), 0o755)
	}
	git(t, wt, "config", "core.hooksPath", hooks)
	writeFile(t, filepath.Join(wt, "README.md"), "dirty\n")
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "a.txt"), "a\n") })
	if _, err := dirtyApply(wt, patch, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("hook fired: %s", b)
	}
	other := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "b.txt"), "b\n") })
	if _, err := gitApplyIndex(wt, other); err != nil {
		t.Fatalf("control apply: %v", err)
	}
	if !exists(marker) {
		t.Fatal("control: plain git apply --index fired no hook; the test proves nothing")
	}
}

func gitApplyIndex(dir string, patch []byte) (string, error) {
	f := filepath.Join(os.TempDir(), "rwp-test-"+filepath.Base(dir)+".patch")
	if err := os.WriteFile(f, patch, 0o600); err != nil {
		return "", err
	}
	defer os.Remove(f)
	return gitMay(dir, "apply", "--index", f)
}

// Every v1 gate stays first and active in a dirty target: .git, write scope (task and policy), symlink, gitlink and
// review-required; each refusal leaves the tree identical. Allowed review-required paths apply (control).
func TestApplyDirtyGates(t *testing.T) {
	repo, wt := linkedWorktree(t)
	head := git(t, repo, "rev-parse", "HEAD")
	writeFile(t, filepath.Join(wt, "README.md"), "dirty\n")
	none := func() *[]string { s := []string{}; return &s }
	gitlink := func() []byte {
		d := filepath.Join(t.TempDir(), "c")
		git(t, filepath.Dir(d), "clone", "-q", repo, d)
		git(t, d, "update-index", "--add", "--cacheinfo", "160000,"+head+",sub")
		return []byte(git(t, d, "diff", "--cached", "--binary", "--full-index", "HEAD") + "\n")
	}()
	symlink := makePatch(t, repo, func(d string) {
		if err := os.Symlink("/etc/passwd", filepath.Join(d, "link")); err != nil {
			t.Fatal(err)
		}
	})
	ci := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, ".github", "workflows", "x.yml"), "on: push\n") })
	scoped := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "Makefile"), "all:\n") })
	for _, c := range []struct {
		name  string
		patch []byte
		o     ApplyOptions
		is    error
	}{
		{".git", []byte(gitHookPatch), ApplyOptions{AllowReviewRequired: true}, ErrGitPath},
		{".GIT in a subdirectory", bytes.ReplaceAll([]byte(gitHookPatch), []byte(".git/hooks"), []byte("sub/.GIT/hooks")), ApplyOptions{AllowReviewRequired: true}, ErrGitPath},
		{"task scope", scoped, ApplyOptions{AllowReviewRequired: true, WriteScope: []string{"docs/"}}, ErrOutOfScope},
		{"policy scope", scoped, ApplyOptions{AllowReviewRequired: true, PolicyScope: none()}, ErrOutOfScope},
		{"symlink", symlink, ApplyOptions{}, ErrReviewRequired},
		{"gitlink", gitlink, ApplyOptions{}, ErrReviewRequired},
		{"review-required path", ci, ApplyOptions{}, ErrReviewRequired},
	} {
		before := fingerprint(t, repo, wt)
		if _, err := dirtyApply(wt, c.patch, c.o); !errors.Is(err, c.is) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.is)
		}
		sameFingerprint(t, before, fingerprint(t, repo, wt))
	}
	rep, err := dirtyApply(wt, ci, ApplyOptions{AllowReviewRequired: true})
	if err != nil || len(rep.Flagged) != 1 || !exists(filepath.Join(wt, ".github", "workflows", "x.yml")) {
		t.Fatalf("control: %+v %v", rep, err)
	}
}

// The target rules: the primary checkout is refused even when clean (decision 10), and a linked worktree with an
// operation in progress or unmerged paths is refused; without AllowDirty a dirty target is still ErrDirty.
func TestApplyDirtyTargetRules(t *testing.T) {
	repo, wt := linkedWorktree(t)
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "a.txt"), "a\n") })
	if _, err := dirtyApply(repo, patch, ApplyOptions{}); !errors.Is(err, ErrDirtyTarget) || !strings.Contains(err.Error(), "primary checkout") {
		t.Fatalf("primary checkout: %v", err)
	}
	if exists(filepath.Join(repo, "a.txt")) {
		t.Fatal("applied to the primary checkout")
	}
	writeFile(t, filepath.Join(wt, "README.md"), "dirty\n")
	if _, err := Apply(context.Background(), wt, bytes.NewReader(patch), ApplyOptions{}); !errors.Is(err, ErrDirty) {
		t.Fatalf("without AllowDirty: %v", err)
	}
	// A conflicting merge in the linked worktree: in progress, then (merge state removed) unmerged paths.
	git(t, wt, "checkout", "-q", "--", "README.md")
	git(t, repo, "checkout", "-q", "-b", "other")
	writeFile(t, filepath.Join(repo, "notes.md"), "other\n")
	commitAll(t, repo, "other")
	writeFile(t, filepath.Join(wt, "notes.md"), "story\n")
	commitAll(t, wt, "story")
	gitMay(wt, "merge", "other")
	if _, err := dirtyApply(wt, patch, ApplyOptions{}); !errors.Is(err, ErrDirtyTarget) || !strings.Contains(err.Error(), "merge in progress") {
		t.Fatalf("merge in progress: %v", err)
	}
	os.Remove(git(t, wt, "rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD"))
	if _, err := dirtyApply(wt, patch, ApplyOptions{}); !errors.Is(err, ErrDirtyTarget) || !strings.Contains(err.Error(), "unmerged") {
		t.Fatalf("unmerged: %v", err)
	}
}

// --snapshot-tree reports divergence without blocking: 0 when the target still has the snapshot's tree, the number
// of changed paths when the snapshot trees are in the store, -1 when they are nowhere to be found.
func TestApplyDirtySnapshotTree(t *testing.T) {
	repo, wt := linkedWorktree(t)
	writeFile(t, filepath.Join(wt, "README.md"), "dirty\n")
	store := t.TempDir()
	s, err := takeSnapshot(context.Background(), wt, SnapshotOptions{}, store)
	s.close()
	if err != nil {
		t.Fatal(err)
	}
	patch := func(name string) []byte {
		return makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, name), "x\n") })
	}
	rep, err := dirtyApply(wt, patch("a.txt"), ApplyOptions{SnapshotTree: s.Tree, SnapshotObjects: store})
	if err != nil || rep.TargetTree != s.Tree || rep.Diverged != 0 {
		t.Fatalf("same tree: %+v %v", rep, err)
	}
	writeFile(t, filepath.Join(wt, "later.txt"), "later\n") // a.txt (applied above) and later.txt diverge
	rep, err = dirtyApply(wt, patch("b.txt"), ApplyOptions{SnapshotTree: s.Tree, SnapshotObjects: store})
	if err != nil || rep.TargetTree == s.Tree || rep.Diverged != 2 {
		t.Fatalf("diverged: %+v %v", rep, err)
	}
	rep, err = dirtyApply(wt, patch("c.txt"), ApplyOptions{SnapshotTree: s.Tree})
	if err != nil || rep.Diverged != -1 || rep.TargetTreeErr != nil {
		t.Fatalf("unknown snapshot tree: %+v %v", rep, err)
	}
	if _, err := dirtyApply(wt, patch("d.txt"), ApplyOptions{SnapshotTree: "not-a-sha"}); err == nil {
		t.Fatal("malformed snapshot tree accepted")
	}
}

// patchEntries reads names and modes from patch headers as git does: spaces, C-quoted names, a mode-only change,
// a binary file, a rename (deletion plus addition) and a copy; a garbage patch is refused.
func TestPatchEntries(t *testing.T) {
	repo, wt := linkedWorktree(t)
	writeFile(t, filepath.Join(repo, "bin.dat"), "\x00\x01")
	writeFile(t, filepath.Join(repo, "run.sh"), "echo\n")
	commitAll(t, repo, "more")
	d := filepath.Join(t.TempDir(), "c")
	git(t, filepath.Dir(d), "clone", "-q", repo, d)
	writeFile(t, filepath.Join(d, "with space.txt"), "s\n")
	writeFile(t, filepath.Join(d, "naïve\ttab.txt"), "q\n")
	writeFile(t, filepath.Join(d, "bin.dat"), "\x00\x02")
	os.Chmod(filepath.Join(d, "run.sh"), 0o755)
	git(t, d, "mv", "notes.md", "docs.md")
	git(t, d, "add", "-A")
	patch := []byte(git(t, d, "diff", "--cached", "--binary", "--full-index", "-M", "HEAD") + "\n")
	got, err := patchEntries(context.Background(), wt, patch)
	if err != nil {
		t.Fatal(err)
	}
	want := []patchEntry{{"bin.dat", "100644", "100644"}, {"docs.md", "000000", "100644"}, {"naïve\ttab.txt", "000000", "100644"},
		{"notes.md", "100644", "000000"}, {"run.sh", "100644", "100755"}, {"with space.txt", "000000", "100644"}}
	if len(got) != len(want) {
		t.Fatalf("entries %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: %q, want %q", i, got[i], want[i])
		}
	}
	// A pure rename of a symlink has no index line; it is still seen (and gated) as a symlink.
	if err := os.Symlink("/etc/passwd", filepath.Join(wt, "link")); err != nil {
		t.Fatal(err)
	}
	ren := []byte("diff --git a/link b/moved\nsimilarity index 100%\nrename from link\nrename to moved\n")
	if got, err := patchEntries(context.Background(), wt, ren); err != nil || len(got) != 2 || got[1].newMode != "120000" {
		t.Fatalf("symlink rename %q %v", got, err)
	}
	if _, err := dirtyApply(wt, ren, ApplyOptions{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("symlink rename not gated: %v", err)
	}
	if _, err := patchEntries(context.Background(), wt, []byte("garbage\n")); err == nil {
		t.Fatal("garbage accepted")
	}
	for _, c := range []struct{ in, want string }{{"a/x b/x", "x"}, {"a/a b b/a b", "a b"}, {"a/x b/y", ""}, {`"a/x\ty" "b/x\ty"`, "x\ty"}} {
		if got := sameNames(c.in); got != c.want {
			t.Errorf("sameNames(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
