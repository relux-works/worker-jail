package jail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func applyDirtyBytes(repo string, patch []byte, o ApplyOptions) (ApplyReport, error) {
	o.AllowDirty = true
	return Apply(context.Background(), repo, bytes.NewReader(patch), o)
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// worktreeState is the index bytes plus every non-.git file's content.
func worktreeState(t *testing.T, repo string) string {
	var b bytes.Buffer
	b.WriteString(readFile(t, filepath.Join(repo, ".git", "index")))
	filepath.Walk(repo, func(p string, fi os.FileInfo, err error) error {
		if fi.IsDir() && fi.Name() == ".git" {
			return filepath.SkipDir
		}
		if fi.Mode().IsRegular() {
			b.WriteString("\x00" + p + "\x00" + readFile(t, p))
		}
		return nil
	})
	return b.String()
}

// Under AllowDirty an unrelated dirty state stays intact, the patch lands in the worktree only and the
// index is byte-identical.
func TestApplyDirtyUnrelated(t *testing.T) {
	repo := dirtyRepo(t)
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "jail", "x.go"), "package jail\n") })
	idx := readFile(t, filepath.Join(repo, ".git", "index"))
	rep, err := applyDirtyBytes(repo, patch, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Paths) != 1 || rep.Paths[0] != "jail/x.go" || readFile(t, filepath.Join(repo, "jail", "x.go")) != "package jail\n" {
		t.Fatalf("report %+v", rep)
	}
	if readFile(t, filepath.Join(repo, ".git", "index")) != idx {
		t.Fatal("index changed")
	}
	if readFile(t, filepath.Join(repo, "README.md")) != "modified\n" || readFile(t, filepath.Join(repo, "untracked.txt")) != "untracked\n" ||
		readFile(t, filepath.Join(repo, "staged.txt")) != "staged\n" {
		t.Fatal("dirty state lost")
	}
}

// A patch conflicting with a dirty hunk, or creating a file that exists untracked, is refused whole and
// the tree is unchanged; control: the same patch applies to the clean repo.
func TestApplyDirtyConflicts(t *testing.T) {
	for name, dirty := range map[string]func(repo string){
		"dirty hunk":       func(r string) { writeFile(t, filepath.Join(r, "README.md"), "mine\n") },
		"untracked exists": func(r string) { writeFile(t, filepath.Join(r, "new.txt"), "mine\n") },
	} {
		repo := newRepo(t)
		patch := makePatch(t, repo, func(d string) {
			writeFile(t, filepath.Join(d, "README.md"), "theirs\n")
			writeFile(t, filepath.Join(d, "new.txt"), "theirs\n")
			writeFile(t, filepath.Join(d, "other.txt"), "theirs\n")
		})
		clean := filepath.Join(t.TempDir(), "clean")
		git(t, filepath.Dir(clean), "clone", "-q", repo, clean)
		if _, err := applyDirtyBytes(clean, patch, ApplyOptions{}); err != nil {
			t.Fatalf("%s control: %v", name, err)
		}
		dirty(repo)
		before := worktreeState(t, repo)
		if _, err := applyDirtyBytes(repo, patch, ApplyOptions{}); err == nil {
			t.Fatalf("%s: applied", name)
		}
		if worktreeState(t, repo) != before {
			t.Fatalf("%s: tree changed", name)
		}
	}
}

// Under AllowDirty the .git, write-scope, review-required and symlink gates still fire and write nothing;
// control: allowed options pass the soft gates.
func TestApplyDirtyGates(t *testing.T) {
	repo := dirtyRepo(t)
	if _, err := applyDirtyBytes(repo, []byte(gitHookPatch), ApplyOptions{AllowReviewRequired: true}); !errors.Is(err, ErrGitPath) {
		t.Fatalf(".git: %v", err)
	}
	wf := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, ".github", "workflows", "x.yml"), "on: push\n") })
	link := makePatch(t, repo, func(d string) {
		if err := os.Symlink("/etc/passwd", filepath.Join(d, "link")); err != nil {
			t.Fatal(err)
		}
	})
	before := worktreeState(t, repo)
	if _, err := applyDirtyBytes(repo, wf, ApplyOptions{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("review: %v", err)
	}
	if _, err := applyDirtyBytes(repo, link, ApplyOptions{}); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := applyDirtyBytes(repo, wf, ApplyOptions{AllowReviewRequired: true, WriteScope: []string{"jail/"}}); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("scope: %v", err)
	}
	if worktreeState(t, repo) != before {
		t.Fatal("refused patches changed the tree")
	}
	if _, err := applyDirtyBytes(repo, wf, ApplyOptions{AllowReviewRequired: true, WriteScope: []string{".github/"}}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// Without AllowDirty a dirty target is still ErrDirty.
func TestApplyDirtyNeedsFlag(t *testing.T) {
	repo := dirtyRepo(t)
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "x.txt"), "x\n") })
	if _, err := Apply(context.Background(), repo, bytes.NewReader(patch), ApplyOptions{}); !errors.Is(err, ErrDirty) {
		t.Fatalf("err %v", err)
	}
	if exists(filepath.Join(repo, "x.txt")) {
		t.Fatal("written")
	}
}

// Under AllowDirty an untracked secret-like file is refused before hashing; control: gitignored, it applies.
func TestApplyDirtySecret(t *testing.T) {
	repo := dirtyRepo(t)
	patch := makePatch(t, repo, func(d string) { writeFile(t, filepath.Join(d, "x.txt"), "x\n") })
	writeFile(t, filepath.Join(repo, ".env"), "TOKEN=1\n")
	if _, err := applyDirtyBytes(repo, patch, ApplyOptions{}); !errors.Is(err, ErrSecretLike) || exists(filepath.Join(repo, "x.txt")) {
		t.Fatalf("err %v", err)
	}
	writeFile(t, filepath.Join(repo, ".gitignore"), "ignored.txt\n.env\n")
	if _, err := applyDirtyBytes(repo, patch, ApplyOptions{}); err != nil {
		t.Fatalf("control: %v", err)
	}
}
