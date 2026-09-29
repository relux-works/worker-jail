package jail

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// snapGit runs git against the snapshot's seed repository.
func snapGit(t *testing.T, s *snapshot, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = append(hostEnv(), "GIT_DIR="+s.seed.gitDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// snapFiles lists the snapshot tree's paths.
func snapFiles(t *testing.T, s *snapshot) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(snapGit(t, s, "ls-tree", "-r", "--name-only", s.Snap), "\n") {
		m[p] = true
	}
	return m
}

// dirtyRepo returns a repo with a modified tracked file, a staged new file, an untracked file,
// a gitignored file and an info/exclude'd file.
func dirtyRepo(t *testing.T) string {
	repo := newRepo(t)
	writeFile(t, filepath.Join(repo, ".gitignore"), "ignored.txt\n")
	git(t, repo, "add", ".gitignore")
	git(t, repo, "commit", "-q", "-m", "ignore")
	writeFile(t, filepath.Join(repo, "README.md"), "modified\n")
	writeFile(t, filepath.Join(repo, "staged.txt"), "staged\n")
	git(t, repo, "add", "staged.txt")
	writeFile(t, filepath.Join(repo, "untracked.txt"), "untracked\n")
	writeFile(t, filepath.Join(repo, "ignored.txt"), "ignored\n")
	writeFile(t, filepath.Join(repo, ".git", "info", "exclude"), "excluded.txt\n")
	writeFile(t, filepath.Join(repo, "excluded.txt"), "excluded\n")
	return repo
}

// repoState captures what a snapshot must not change: index bytes, refs, object counts and status.
func repoState(t *testing.T, repo string) string {
	idx, err := os.ReadFile(filepath.Join(repo, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	return string(idx) + "\x00" + git(t, repo, "for-each-ref") + "\x00" + git(t, repo, "count-objects", "-v") +
		"\x00" + git(t, repo, "status", "--porcelain")
}

// The snapshot holds modified, staged and untracked files, excludes ignored and info/exclude'd ones,
// and is a child of HEAD.
func TestSnapshotContent(t *testing.T) {
	repo := dirtyRepo(t)
	s, err := snapshotWorktree(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Cleanup()
	f := snapFiles(t, s)
	if !f["README.md"] || !f["staged.txt"] || !f["untracked.txt"] || f["ignored.txt"] || f["excluded.txt"] {
		t.Fatalf("snapshot files %v", f)
	}
	if got := snapGit(t, s, "show", s.Snap+":README.md"); got != "modified" {
		t.Fatalf("README in snapshot %q", got)
	}
	if s.Head != git(t, repo, "rev-parse", "HEAD") || snapGit(t, s, "rev-parse", s.Snap+"^") != s.Head {
		t.Fatalf("snapshot parent must be HEAD")
	}
	dir := s.seed.dir
	s.Cleanup()
	if exists(dir) {
		t.Fatal("cleanup left the seed dir")
	}
}

// A snapshot leaves the source repository's index, refs, objects and status byte-identical.
func TestSnapshotIsolation(t *testing.T) {
	repo := dirtyRepo(t)
	before := repoState(t, repo)
	s, err := snapshotWorktree(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	s.Cleanup()
	if repoState(t, repo) != before {
		t.Fatal("snapshot changed the source repo")
	}
}

// Snapshot succeeds under commit.gpgsign=true with an unusable key; control: a commit honoring that
// config fails there. git 2.53's commit-tree no longer reads commit.gpgsign, so the control uses
// `git commit`; --no-gpg-sign stays as the guard for gits that do.
func TestSnapshotIgnoresSigningConfig(t *testing.T) {
	repo := dirtyRepo(t)
	git(t, repo, "config", "commit.gpgsign", "true")
	git(t, repo, "config", "gpg.format", "ssh")
	git(t, repo, "config", "user.signingkey", "/nonexistent/wj-bogus-key")
	s, err := snapshotWorktree(context.Background(), repo)
	if err != nil {
		t.Fatalf("snapshot with signing config: %v", err)
	}
	s.Cleanup()
	cmd := exec.Command("git", "-C", repo, "commit", "-q", "--allow-empty", "-m", "x")
	cmd.Env = append(hostEnv(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("control: signing commit succeeded: %s", out)
	}
}

// Untracked secret-like files are refused by name; ignored ones and tracked .env.example are allowed.
func TestSnapshotSecretGuard(t *testing.T) {
	for _, name := range []string{".env", "id_ed25519", "sub/Server.PEM", "credentials-prod.json"} {
		repo := newRepo(t)
		writeFile(t, filepath.Join(repo, name), "secret\n")
		before := repoState(t, repo)
		_, err := snapshotWorktree(context.Background(), repo)
		if !errors.Is(err, ErrSecretLike) || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: err %v", name, err)
		}
		if repoState(t, repo) != before {
			t.Fatalf("%s: refused snapshot changed the repo", name)
		}
		// Control: the same file gitignored is allowed and absent.
		writeFile(t, filepath.Join(repo, ".gitignore"), name+"\n")
		s, err := snapshotWorktree(context.Background(), repo)
		if err != nil {
			t.Fatalf("%s ignored: %v", name, err)
		}
		if snapFiles(t, s)[name] {
			t.Fatalf("%s ignored but snapshotted", name)
		}
		s.Cleanup()
	}
	repo := newRepo(t)
	writeFile(t, filepath.Join(repo, ".env.example"), "A=\n")
	git(t, repo, "add", ".env.example")
	git(t, repo, "commit", "-q", "-m", "example")
	writeFile(t, filepath.Join(repo, ".env.example"), "A=1\n")
	s, err := snapshotWorktree(context.Background(), repo)
	if err != nil {
		t.Fatalf("tracked .env.example: %v", err)
	}
	s.Cleanup()
	if secretLike("envelope.go") || secretLike("keys.go") || !secretLike("a/.ENV.local") {
		t.Fatal("secretLike table wrong")
	}
}
