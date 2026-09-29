package jail

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// secretPatterns are basename globs, matched case-insensitively, that an untracked file must not match
// before it is hashed into a snapshot or a dirty-apply index.
var secretPatterns = []string{".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*",
	"id_ecdsa*", ".netrc", ".npmrc", ".pypirc", "credentials*.json"}

func secretLike(p string) bool {
	b := strings.ToLower(path.Base(p))
	for _, pat := range secretPatterns {
		if ok, _ := path.Match(pat, b); ok {
			return true
		}
	}
	return false
}

// seedRepo is a temporary bare repository borrowing a host repository's objects, with its own index
// over the host worktree. Nothing it does writes under the host repository.
type seedRepo struct {
	dir, gitDir, index, top, head string
}

// newSeed builds a seed repository whose index holds repo's working tree (HEAD plus staged, unstaged and
// untracked non-ignored files). It refuses secret-like untracked files before hashing anything.
func newSeed(ctx context.Context, repo string) (_ *seedRepo, err error) {
	top, err := hostGit(ctx, repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	common, err := hostGit(ctx, repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return nil, err
	}
	exclude, err := hostGit(ctx, repo, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude")
	if err != nil {
		return nil, err
	}
	head, err := hostGit(ctx, repo, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return nil, err
	}
	out, err := hostGit(ctx, repo, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" && secretLike(p) {
			bad = append(bad, p)
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrSecretLike, strings.Join(bad, ", "))
	}
	dir, err := os.MkdirTemp("", "wj-seed-")
	if err != nil {
		return nil, err
	}
	s := &seedRepo{dir: dir, gitDir: filepath.Join(dir, "seed.git"), index: filepath.Join(dir, "index"), top: top, head: head}
	defer func() {
		if err != nil {
			s.cleanup()
		}
	}()
	if _, err = hostGit(ctx, dir, "init", "-q", "--bare", s.gitDir); err != nil {
		return nil, err
	}
	alt := filepath.Join(s.gitDir, "objects", "info", "alternates")
	if err = os.WriteFile(alt, []byte(filepath.Join(common, "objects")+"\n"), 0o644); err != nil {
		return nil, err
	}
	if ex, rerr := os.ReadFile(exclude); rerr == nil {
		if err = os.MkdirAll(filepath.Join(s.gitDir, "info"), 0o755); err != nil {
			return nil, err
		}
		if err = os.WriteFile(filepath.Join(s.gitDir, "info", "exclude"), ex, 0o644); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(rerr) {
		return nil, rerr
	}
	if _, err = s.git(ctx, nil, nil, "read-tree", head); err != nil {
		return nil, err
	}
	if _, err = s.git(ctx, nil, nil, "add", "-A"); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *seedRepo) env(extra ...string) []string {
	return append(hostEnv(), append([]string{"GIT_DIR=" + s.gitDir, "GIT_WORK_TREE=" + s.top,
		"GIT_INDEX_FILE=" + s.index}, extra...)...)
}

func (s *seedRepo) git(ctx context.Context, stdin []byte, extraEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env, cmd.Dir = s.env(extraEnv...), s.top
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", &cmdError{"git " + strings.Join(args, " "), err, errb.Bytes()}
	}
	return out.String(), nil
}

func (s *seedRepo) cleanup() { os.RemoveAll(s.dir) }

// snapshot is a commit of a host working tree held in a temporary seed repository.
type snapshot struct {
	seed       *seedRepo
	Snap, Head string
}

// Cleanup removes the seed repository; call it after every stream from it has been consumed.
func (s *snapshot) Cleanup() { s.seed.cleanup() }

// snapshotWorktree commits repo's working tree into a temporary seed repository as refs/heads/snapshot.
// It never modifies anything under repo.
func snapshotWorktree(ctx context.Context, repo string) (*snapshot, error) {
	s, err := newSeed(ctx, repo)
	if err != nil {
		return nil, err
	}
	tree, err := s.git(ctx, nil, nil, "write-tree")
	if err != nil {
		s.cleanup()
		return nil, err
	}
	id := []string{"GIT_AUTHOR_NAME=worker-jail", "GIT_AUTHOR_EMAIL=snapshot@worker-jail.invalid",
		"GIT_COMMITTER_NAME=worker-jail", "GIT_COMMITTER_EMAIL=snapshot@worker-jail.invalid"}
	snap, err := s.git(ctx, nil, id, "commit-tree", "--no-gpg-sign", "-p", s.head,
		"-m", "worker-jail snapshot of "+s.top, strings.TrimSpace(tree))
	if err != nil {
		s.cleanup()
		return nil, err
	}
	snap = strings.TrimSpace(snap)
	if _, err := s.git(ctx, nil, nil, "update-ref", "refs/heads/snapshot", snap); err != nil {
		s.cleanup()
		return nil, err
	}
	return &snapshot{seed: s, Snap: snap, Head: s.head}, nil
}
