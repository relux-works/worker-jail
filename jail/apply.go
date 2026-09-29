package jail

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ApplyOptions tunes Apply.
// WriteScope lists repository-relative path prefixes the patch may touch: an entry ending in "/"
// is a directory, any other entry an exact file. Nil or empty means no restriction.
type ApplyOptions struct {
	AllowReviewRequired bool
	WriteScope          []string
	// AllowDirty permits a dirty target: the patch is checked against its current working tree and
	// applied to the working tree only, never to its index.
	AllowDirty bool
}

// Flag is a path that needs explicit review.
type Flag struct{ Path, Reason string }

// ApplyReport lists the paths a patch touches and the ones flagged for review.
type ApplyReport struct {
	Paths      []string
	Flagged    []Flag
	OutOfScope []string
}

func applyGit(ctx context.Context, repo, index string, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo, "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = hostEnv()
	if index != "" {
		cmd.Env = append(cmd.Env, "GIT_INDEX_FILE="+index)
	}
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

// Apply checks a worker patch in a temporary index and applies it to repo's worktree and index.
// It never runs hooks and never commits.
func Apply(ctx context.Context, repo string, patch io.Reader, o ApplyOptions) (ApplyReport, error) {
	var rep ApplyReport
	data, err := io.ReadAll(io.LimitReader(patch, ExportCap+1))
	if err != nil {
		return rep, fmt.Errorf("jail: read patch: %w", err)
	}
	if len(data) > ExportCap {
		return rep, fmt.Errorf("jail: patch exceeds 64 MiB")
	}
	if err := validateWriteScope(o.WriteScope); err != nil {
		return rep, err
	}
	if p := gitPathInHeaders(data); p != "" {
		return rep, fmt.Errorf("%w: %q", ErrGitPath, p)
	}
	out, err := applyGit(ctx, repo, "", nil, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(out) != "true" {
		return rep, fmt.Errorf("jail: %s is not a git worktree: %v", repo, err)
	}
	if o.AllowDirty {
		return applyDirty(ctx, repo, data, o)
	}
	out, err = applyGit(ctx, repo, "", nil, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return rep, err
	}
	if out != "" {
		return rep, fmt.Errorf("%w: %s", ErrDirty, repo)
	}
	tmp, err := os.MkdirTemp("", "wj-apply-")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(tmp)
	idx := filepath.Join(tmp, "index")
	if _, err := applyGit(ctx, repo, idx, nil, "read-tree", "HEAD"); err != nil {
		return rep, err
	}
	if _, err := applyGit(ctx, repo, idx, data, "apply", "--cached", "--whitespace=nowarn", "-"); err != nil {
		return rep, fmt.Errorf("jail: patch does not apply: %w", err)
	}
	raw, err := applyGit(ctx, repo, idx, nil, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", "HEAD")
	if err != nil {
		return rep, err
	}
	if rep, err = checkRaw(raw, o); err != nil {
		return rep, err
	}
	if _, err := applyGit(ctx, repo, "", data, "apply", "--index", "--whitespace=nowarn", "-"); err != nil {
		return rep, err
	}
	return rep, nil
}

// applyDirty checks the patch against a temporary index of repo's current working tree, then applies it
// to the working tree only.
func applyDirty(ctx context.Context, repo string, data []byte, o ApplyOptions) (ApplyReport, error) {
	var rep ApplyReport
	s, err := newSeed(ctx, repo)
	if err != nil {
		return rep, err
	}
	defer s.cleanup()
	pre, err := s.git(ctx, nil, nil, "write-tree")
	if err != nil {
		return rep, err
	}
	if _, err := s.git(ctx, data, nil, "apply", "--cached", "--whitespace=nowarn", "-"); err != nil {
		return rep, fmt.Errorf("jail: patch does not apply: %w", err)
	}
	raw, err := s.git(ctx, nil, nil, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", strings.TrimSpace(pre))
	if err != nil {
		return rep, err
	}
	if rep, err = checkRaw(raw, o); err != nil {
		return rep, err
	}
	if _, err := applyGit(ctx, repo, "", data, "apply", "--whitespace=nowarn", "-"); err != nil {
		return rep, err
	}
	return rep, nil
}

// checkRaw parses `git diff --raw -z` output and runs the path gates: .git and write scope (hard), then
// symlinks, gitlinks and review-required paths unless allowed.
func checkRaw(raw string, o ApplyOptions) (ApplyReport, error) {
	var rep ApplyReport
	f := strings.Split(raw, "\x00")
	for i := 0; i+1 < len(f); i += 2 {
		meta, path := strings.Fields(strings.TrimPrefix(f[i], ":")), f[i+1]
		if len(meta) < 5 {
			return rep, fmt.Errorf("jail: unparsable diff entry %q", f[i])
		}
		rep.Paths = append(rep.Paths, path)
		if isGitPath(path) {
			return rep, fmt.Errorf("%w: %q", ErrGitPath, path)
		}
		if len(o.WriteScope) > 0 && !inWriteScope(o.WriteScope, path) {
			rep.OutOfScope = append(rep.OutOfScope, path)
		}
		if meta[1] == "120000" {
			rep.Flagged = append(rep.Flagged, Flag{path, "symlink"})
		}
		if meta[0] == "160000" || meta[1] == "160000" {
			rep.Flagged = append(rep.Flagged, Flag{path, "gitlink"})
		}
		if why, ok := reviewRequired(path); ok {
			rep.Flagged = append(rep.Flagged, Flag{path, why})
		}
	}
	if len(rep.OutOfScope) > 0 {
		return rep, ErrOutOfScope
	}
	if len(rep.Flagged) > 0 && !o.AllowReviewRequired {
		return rep, ErrReviewRequired
	}
	return rep, nil
}

// validateWriteScope rejects empty, absolute and non-canonical entries and entries naming .git.
func validateWriteScope(scope []string) error {
	for _, e := range scope {
		comps := strings.Split(strings.TrimSuffix(e, "/"), "/")
		if e == "" || strings.HasPrefix(e, "/") {
			return fmt.Errorf("jail: invalid write-scope entry %q", e)
		}
		for _, c := range comps {
			if c == "" || c == "." || c == ".." || strings.EqualFold(c, ".git") {
				return fmt.Errorf("jail: invalid write-scope entry %q", e)
			}
		}
	}
	return nil
}

// inWriteScope reports whether path matches a scope entry, case-insensitively.
func inWriteScope(scope []string, path string) bool {
	for _, e := range scope {
		if strings.HasSuffix(e, "/") {
			if len(path) > len(e) && strings.EqualFold(path[:len(e)], e) {
				return true
			}
		} else if strings.EqualFold(path, e) {
			return true
		}
	}
	return false
}

// gitPathInHeaders scans the patch's file headers (from a `diff --git ` line to the first `@@` or
// `GIT binary patch` line) for a .git component before git parses it, so such a patch fails as ErrGitPath.
// Hunk content is never inspected. The raw-diff check below stays authoritative.
func gitPathInHeaders(patch []byte) string {
	inHeader := false
	for _, line := range strings.Split(string(patch), "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			inHeader = true
		case strings.HasPrefix(line, "@@"), strings.HasPrefix(line, "GIT binary patch"):
			inHeader = false
		}
		if !inHeader {
			continue
		}
		for _, f := range strings.Fields(line) {
			f = strings.Trim(f, `"`)
			if isGitPath(strings.TrimPrefix(strings.TrimPrefix(f, "a/"), "b/")) {
				return f
			}
		}
	}
	return ""
}

// hostEnv is the host environment without GIT_* variables, so no inherited GIT_DIR,
// GIT_INDEX_FILE or similar can redirect a host git or go command.
func hostEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	return env
}

func isGitPath(path string) bool {
	for _, c := range strings.Split(path, "/") {
		if strings.EqualFold(strings.TrimRight(c, ". "), ".git") {
			return true
		}
	}
	return false
}

var reviewDirs = map[string]bool{".github": true, ".circleci": true, ".githooks": true, ".husky": true,
	".vscode": true, ".claude": true, ".codex": true, ".agents": true}

var reviewFiles = map[string]bool{".gitattributes": true, ".gitmodules": true, ".gitlab-ci.yml": true,
	".pre-commit-config.yaml": true, "lefthook.yml": true, "lefthook.yaml": true, ".envrc": true,
	"agents.md": true, "claude.md": true, ".mcp.json": true}

// reviewRequired reports whether path must be reviewed before it is applied, and why.
func reviewRequired(path string) (string, bool) {
	comps := strings.Split(strings.ToLower(path), "/")
	for _, c := range comps {
		if reviewDirs[c] {
			return "review-required directory " + c, true
		}
	}
	if b := comps[len(comps)-1]; reviewFiles[b] {
		return "review-required file " + b, true
	}
	return "", false
}
