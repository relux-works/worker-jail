package workplace

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ApplyOptions tunes Apply.
// WriteScope lists repository-relative path prefixes the patch may touch: an entry ending in "/"
// is a directory, any other entry an exact file. Nil or empty means no restriction.
// PolicyScope, when non-nil, is the write_scope of the producing worker's policy: ["*"] is the whole
// repository and [] refuses every path. With both, a path must be inside both (authority only narrows).
//
// AllowDirty (v2.0) applies into a dirty linked worktree instead of refusing it with ErrDirty: the patch goes to the
// working tree only, never to the index, HEAD or refs. SnapshotTree, with AllowDirty, is the tree the patch was made
// against; when the target's current snapshot tree differs, the report says how many paths diverged (never blocking).
// SnapshotObjects is an extra object dir holding snapshot trees (Workplace.SnapshotStore) for that count.
type ApplyOptions struct {
	AllowReviewRequired bool
	WriteScope          []string
	PolicyScope         *[]string
	AllowDirty          bool
	SnapshotTree        string
	SnapshotObjects     string
}

// inScope reports whether path is inside the task's and the policy's write scopes.
func (o ApplyOptions) inScope(path string) bool {
	if len(o.WriteScope) > 0 && !inWriteScope(o.WriteScope, path) {
		return false
	}
	if o.PolicyScope != nil {
		ps := *o.PolicyScope
		return len(ps) == 1 && ps[0] == "*" || inWriteScope(ps, path)
	}
	return true
}

// Flag is a path that needs explicit review.
type Flag struct{ Path, Reason string }

// ApplyReport lists the paths a patch touches and the ones flagged for review.
// With AllowDirty and SnapshotTree, TargetTree is the target's snapshot tree before the apply and Diverged the number
// of paths that differ from SnapshotTree (-1: not countable, the snapshot tree is unknown here); TargetTreeErr says
// why TargetTree could not be computed. All three are informational.
type ApplyReport struct {
	Paths      []string
	Flagged    []Flag
	OutOfScope []string

	TargetTree    string
	Diverged      int
	TargetTreeErr error
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
// With AllowDirty (v2.0) it applies to the working tree of a dirty linked worktree instead (applyDirty).
// It never runs hooks and never commits.
func Apply(ctx context.Context, repo string, patch io.Reader, o ApplyOptions) (ApplyReport, error) {
	var rep ApplyReport
	data, err := io.ReadAll(io.LimitReader(patch, ExportCap+1))
	if err != nil {
		return rep, fmt.Errorf("workplace: read patch: %w", err)
	}
	if len(data) > ExportCap {
		return rep, fmt.Errorf("workplace: patch exceeds 64 MiB")
	}
	if err := validateWriteScope(o.WriteScope); err != nil {
		return rep, err
	}
	if ps := o.PolicyScope; ps != nil && !(len(*ps) == 1 && (*ps)[0] == "*") {
		if err := validateWriteScope(*ps); err != nil {
			return rep, fmt.Errorf("%w (policy)", err)
		}
	}
	if p := gitPathInHeaders(data); p != "" {
		return rep, fmt.Errorf("%w: %q", ErrGitPath, p)
	}
	out, err := applyGit(ctx, repo, "", nil, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(out) != "true" {
		return rep, fmt.Errorf("workplace: %s is not a git worktree: %v", repo, err)
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
	tmp, err := os.MkdirTemp("", "rwp-apply-")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(tmp)
	idx := filepath.Join(tmp, "index")
	if _, err := applyGit(ctx, repo, idx, nil, "read-tree", "HEAD"); err != nil {
		return rep, err
	}
	if _, err := applyGit(ctx, repo, idx, data, "apply", "--cached", "--whitespace=nowarn", "-"); err != nil {
		return rep, fmt.Errorf("workplace: patch does not apply: %w", err)
	}
	raw, err := applyGit(ctx, repo, idx, nil, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", "HEAD")
	if err != nil {
		return rep, err
	}
	var entries []patchEntry
	f := strings.Split(raw, "\x00")
	for i := 0; i+1 < len(f); i += 2 {
		meta, path := strings.Fields(strings.TrimPrefix(f[i], ":")), f[i+1]
		if len(meta) < 5 {
			return rep, fmt.Errorf("workplace: unparsable diff entry %q", f[i])
		}
		entries = append(entries, patchEntry{path, meta[0], meta[1]})
	}
	if err := gate(&rep, entries, o); err != nil {
		return rep, err
	}
	if _, err := applyGit(ctx, repo, "", data, "apply", "--index", "--whitespace=nowarn", "-"); err != nil {
		return rep, err
	}
	return rep, nil
}

// patchEntry is one path a patch touches, with its old and new modes ("000000" when absent).
type patchEntry struct{ path, oldMode, newMode string }

// gate applies the path gates in their protocol order: .git (hard), write scope (hard), then symlinks, gitlinks and
// review-required paths unless AllowReviewRequired. It fills rep.Paths, rep.OutOfScope and rep.Flagged.
func gate(rep *ApplyReport, entries []patchEntry, o ApplyOptions) error {
	for _, e := range entries {
		path := e.path
		rep.Paths = append(rep.Paths, path)
		if isGitPath(path) {
			return fmt.Errorf("%w: %q", ErrGitPath, path)
		}
		if !o.inScope(path) {
			rep.OutOfScope = append(rep.OutOfScope, path)
		}
		if e.newMode == "120000" {
			rep.Flagged = append(rep.Flagged, Flag{path, "symlink"})
		}
		if e.oldMode == "160000" || e.newMode == "160000" {
			rep.Flagged = append(rep.Flagged, Flag{path, "gitlink"})
		}
		if why, ok := reviewRequired(path); ok {
			rep.Flagged = append(rep.Flagged, Flag{path, why})
		}
	}
	if len(rep.OutOfScope) > 0 {
		return ErrOutOfScope
	}
	if len(rep.Flagged) > 0 && !o.AllowReviewRequired {
		return ErrReviewRequired
	}
	return nil
}

// applyDirty applies a patch into a dirty linked worktree (worktree-seeding.md §4, design-owner decision 10).
// Target rules: a linked worktree (its git dir differs from the common dir), no unmerged paths, no operation in
// progress. The gates run on the patch text, then `git apply --check` and `git apply` against the working tree:
// git apply is all or nothing, so a conflicting hunk or an untracked file in the way refuses the whole patch and
// leaves the tree as it was. The index, HEAD and refs are never written; hooks are disabled.
func applyDirty(ctx context.Context, repo string, data []byte, o ApplyOptions) (ApplyReport, error) {
	rep := ApplyReport{Diverged: -1}
	if o.SnapshotTree != "" && !shaRE.MatchString(o.SnapshotTree) {
		return rep, fmt.Errorf("workplace: invalid snapshot tree %q", o.SnapshotTree)
	}
	si, err := checkSource(ctx, repo, ErrDirtyTarget)
	if err != nil {
		return rep, err
	}
	if si.gitDir == si.commonDir {
		return rep, fmt.Errorf("%w: %s is a primary checkout; use a linked worktree (git worktree add)", ErrDirtyTarget, si.top)
	}
	entries, err := patchEntries(ctx, si.top, data)
	if err != nil {
		return rep, err
	}
	if err := gate(&rep, entries, o); err != nil {
		return rep, err
	}
	if o.SnapshotTree != "" {
		rep.TargetTree, rep.Diverged, rep.TargetTreeErr = divergence(ctx, si.top, o.SnapshotTree, o.SnapshotObjects)
	}
	if _, err := applyGit(ctx, si.top, "", data, "apply", "--check", "--whitespace=nowarn", "-"); err != nil {
		return rep, fmt.Errorf("workplace: patch does not apply: %w", err)
	}
	if _, err := applyGit(ctx, si.top, "", data, "apply", "--whitespace=nowarn", "-"); err != nil {
		return rep, err
	}
	return rep, nil
}

// divergence computes the target's current snapshot tree in a temporary repository (discarded) and counts the paths
// that differ from want. The count needs want's trees: in the target's objects or in store; otherwise it is -1.
func divergence(ctx context.Context, top, want, store string) (string, int, error) {
	s, err := takeSnapshot(ctx, top, SnapshotOptions{}, "", store)
	defer s.close()
	if err != nil {
		return "", -1, err
	}
	if s.Tree == want {
		return s.Tree, 0, nil
	}
	out, err := s.git(ctx, nil, "", "diff-tree", "-r", "-z", "--name-only", "--no-renames", want, s.Tree)
	if err != nil {
		return s.Tree, -1, nil
	}
	n := 0
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			n++
		}
	}
	return s.Tree, n, nil
}

// validateWriteScope rejects empty, absolute and non-canonical entries and entries naming .git.
func validateWriteScope(scope []string) error {
	for _, e := range scope {
		comps := strings.Split(strings.TrimSuffix(e, "/"), "/")
		if e == "" || strings.HasPrefix(e, "/") {
			return fmt.Errorf("workplace: invalid write-scope entry %q", e)
		}
		for _, c := range comps {
			if c == "" || c == "." || c == ".." || strings.EqualFold(c, ".git") {
				return fmt.Errorf("workplace: invalid write-scope entry %q", e)
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

// patchEntries reads the paths and modes a patch touches from its text: the file headers (`diff --git`, mode,
// rename and copy lines, `---`/`+++`). A rename is a deletion and an addition, as in v1's --no-renames diff. Each
// file's resulting name (the new one, or the old one for a deletion) is cross-checked against git's own parse
// (`git apply --numstat`); any difference refuses the patch.
func patchEntries(ctx context.Context, top string, data []byte) ([]patchEntry, error) {
	type block struct {
		gitLine, oldName, newName, oldMode, newMode string
		renameFrom, renameTo, copyFrom, copyTo      string
		created, deleted                            bool
	}
	var blocks []*block
	var b *block
	inHeader := false
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "diff --git "); ok {
			b = &block{gitLine: rest}
			blocks, inHeader = append(blocks, b), true
			continue
		}
		if b == nil || !inHeader {
			continue
		}
		f := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "@@"), strings.HasPrefix(line, "GIT binary patch"), strings.HasPrefix(line, "Binary files "):
			inHeader = false
		case strings.HasPrefix(line, "old mode ") && len(f) == 3:
			b.oldMode = f[2]
		case strings.HasPrefix(line, "new mode ") && len(f) == 3:
			b.newMode = f[2]
		case strings.HasPrefix(line, "deleted file mode ") && len(f) == 4:
			b.oldMode, b.newMode, b.deleted = f[3], "000000", true
		case strings.HasPrefix(line, "new file mode ") && len(f) == 4:
			b.oldMode, b.newMode, b.created = "000000", f[3], true
		case strings.HasPrefix(line, "index ") && len(f) == 3:
			b.oldMode, b.newMode = f[2], f[2]
		case strings.HasPrefix(line, "rename from "):
			b.renameFrom = headerName(strings.TrimPrefix(line, "rename from "), "")
		case strings.HasPrefix(line, "rename to "):
			b.renameTo = headerName(strings.TrimPrefix(line, "rename to "), "")
		case strings.HasPrefix(line, "copy from "):
			b.copyFrom = headerName(strings.TrimPrefix(line, "copy from "), "")
		case strings.HasPrefix(line, "copy to "):
			b.copyTo = headerName(strings.TrimPrefix(line, "copy to "), "")
		case strings.HasPrefix(line, "--- "):
			b.oldName = headerName(strings.TrimPrefix(line, "--- "), "a/")
		case strings.HasPrefix(line, "+++ "):
			b.newName = headerName(strings.TrimPrefix(line, "+++ "), "b/")
		}
	}
	var entries []patchEntry
	mine := map[string]bool{}
	for _, b := range blocks {
		if from := b.renameFrom + b.copyFrom; from != "" && b.oldMode == "" && b.newMode == "" {
			// A pure rename or copy has no index line: git apply takes the mode of the file it reads, so do we.
			b.oldMode = worktreeMode(filepath.Join(top, filepath.FromSlash(from)))
			b.newMode = b.oldMode
		}
		name := b.newName
		if name == "" || name == "/dev/null" {
			name = b.oldName
		}
		if name == "" || name == "/dev/null" {
			name = sameNames(b.gitLine)
		}
		switch {
		case b.renameFrom != "" && b.renameTo != "":
			entries = append(entries, patchEntry{b.renameFrom, b.oldMode, "000000"}, patchEntry{b.renameTo, "000000", b.newMode})
			mine[b.renameTo] = true
		case b.copyFrom != "" && b.copyTo != "":
			entries = append(entries, patchEntry{b.copyTo, "000000", b.newMode})
			mine[b.copyTo] = true
		case name == "":
			return nil, fmt.Errorf("workplace: cannot read the file names of patch header %q", b.gitLine)
		default:
			entries = append(entries, patchEntry{name, b.oldMode, b.newMode})
			mine[name] = true
		}
	}
	out, err := applyGit(ctx, top, "", data, "apply", "--numstat", "-z", "-")
	if err != nil {
		return nil, fmt.Errorf("workplace: patch does not parse: %w", err)
	}
	theirs := map[string]bool{}
	for _, rec := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
		if f := strings.SplitN(rec, "\t", 3); len(f) == 3 && f[2] != "" { // added, deleted, name
			theirs[f[2]] = true
		} else {
			return nil, fmt.Errorf("workplace: unexpected numstat record %q", rec)
		}
	}
	if !maps.Equal(mine, theirs) {
		return nil, fmt.Errorf("workplace: patch file names are ambiguous (headers %v, git %v)", slices.Sorted(maps.Keys(mine)), slices.Sorted(maps.Keys(theirs)))
	}
	slices.SortFunc(entries, func(a, b patchEntry) int { return strings.Compare(a.path, b.path) })
	return entries, nil
}

// worktreeMode returns the git mode of a worktree path ("" if it does not exist; git apply then fails).
func worktreeMode(p string) string {
	fi, err := os.Lstat(p)
	switch {
	case err != nil:
		return ""
	case fi.Mode()&os.ModeSymlink != 0:
		return "120000"
	case fi.IsDir():
		return "160000"
	case fi.Mode()&0o111 != 0:
		return "100755"
	}
	return "100644"
}

// headerName decodes a file name of a patch header: C-quoted or plain, without the trailing tab git adds to names
// with spaces, and without prefix ("a/" or "b/"). "/dev/null" stays as it is.
func headerName(s, prefix string) string {
	s = strings.TrimSuffix(s, "\t")
	if strings.HasPrefix(s, `"`) {
		u, err := strconv.Unquote(s)
		if err != nil {
			return ""
		}
		s = u
	}
	if s == "/dev/null" {
		return s
	}
	return strings.TrimPrefix(s, prefix)
}

// sameNames returns the name of a `diff --git a/X b/X` line whose two names are equal (a mode-only or binary
// change has no ---/+++ lines), or "".
func sameNames(rest string) string {
	if strings.HasPrefix(rest, `"`) {
		q, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return ""
		}
		a, b := headerName(q, "a/"), headerName(strings.TrimPrefix(rest[len(q):], " "), "b/")
		if a == b {
			return a
		}
		return ""
	}
	n := (len(rest) - len("a/ b/")) / 2
	if n <= 0 || !strings.HasPrefix(rest, "a/") || rest[2+n:2+n+3] != " b/" || rest[2:2+n] != rest[5+n:] {
		return ""
	}
	return rest[2 : 2+n]
}
