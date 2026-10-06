package jail

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Snapshot limits (docs/design/v2/worktree-seeding.md §1, §2).
const (
	MaxUntrackedFile       = 10 << 20 // one untracked file
	DefaultMaxUntrackedMiB = 256      // all untracked files together, unless SnapshotOptions raises it
	secretScanMax          = 1 << 20  // the content rule reads files of the delta up to this size
	snapshotRef            = "refs/heads/snapshot"
	snapshotDate           = "946684800 +0000" // 2000-01-01T00:00:00Z
)

// SnapshotOptions tunes a worktree snapshot (provision and seed-gomod --from-worktree).
// AllowSecretPaths lists exact repository paths the name rule of the secret guard lets through;
// the content rule has no override, and Provision refuses any override for a HIGH or CRITICAL policy.
type SnapshotOptions struct {
	MaxUntrackedMiB  int // 0: DefaultMaxUntrackedMiB
	AllowSecretPaths []string
}

// snapshotGit is the fixed config of every git call against a snapshot's temporary repository:
// no hooks, no fsmonitor, no untracked cache, no global attributes, no automatic gc, pathspecs taken literally.
var snapshotGit = []string{"--literal-pathspecs", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
	"-c", "core.untrackedCache=false", "-c", "core.attributesFile=/dev/null", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
	"-c", "commit.gpgsign=false"}

// sourceGit is the fixed config of the read-only git calls against the source worktree.
var sourceGit = []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"}

// snapshot is a worktree's state captured in a temporary bare repository whose alternates name the source's
// object dir. The source is only read: add and write-tree write to tmp/objects, which has no alternates, so
// git cannot even freshen (touch) an existing source object.
type snapshot struct {
	top, tmp, gitDir, objects string
	Parent, Tree, Commit      string
}

// srcGit runs a read-only git command in the source worktree and returns its raw stdout.
// GIT_CONFIG_GLOBAL is passed through so the owner's global excludes apply to the untracked list.
func srcGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append(append([]string{"-C", dir}, sourceGit...), args...)...)
	cmd.Env = hostEnv()
	if g, ok := os.LookupEnv("GIT_CONFIG_GLOBAL"); ok {
		cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL="+g)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &limitBuffer{buf: &errb, max: 1 << 20}
	if err := cmd.Run(); err != nil {
		return "", &cmdError{"git " + strings.Join(args, " "), err, errb.Bytes()}
	}
	return out.String(), nil
}

// env is the environment of a git call against the temporary repository: an empty config and, for the
// steps that write objects, objDir as the object dir (without alternates).
func (s *snapshot) env(objDir string) []string {
	env := append(hostEnv(), "GIT_DIR="+s.gitDir, "GIT_WORK_TREE="+s.top, "GIT_INDEX_FILE="+filepath.Join(s.tmp, "index"),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=worker-jail", "GIT_AUTHOR_EMAIL=snapshot@worker-jail.invalid", "GIT_AUTHOR_DATE="+snapshotDate,
		"GIT_COMMITTER_NAME=worker-jail", "GIT_COMMITTER_EMAIL=snapshot@worker-jail.invalid", "GIT_COMMITTER_DATE="+snapshotDate)
	if objDir != "" {
		env = append(env, "GIT_OBJECT_DIRECTORY="+objDir)
	}
	return env
}

func (s *snapshot) cmd(ctx context.Context, objDir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", append(append([]string{}, snapshotGit...), args...)...)
	cmd.Dir, cmd.Env = s.tmp, s.env(objDir)
	return cmd
}

// git runs a git command against the temporary repository and returns its raw stdout.
func (s *snapshot) git(ctx context.Context, stdin []byte, objDir string, args ...string) (string, error) {
	cmd := s.cmd(ctx, objDir, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &limitBuffer{buf: &errb, max: 1 << 20}
	if err := cmd.Run(); err != nil {
		return "", &cmdError{"git " + strings.Join(args, " "), err, errb.Bytes()}
	}
	return out.String(), nil
}

func (s *snapshot) close() {
	if s != nil && s.tmp != "" {
		os.RemoveAll(s.tmp)
	}
}

// inProgress maps git-dir entries to the operation they reveal.
var inProgress = []struct{ path, op string }{
	{"MERGE_HEAD", "a merge"}, {"rebase-merge", "a rebase"}, {"rebase-apply", "a rebase or am"},
	{"CHERRY_PICK_HEAD", "a cherry-pick"}, {"REVERT_HEAD", "a revert"}, {"sequencer", "a cherry-pick or revert sequence"},
	{"BISECT_LOG", "a bisect"},
}

// sourceInfo is what checkSource learns about a worktree: absolute paths and HEAD.
type sourceInfo struct {
	top, head, objects, exclude, gitDir, commonDir string
}

// checkSource resolves dir's top level and HEAD and refuses, wrapped in refusal, the states a snapshot or a dirty
// apply cannot use: unborn HEAD, an operation in progress, unmerged paths.
func checkSource(ctx context.Context, dir string, refusal error) (sourceInfo, error) {
	var si sourceInfo
	out, err := srcGit(ctx, dir, "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir", "--git-common-dir")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if err != nil || len(lines) != 3 {
		return si, fmt.Errorf("jail: %s is not a git worktree: %v", dir, err)
	}
	si.top, si.gitDir, si.commonDir = lines[0], lines[1], lines[2]
	if out, err = srcGit(ctx, si.top, "rev-parse", "--verify", "-q", "HEAD^{commit}"); err != nil {
		return si, fmt.Errorf("%w: unborn HEAD in %s", refusal, si.top)
	}
	si.head = strings.TrimSpace(out)
	args := []string{"rev-parse", "--path-format=absolute", "--git-path", "objects", "--git-path", "info/exclude"}
	for _, p := range inProgress {
		args = append(args, "--git-path", p.path)
	}
	out, err = srcGit(ctx, si.top, args...)
	paths := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if err != nil || len(paths) != 2+len(inProgress) {
		return si, fmt.Errorf("jail: git paths of %s: %v", si.top, err)
	}
	si.objects, si.exclude = paths[0], paths[1]
	for i, p := range inProgress {
		if _, err := os.Lstat(paths[2+i]); err == nil {
			return si, fmt.Errorf("%w: %s in progress in %s", refusal, p.op, si.top)
		}
	}
	if out, err = srcGit(ctx, si.top, "ls-files", "-u", "-z"); err != nil {
		return si, err
	}
	if out != "" {
		return si, fmt.Errorf("%w: unmerged paths in %s", refusal, si.top)
	}
	return si, nil
}

// newPaths returns the paths the snapshot adds to HEAD's tree beyond `add -u`, NUL-separated: the source's untracked,
// non-ignored files and the files staged as new (in the source's index, not in HEAD). It refuses nested repositories
// and oversized files first; sizes are taken with Lstat, so nothing is read or followed.
func newPaths(ctx context.Context, top string, maxTotal int64) ([]byte, error) {
	others, err := srcGit(ctx, top, "ls-files", "-z", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	staged, err := srcGit(ctx, top, "diff-index", "--cached", "-z", "--name-only", "--no-renames", "--diff-filter=A", "HEAD")
	if err != nil {
		return nil, err
	}
	var list []string
	var nested, big []string
	var total int64
	for i, out := range []string{others, staged} {
		for _, p := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
			if p == "" {
				continue
			}
			if i == 0 && strings.HasSuffix(p, "/") { // git lists an untracked nested repository as its directory
				nested = append(nested, p)
				continue
			}
			fi, err := os.Lstat(filepath.Join(top, filepath.FromSlash(p)))
			if i == 1 && err != nil {
				continue // staged, then removed from the worktree: add -u records nothing for it either
			}
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrSnapshot, err)
			}
			if fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
				if fi.Size() > MaxUntrackedFile {
					big = append(big, p)
				}
				total += fi.Size()
			}
			list = append(list, p)
		}
	}
	switch {
	case len(nested) > 0:
		return nil, fmt.Errorf("%w: nested git repository among the untracked paths: %s", ErrSnapshot, strings.Join(nested, ", "))
	case len(big) > 0:
		return nil, fmt.Errorf("%w: untracked file over 10 MiB: %s", ErrSnapshot, strings.Join(big, ", "))
	case total > maxTotal:
		return nil, fmt.Errorf("%w: untracked files total %d bytes, over %d MiB (raise with --max-untracked-mib)", ErrSnapshot, total, maxTotal>>20)
	case len(list) == 0:
		return nil, nil
	}
	return []byte(strings.Join(list, "\x00") + "\x00"), nil
}

// takeSnapshot captures dir's worktree (worktree-seeding.md §1 steps 1 to 3) and returns it with its tree.
// treeStore, if set, is an object dir that keeps the snapshot's new trees (paths and blob ids, no content), so a
// later apply --snapshot-tree can count the paths that diverged; it is an extra alternate of the snapshot, as are
// readOnly (object dirs that are only read). The caller closes the snapshot, which removes its temporary directory.
func takeSnapshot(ctx context.Context, dir string, o SnapshotOptions, treeStore string, readOnly ...string) (_ *snapshot, err error) {
	if o.MaxUntrackedMiB < 0 {
		return nil, fmt.Errorf("jail: negative max untracked MiB")
	}
	maxTotal := int64(DefaultMaxUntrackedMiB) << 20
	if o.MaxUntrackedMiB > 0 {
		maxTotal = int64(o.MaxUntrackedMiB) << 20
	}
	si, err := checkSource(ctx, dir, ErrSnapshot)
	if err != nil {
		return nil, err
	}
	// read-tree drops skip-worktree bits, so a sparse checkout's absent files would be recorded as deleted.
	if out, err := srcGit(ctx, si.top, "ls-files", "-t", "-z"); err != nil {
		return nil, err
	} else if strings.HasPrefix(out, "S ") || strings.Contains(out, "\x00S ") {
		return nil, fmt.Errorf("%w: sparse checkout (skip-worktree entries) in %s", ErrSnapshot, si.top)
	}
	list, err := newPaths(ctx, si.top, maxTotal)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "wj-snapshot-")
	if err != nil {
		return nil, err
	}
	s := &snapshot{top: si.top, tmp: tmp, gitDir: filepath.Join(tmp, "seed.git"), objects: filepath.Join(tmp, "objects"), Parent: si.head}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	if real, err := filepath.EvalSymlinks(tmp); err != nil || within(real, si.top) || within(real, si.commonDir) {
		return nil, fmt.Errorf("%w: temporary dir %s is inside the source", ErrSnapshot, tmp)
	}
	init := exec.CommandContext(ctx, "git", "init", "-q", "--bare", "--template=", s.gitDir)
	init.Env = append(hostEnv(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := init.CombinedOutput(); err != nil {
		return nil, &cmdError{"git init", err, out}
	}
	alternates := si.objects + "\n" + s.objects + "\n"
	for _, d := range append([]string{treeStore}, readOnly...) {
		if d != "" {
			alternates += d + "\n"
		}
	}
	if err := os.MkdirAll(s.objects, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(s.gitDir, "objects", "info", "alternates"), []byte(alternates), 0o600); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(si.exclude); err == nil {
		if err := os.MkdirAll(filepath.Join(s.gitDir, "info"), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(s.gitDir, "info", "exclude"), b, 0o600); err != nil {
			return nil, err
		}
	}
	if _, err := s.git(ctx, nil, "", "read-tree", s.Parent); err != nil {
		return nil, err
	}
	// Stat info only, in the temporary index: add -u then hashes just the files that changed. Exit 1 means "needs update".
	if _, err := s.git(ctx, nil, s.objects, "update-index", "-q", "--refresh"); err != nil && exitCode(err) != 1 {
		return nil, err
	}
	if _, err := s.git(ctx, nil, s.objects, "add", "-u"); err != nil {
		return nil, err
	}
	if len(list) > 0 {
		if _, err := s.git(ctx, list, s.objects, "add", "-f", "--pathspec-from-file=-", "--pathspec-file-nul"); err != nil {
			return nil, err
		}
	}
	treeObjs := s.objects
	if treeStore != "" {
		treeObjs = treeStore
	}
	out, err := s.git(ctx, nil, treeObjs, "write-tree", "--missing-ok")
	if err != nil {
		return nil, err
	}
	s.Tree = strings.TrimSpace(out)
	return s, nil
}

// exitCode returns the exit status of a failed git command, or -1.
func exitCode(err error) int {
	if ce, ok := err.(*cmdError); ok {
		if code, _ := exitOf(ce.err); code > 0 {
			return code
		}
	}
	return -1
}

// within reports whether p is root or below it.
func within(p, root string) bool {
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// commit makes the snapshot commit (step 5) and points refs/heads/snapshot at it (step 6): fixed identity and
// date, no signing, so the commit id is a function of the content and the parent.
func (s *snapshot) commit(ctx context.Context) error {
	out, err := s.git(ctx, nil, "", "commit-tree", "--no-gpg-sign", "-p", s.Parent, "-m", "worker-jail snapshot", s.Tree)
	if err != nil {
		return err
	}
	s.Commit = strings.TrimSpace(out)
	_, err = s.git(ctx, nil, "", "update-ref", snapshotRef, s.Commit)
	return err
}

// bundle returns the command that writes a bundle of refs/heads/snapshot to stdout.
func (s *snapshot) bundle(ctx context.Context) *exec.Cmd {
	return s.cmd(ctx, "", "bundle", "create", "-", snapshotRef)
}

// SnapshotTree returns the tree a snapshot of dir's worktree would have now, without writing to dir: the same
// technique, refusals and limits as provision --from-worktree, in a temporary repository that is removed again.
// Importers (rwh) compare it with Workspace.SnapshotTree.
func SnapshotTree(ctx context.Context, dir string) (string, error) {
	s, err := takeSnapshot(ctx, dir, SnapshotOptions{}, "")
	defer s.close()
	if err != nil {
		return "", err
	}
	return s.Tree, nil
}

// Secret guard (worktree-seeding.md §2).
var (
	secretNames   = []string{".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "id_ecdsa*", ".netrc", ".npmrc", ".pypirc", "credentials*.json"}
	secretContent = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|xox[bp]-[A-Za-z0-9-]{20,}`)
)

// secretName reports whether path's basename matches the name rule, case-insensitively.
func secretName(p string) bool {
	base := strings.ToLower(path.Base(p))
	for _, pat := range secretNames {
		if ok, _ := path.Match(pat, base); ok {
			return true
		}
	}
	return false
}

// guard runs the secret guard over the delta between the parent and the snapshot tree: every added, modified or
// type-changed path. The name rule skips the paths in allow; the content rule reads blobs up to 1 MiB and has
// no override. The error lists paths only, never what matched.
func (s *snapshot) guard(ctx context.Context, allow []string) error {
	raw, err := s.git(ctx, nil, "", "diff-tree", "-r", "-z", "--no-renames", "--diff-filter=AMT", s.Parent, s.Tree)
	if err != nil {
		return err
	}
	var byName, byContent []string
	var blobs []string
	paths := map[string][]string{}
	f := strings.Split(raw, "\x00")
	for i := 0; i+1 < len(f); i += 2 {
		meta, p := strings.Fields(strings.TrimPrefix(f[i], ":")), f[i+1]
		if len(meta) < 5 {
			return fmt.Errorf("jail: unparsable diff entry %q", f[i])
		}
		if meta[1] == "160000" {
			continue // a gitlink carries no content
		}
		if secretName(p) && !slices.Contains(allow, p) {
			byName = append(byName, p)
		}
		if paths[meta[3]] == nil {
			blobs = append(blobs, meta[3])
		}
		paths[meta[3]] = append(paths[meta[3]], p)
	}
	hits, err := s.scanBlobs(ctx, blobs)
	if err != nil {
		return err
	}
	for _, oid := range hits {
		byContent = append(byContent, paths[oid]...)
	}
	if len(byName) == 0 && len(byContent) == 0 {
		return nil
	}
	slices.Sort(byContent)
	var parts []string
	if len(byName) > 0 {
		parts = append(parts, "name rule: "+strings.Join(byName, ", "))
	}
	if len(byContent) > 0 {
		parts = append(parts, "content rule: "+strings.Join(byContent, ", "))
	}
	return fmt.Errorf("%w: %s", ErrSecret, strings.Join(parts, "; "))
}

// scanBlobs returns the blobs (up to secretScanMax bytes each) whose content matches the content rule.
func (s *snapshot) scanBlobs(ctx context.Context, oids []string) ([]string, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	cmd := s.cmd(ctx, "", "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(strings.Join(oids, "\n") + "\n")
	var errb bytes.Buffer
	cmd.Stderr = &limitBuffer{buf: &errb, max: 1 << 20}
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	hits, rerr := readBatch(bufio.NewReader(pipe), len(oids))
	io.Copy(io.Discard, pipe)
	if werr := cmd.Wait(); werr != nil {
		return nil, &cmdError{"git cat-file --batch", werr, errb.Bytes()}
	}
	return hits, rerr
}

// readBatch reads n `cat-file --batch` records and returns the oids whose content matches the content rule.
func readBatch(r *bufio.Reader, n int) ([]string, error) {
	var hits []string
	for range n {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("jail: cat-file: %w", err)
		}
		f := strings.Fields(hdr)
		if len(f) != 3 {
			return nil, fmt.Errorf("jail: cat-file: unexpected header %q", strings.TrimSpace(hdr))
		}
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("jail: cat-file: %w", err)
		}
		if size > secretScanMax {
			if _, err := r.Discard(int(size) + 1); err != nil {
				return nil, fmt.Errorf("jail: cat-file: %w", err)
			}
			continue
		}
		body := make([]byte, size+1)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("jail: cat-file: %w", err)
		}
		if secretContent.Match(body[:size]) {
			hits = append(hits, f[0])
		}
	}
	return hits, nil
}
