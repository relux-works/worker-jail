package workplace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// takeSnap snapshots dir and removes the snapshot's temporary directory at the end of the test.
func takeSnap(t *testing.T, dir string, o SnapshotOptions) *snapshot {
	t.Helper()
	s, err := takeSnapshot(context.Background(), dir, o, "")
	t.Cleanup(s.close)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// treeFiles returns the snapshot tree as path → content (link text for symlinks, "gitlink <oid>" for gitlinks).
func treeFiles(t *testing.T, s *snapshot) map[string]string {
	t.Helper()
	ctx := context.Background()
	out, err := s.git(ctx, nil, "", "ls-tree", "-r", "-z", s.Tree)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, rec := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
		meta, p, _ := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if f[1] == "commit" {
			files[p] = "gitlink " + f[2]
			continue
		}
		b, err := s.git(ctx, nil, "", "cat-file", "blob", f[2])
		if err != nil {
			t.Fatal(err)
		}
		files[p] = b
	}
	return files
}

// fingerprint records every file and directory under the roots with mode, size, mtime and content hash,
// so any write (a new object, an index refresh, a lock file, a touched mtime) changes it.
func fingerprint(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	fp := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			v := fmt.Sprintf("%v %d %d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
			if fi.Mode().IsRegular() {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				sum := sha256.Sum256(b)
				v += " " + hex.EncodeToString(sum[:])
			}
			fp[p] = v
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return fp
}

func sameFingerprint(t *testing.T, before, after map[string]string) {
	t.Helper()
	for p, v := range before {
		if after[p] != v {
			t.Errorf("changed: %s\n  before %s\n  after  %s", p, v, after[p])
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("created: %s", p)
		}
	}
}

// gitMay runs git like git() but returns its failure instead of failing the test.
func gitMay(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func commitAll(t *testing.T, dir, msg string) {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
}

// dirtyRepo has a committed tracked.txt, gone.txt, staged.txt and .gitignore, then: tracked.txt modified,
// gone.txt deleted, staged.txt modified and staged, new.txt staged as new, untracked.txt and sub/u.txt untracked,
// and ignored (.gitignore), excluded (info/exclude) files.
func dirtyRepo(t *testing.T) string {
	t.Helper()
	dir := newRepo(t)
	writeFile(t, filepath.Join(dir, "tracked.txt"), "v1\n")
	writeFile(t, filepath.Join(dir, "gone.txt"), "bye\n")
	writeFile(t, filepath.Join(dir, "staged.txt"), "s1\n")
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.log\n")
	commitAll(t, dir, "files")
	writeFile(t, filepath.Join(dir, "tracked.txt"), "v2\n")
	os.Remove(filepath.Join(dir, "gone.txt"))
	writeFile(t, filepath.Join(dir, "staged.txt"), "s2\n")
	writeFile(t, filepath.Join(dir, "new.txt"), "new\n")
	git(t, dir, "add", "staged.txt", "new.txt")
	writeFile(t, filepath.Join(dir, "untracked.txt"), "u\n")
	writeFile(t, filepath.Join(dir, "sub", "u.txt"), "su\n")
	writeFile(t, filepath.Join(dir, "debug.log"), "ignored\n")
	writeFile(t, filepath.Join(dir, ".git", "info", "exclude"), "excluded.txt\n")
	writeFile(t, filepath.Join(dir, "excluded.txt"), "excluded\n")
	return dir
}

// The snapshot holds the worktree's state: modified, staged (modified and new) and untracked files are in,
// deleted files are gone, and ignored, info/exclude-excluded and globally excluded files are out.
func TestSnapshotContent(t *testing.T) {
	dir := dirtyRepo(t)
	global := filepath.Join(t.TempDir(), "gitconfig")
	globalIgnore := filepath.Join(t.TempDir(), "ignore")
	writeFile(t, globalIgnore, "global-excluded.txt\n")
	writeFile(t, global, "[core]\n\texcludesFile = "+globalIgnore+"\n")
	t.Setenv("GIT_CONFIG_GLOBAL", global) // the owner's global config, read by the untracked listing only
	writeFile(t, filepath.Join(dir, "global-excluded.txt"), "g\n")
	s := takeSnap(t, dir, SnapshotOptions{})
	got := treeFiles(t, s)
	want := map[string]string{"README.md": "hello\n", ".gitignore": "*.log\n", "tracked.txt": "v2\n", "staged.txt": "s2\n",
		"new.txt": "new\n", "untracked.txt": "u\n", "sub/u.txt": "su\n"}
	for p, c := range want {
		if got[p] != c {
			t.Errorf("%s: %q, want %q", p, got[p], c)
		}
	}
	for _, p := range []string{"gone.txt", "debug.log", "excluded.txt", "global-excluded.txt"} {
		if _, ok := got[p]; ok {
			t.Errorf("%s is in the snapshot", p)
		}
	}
	if len(got) != len(want) {
		t.Errorf("snapshot files %v", got)
	}
	if head := git(t, dir, "rev-parse", "HEAD"); s.Parent != head {
		t.Fatalf("parent %s, HEAD %s", s.Parent, head)
	}
	// Control: without the global config the same file is untracked and lands in the snapshot.
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	if _, ok := treeFiles(t, takeSnap(t, dir, SnapshotOptions{}))["global-excluded.txt"]; !ok {
		t.Fatal("control: global-excluded.txt missing without the global exclude")
	}
}

// A symlink is stored as its link text, never followed; a clean worktree's snapshot tree is HEAD's tree.
func TestSnapshotSymlinkAndClean(t *testing.T) {
	dir := newRepo(t)
	if got, want := takeSnap(t, dir, SnapshotOptions{}).Tree, git(t, dir, "rev-parse", "HEAD^{tree}"); got != want {
		t.Fatalf("clean tree %s, HEAD tree %s", got, want)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if got := treeFiles(t, takeSnap(t, dir, SnapshotOptions{}))["link"]; got != "/etc/passwd" {
		t.Fatalf("link stored as %q", got)
	}
}

// The source is never written: every file and directory of the worktree and of .git (index bytes, refs, objects,
// mtimes) is identical after a snapshot, its commit and its bundle; the temporary directory is removed.
func TestSnapshotSourceIsolation(t *testing.T) {
	dir := dirtyRepo(t)
	// A copy of a committed blob as an untracked file: git add would freshen (touch) the existing source object.
	writeFile(t, filepath.Join(dir, "copy.txt"), "hello\n")
	git(t, dir, "gc", "-q") // packed objects and refs as well as loose ones below
	writeFile(t, filepath.Join(dir, "after-gc.txt"), "x\n")
	git(t, dir, "add", "after-gc.txt")
	before := fingerprint(t, dir)
	s, err := takeSnapshot(context.Background(), dir, SnapshotOptions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out, err := s.bundle(context.Background()).Output(); err != nil || !strings.HasPrefix(string(out), "# v") {
		t.Fatalf("bundle: %v", err)
	}
	tmp := s.tmp
	s.close()
	if exists(tmp) {
		t.Fatal("temporary directory left behind")
	}
	sameFingerprint(t, before, fingerprint(t, dir))
}

// A linked worktree snapshots its own state, and neither it nor the main checkout (which holds the common
// git dir) is written.
func TestSnapshotLinkedWorktree(t *testing.T) {
	main := newRepo(t)
	wt := filepath.Join(t.TempDir(), "wt")
	git(t, main, "worktree", "add", "-q", "-b", "story", wt)
	writeFile(t, filepath.Join(wt, "README.md"), "story edit\n")
	writeFile(t, filepath.Join(wt, "story.txt"), "s\n")
	writeFile(t, filepath.Join(main, "main-only.txt"), "m\n")
	before := fingerprint(t, main, wt)
	files := treeFiles(t, takeSnap(t, wt, SnapshotOptions{}))
	if files["README.md"] != "story edit\n" || files["story.txt"] != "s\n" || files["main-only.txt"] != "" {
		t.Fatalf("linked worktree snapshot %v", files)
	}
	sameFingerprint(t, before, fingerprint(t, main, wt))
}

// The source's clean filter, fsmonitor and hooks never run during a snapshot (an empty config, hooks and fsmonitor
// off). Control: a plain `git add` in the source runs the same filter.
func TestSnapshotRunsNoSourceConfig(t *testing.T) {
	dir := newRepo(t)
	canary := filepath.Join(t.TempDir(), "canary")
	script := filepath.Join(t.TempDir(), "touch.sh")
	writeFile(t, script, "#!/bin/sh\necho \"$0 $*\" >> "+canary+"\ncat\n")
	os.Chmod(script, 0o755)
	hooks := filepath.Join(t.TempDir(), "hooks")
	for _, h := range []string{"pre-commit", "post-index-change", "reference-transaction", "post-checkout", "fsmonitor-watchman"} {
		writeFile(t, filepath.Join(hooks, h), "#!/bin/sh\necho hook "+h+" >> "+canary+"\n")
		os.Chmod(filepath.Join(hooks, h), 0o755)
	}
	git(t, dir, "config", "filter.x.clean", script)
	git(t, dir, "config", "filter.x.required", "true")
	git(t, dir, "config", "core.fsmonitor", filepath.Join(hooks, "fsmonitor-watchman"))
	git(t, dir, "config", "core.hooksPath", hooks)
	writeFile(t, filepath.Join(dir, ".gitattributes"), "*.txt filter=x\n")
	writeFile(t, filepath.Join(dir, "a.txt"), "raw bytes\n")
	writeFile(t, filepath.Join(dir, "README.md"), "edited\n")
	s := takeSnap(t, dir, SnapshotOptions{})
	if err := s.commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(canary); err == nil {
		t.Fatalf("source config executed during the snapshot: %s", b)
	}
	if got := treeFiles(t, s)["a.txt"]; got != "raw bytes\n" {
		t.Fatalf("snapshot bytes %q, want raw", got)
	}
	git(t, dir, "add", "a.txt")
	if b, _ := os.ReadFile(canary); !strings.Contains(string(b), "touch.sh") {
		t.Fatalf("control: plain git add did not run the clean filter (canary %q); the test proves nothing", b)
	}
}

// commit.gpgsign=true with a bogus gpg.program in the source does not stop the snapshot commit, and the commit id
// is a function of the content: the same state gives the same id, another state another id.
func TestSnapshotCommitDeterministic(t *testing.T) {
	dir := dirtyRepo(t)
	git(t, dir, "config", "commit.gpgsign", "true")
	git(t, dir, "config", "gpg.program", "/nonexistent/gpg")
	commit := func() string {
		s := takeSnap(t, dir, SnapshotOptions{})
		if err := s.commit(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := git(t, s.gitDir, "cat-file", "-p", s.Commit); strings.Contains(got, "gpgsig") || !strings.Contains(got, "remote-workplace <snapshot@remote-workplace.invalid> 946684800 +0000") {
			t.Fatalf("commit %s", got)
		}
		return s.Commit
	}
	a, b := commit(), commit()
	if a != b {
		t.Fatalf("same content, different commits %s %s", a, b)
	}
	writeFile(t, filepath.Join(dir, "untracked.txt"), "changed\n")
	if c := commit(); c == a {
		t.Fatal("different content, same commit")
	}
	// Control: the source's own config does try to sign, and fails.
	if _, err := gitMay(dir, "commit", "--allow-empty", "-m", "x"); err == nil {
		t.Fatal("control: a plain commit in the source succeeded; the bogus gpg.program is not in effect")
	}
}

// The secret guard's name rule flags each pattern case-insensitively at any depth; ordinary names are left alone.
func TestSecretName(t *testing.T) {
	flagged := []string{".env", ".ENV", "sub/.env", ".env.local", "cert.pem", "a/server.KEY", "store.p12", "store.pfx",
		"id_rsa", "id_rsa.pub", "id_ed25519", "id_ecdsa_old", ".netrc", ".npmrc", ".pypirc", "credentials.json", "credentials-prod.json"}
	ordinary := []string{"env.txt", ".envrc", "my.env.bak", "pem.go", "keys.txt", "credentials.yaml", "id.rsa", "netrc.md", "a.key.txt"}
	for _, p := range flagged {
		if !secretName(p) {
			t.Errorf("%s not flagged", p)
		}
	}
	for _, p := range ordinary {
		if secretName(p) {
			t.Errorf("%s flagged", p)
		}
	}
}

// The guard runs on the whole delta (untracked, staged and modified tracked files), lists paths and never the
// matching text, skips ignored files, and lets the name rule (only) be overridden by exact path.
func TestSnapshotSecretGuard(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	contents := map[string]string{
		"private key": key,
		"aws":         "aws_access_key_id = AKIA" + strings.Repeat("Q", 16) + "\n",
		"github":      "token: ghp_" + strings.Repeat("a", 36) + "\n",
		"github pat":  "GITHUB_TOKEN=github_pat_" + strings.Repeat("B_", 26) + "\n",
		"slack":       "xoxb-" + strings.Repeat("1", 24) + "\n",
	}
	cases := []struct {
		name  string
		setup func(dir string)
		allow []string
		want  string // "" means the guard passes; otherwise a substring of the error
	}{
		{"name rule, untracked", func(d string) { writeFile(t, filepath.Join(d, "config", ".env"), "A=1\n") }, nil, "name rule: config/.env"},
		{"name rule, staged", func(d string) { writeFile(t, filepath.Join(d, "id_rsa"), "x\n"); git(t, d, "add", "id_rsa") }, nil, "name rule: id_rsa"},
		{"modified tracked .npmrc", func(d string) { writeFile(t, filepath.Join(d, ".npmrc"), "//registry/:_authToken=x\n") }, nil, "name rule: .npmrc"},
		{"unmodified tracked .npmrc is not in the delta", func(string) {}, nil, ""},
		{"ignored file is out of the snapshot", func(d string) {
			writeFile(t, filepath.Join(d, ".gitignore"), ".env\n")
			writeFile(t, filepath.Join(d, ".env"), key)
		}, nil, ""},
		{"override by exact path", func(d string) { writeFile(t, filepath.Join(d, ".env"), "A=1\n") }, []string{".env"}, ""},
		{"override is exact", func(d string) { writeFile(t, filepath.Join(d, "sub", ".env"), "A=1\n") }, []string{".env"}, "name rule: sub/.env"},
		{"content rule has no override", func(d string) { writeFile(t, filepath.Join(d, "deploy.pem"), key) }, []string{"deploy.pem"}, "content rule: deploy.pem"},
		{"content over 1 MiB is not read", func(d string) {
			writeFile(t, filepath.Join(d, "big.txt"), strings.Repeat("x", secretScanMax)+"\n"+key)
		}, nil, ""},
		{"ordinary content", func(d string) { writeFile(t, filepath.Join(d, "notes.txt"), "AKIA is a prefix\nghp_short\n") }, nil, ""},
	}
	for name, c := range contents {
		cases = append(cases, struct {
			name  string
			setup func(dir string)
			allow []string
			want  string
		}{"content " + name, func(d string) { writeFile(t, filepath.Join(d, "src", "notes.txt"), "x\n"+c) }, nil, "content rule: src/notes.txt"})
		cases = append(cases, struct {
			name  string
			setup func(dir string)
			allow []string
			want  string
		}{"content " + name + " in a modified tracked file", func(d string) { writeFile(t, filepath.Join(d, "README.md"), c) }, nil, "content rule: README.md"})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newRepo(t)
			writeFile(t, filepath.Join(dir, ".npmrc"), "registry=https://registry.npmjs.org/\n")
			commitAll(t, dir, "npmrc")
			c.setup(dir)
			err := takeSnap(t, dir, SnapshotOptions{}).guard(context.Background(), c.allow)
			if c.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrSecret) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			for _, secret := range []string{"PRIVATE KEY", "AKIA", "ghp_", "github_pat_", "xoxb-", "_authToken", "A=1"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks matching text %q: %v", secret, err)
				}
			}
		})
	}
}

// The override is refused for a HIGH or CRITICAL policy (decision 8) and allowed below; no override is always fine.
// The HIGH and CRITICAL levels come from stored policies, as Provision reads them.
func TestSecretOverrideByRisk(t *testing.T) {
	j := newTestWorkplace(t, newFakeDocker())
	high := strings.Replace(string(testPolicy("p1", "hi")), `"network":{"mode":"none"}`,
		`"network":{"mode":"allowlist","hosts":["registry\\.npmjs\\.org"],"ports":[443],"rate":{"requests_per_min":60,"max_conns":4,"bytes_per_day":1048576}}`, 1)
	high = strings.Replace(high, `"worker":"hi",`, `"worker":"hi","note":"npm",`, 1)
	critical := strings.Replace(string(testPolicy("p1", "cr")), `"network":{"mode":"none"}`,
		`"network":{"mode":"all","ports":["*"],"rate":{"requests_per_min":60,"max_conns":4,"bytes_per_day":1048576}}`, 1)
	storePolicy(t, j, "p1", "hi", []byte(high))
	storePolicy(t, j, "p1", "cr", []byte(critical))
	storePolicy(t, j, "p1", "md", testPolicy("p1", "md"))
	for _, c := range []struct {
		worker string
		risk   Risk
		ok     bool
	}{{"hi", RiskHigh, false}, {"cr", RiskCritical, false}, {"md", RiskMedium, true}} {
		pol, err := j.LoadPolicy(Ref{"p1", c.worker})
		if err != nil {
			t.Fatal(err)
		}
		risk := EffectiveRisk(pol).Level
		if risk != c.risk {
			t.Fatalf("%s: risk %s, want %s", c.worker, risk, c.risk)
		}
		err = secretOverrideAllowed([]string{".env"}, risk)
		if c.ok != (err == nil) || !c.ok && !errors.Is(err, ErrSecret) {
			t.Errorf("%s (%s): override err %v", c.worker, risk, err)
		}
		if err := secretOverrideAllowed(nil, risk); err != nil {
			t.Errorf("%s: no override refused: %v", c.worker, err)
		}
	}
}

// Each refusal is ErrSnapshot with its cause, and each has a control that passes.
func TestSnapshotRefusals(t *testing.T) {
	conflict := func(t *testing.T) string { // two branches that change README.md differently
		dir := newRepo(t)
		git(t, dir, "checkout", "-q", "-b", "other")
		writeFile(t, filepath.Join(dir, "README.md"), "other\n")
		commitAll(t, dir, "other")
		git(t, dir, "checkout", "-q", "main")
		writeFile(t, filepath.Join(dir, "README.md"), "main\n")
		commitAll(t, dir, "main")
		return dir
	}
	run := func(dir string, args ...string) { gitMay(dir, args...) } // expected to stop on the conflict
	cases := []struct {
		name  string
		setup func(t *testing.T) string
		o     SnapshotOptions
		want  string
	}{
		{"unborn HEAD", func(t *testing.T) string {
			d := t.TempDir()
			git(t, d, "init", "-q")
			writeFile(t, filepath.Join(d, "a"), "a\n")
			return d
		}, SnapshotOptions{}, "unborn HEAD"},
		{"merge", func(t *testing.T) string { d := conflict(t); run(d, "merge", "other"); return d }, SnapshotOptions{}, "a merge in progress"},
		{"rebase", func(t *testing.T) string { d := conflict(t); run(d, "rebase", "other"); return d }, SnapshotOptions{}, "rebase"},
		{"cherry-pick", func(t *testing.T) string { d := conflict(t); run(d, "cherry-pick", "other"); return d }, SnapshotOptions{}, "a cherry-pick in progress"},
		{"bisect", func(t *testing.T) string { d := conflict(t); git(t, d, "bisect", "start"); return d }, SnapshotOptions{}, "a bisect in progress"},
		{"unmerged paths", func(t *testing.T) string {
			d := conflict(t)
			run(d, "merge", "other")
			os.Remove(filepath.Join(d, ".git", "MERGE_HEAD")) // the merge state is gone, the conflict entries stay
			return d
		}, SnapshotOptions{}, "unmerged paths"},
		{"nested repository", func(t *testing.T) string {
			d := newRepo(t)
			git(t, d, "init", "-q", filepath.Join(d, "vendor", "lib"))
			writeFile(t, filepath.Join(d, "vendor", "lib", "x.go"), "package lib\n")
			return d
		}, SnapshotOptions{}, "nested git repository among the untracked paths: vendor/lib/"},
		{"untracked file over 10 MiB", func(t *testing.T) string {
			d := newRepo(t)
			writeFile(t, filepath.Join(d, "big.bin"), strings.Repeat("x", MaxUntrackedFile+1))
			return d
		}, SnapshotOptions{MaxUntrackedMiB: 1024}, "untracked file over 10 MiB: big.bin"},
		{"total over the limit", func(t *testing.T) string {
			d := newRepo(t)
			writeFile(t, filepath.Join(d, "a.bin"), strings.Repeat("a", 600<<10))
			writeFile(t, filepath.Join(d, "b.bin"), strings.Repeat("b", 600<<10))
			return d
		}, SnapshotOptions{MaxUntrackedMiB: 1}, "over 1 MiB"},
		{"sparse checkout", func(t *testing.T) string {
			d := newRepo(t)
			writeFile(t, filepath.Join(d, "docs", "x.md"), "x\n")
			commitAll(t, d, "docs")
			git(t, d, "update-index", "--skip-worktree", "docs/x.md")
			return d
		}, SnapshotOptions{}, "sparse checkout"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := c.setup(t)
			s, err := takeSnapshot(context.Background(), dir, c.o, "")
			s.close()
			if !errors.Is(err, ErrSnapshot) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
	// Controls: a 10 MiB file and a total within a raised limit pass; a committed gitlink is carried as a pointer.
	dir := newRepo(t)
	writeFile(t, filepath.Join(dir, "ok.bin"), strings.Repeat("x", MaxUntrackedFile))
	writeFile(t, filepath.Join(dir, "a.bin"), strings.Repeat("a", 600<<10))
	takeSnap(t, dir, SnapshotOptions{MaxUntrackedMiB: 12})
	head := git(t, dir, "rev-parse", "HEAD")
	git(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+head+",mod")
	git(t, dir, "commit", "-q", "-m", "gitlink")
	os.Mkdir(filepath.Join(dir, "mod"), 0o755) // an uninitialised submodule is an empty directory
	if got := treeFiles(t, takeSnap(t, dir, SnapshotOptions{MaxUntrackedMiB: 12}))["mod"]; got != "gitlink "+head {
		t.Fatalf("gitlink %q", got)
	}
	if _, err := takeSnapshot(context.Background(), t.TempDir(), SnapshotOptions{}, ""); err == nil {
		t.Fatal("a non-repository was snapshotted")
	}
}

// SnapshotTree is the tree provision would snapshot, and it writes nothing to the worktree.
func TestSnapshotTreeExported(t *testing.T) {
	dir := dirtyRepo(t)
	before := fingerprint(t, dir)
	tree, err := SnapshotTree(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := takeSnap(t, dir, SnapshotOptions{}).Tree; tree != want || !shaRE.MatchString(tree) {
		t.Fatalf("tree %s, want %s", tree, want)
	}
	sameFingerprint(t, before, fingerprint(t, dir))
	if _, err := SnapshotTree(context.Background(), t.TempDir()); err == nil {
		t.Fatal("non-repository accepted")
	}
}
