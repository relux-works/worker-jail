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

// provisionStart answers the existence probe with probeExit and accepts clone calls whose stdin is a git bundle.
func provisionStart(t *testing.T, probeExit, cloneExit int) func(c *fakeCall) int {
	return func(c *fakeCall) int {
		in := readAll(c.stdin)
		argv := c.argv()
		if argv[0] == "test" {
			return probeExit
		}
		if !bytes.HasPrefix(in, []byte("# v2 git bundle")) && !bytes.HasPrefix(in, []byte("# v3 git bundle")) {
			t.Errorf("clone stdin is not a git bundle: %q", in[:min(len(in), 40)])
		}
		if cloneExit != 0 {
			c.stderr.Write([]byte("fatal: clone failed"))
		}
		return cloneExit
	}
}

// A fresh workspace is created with labels and cloned from a host bundle at the resolved base.
func TestProvisionFresh(t *testing.T) {
	repo := newRepo(t)
	head := git(t, repo, "rev-parse", "HEAD")
	fd := newFakeDocker()
	fd.onStart = provisionStart(t, 1, 0)
	j := newTestJail(t, fd)
	id := storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
	storePolicy(t, j, "p1", "w2", testPolicy("p1", "w2"))
	ws, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if ws.Existed || ws.Base != head || ws.Volume != "wj.p1.w1" {
		t.Fatalf("ws %+v", ws)
	}
	l := fd.volumes["wj.p1.w1"]
	if l[LabelBase] != head || l[LabelKind] != KindWorkspace || l[LabelWorker] != "w1" || l[LabelCreated] == "" {
		t.Fatalf("labels %v", l)
	}
	if l[LabelPolicyID] != id || l[LabelPolicyRisk] != "MEDIUM" || ws.PolicyID != id || ws.Risk != "MEDIUM" {
		t.Fatalf("policy labels %v, ws %+v", l, ws)
	}
	argv := fd.starts[0].argv()
	if argv[0] != "sh" || argv[4] != head || argv[5] != "w1" || argv[6] != "w1@p1.worker-jail.invalid" {
		t.Fatalf("clone argv %q", argv)
	}
	if !hasPair(fd.starts[0].create, "-w", "/work") || strings.Contains(strings.Join(fd.starts[0].create, " "), ",readonly") {
		t.Fatalf("clone must mount the workspace rw at /work: %q", fd.starts[0].create)
	}
	// A tag works too (control for the raw-sha refusal).
	git(t, repo, "tag", "v1")
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w2"}, Repo: repo, RefName: "v1"}); err != nil {
		t.Fatalf("tag refused: %v", err)
	}
}

// An existing, complete workspace is returned with Existed and its label base; nothing is created.
func TestProvisionExisting(t *testing.T) {
	fd := newFakeDocker()
	base := strings.Repeat("b", 40)
	addWorkspace(fd, "p1", "w1", base)
	fd.onStart = provisionStart(t, 0, 0)
	j := newTestJail(t, fd)
	ws, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: "/nonexistent"})
	if err != nil || !ws.Existed || ws.Base != base {
		t.Fatalf("ws %+v err %v", ws, err)
	}
	if fd.count("volume create") != 0 || len(fd.starts) != 1 || !strings.Contains(strings.Join(fd.starts[0].create, " "), "dst=/work,readonly") {
		t.Fatalf("existing workspace must only be probed read-only; calls %v", fd.calls)
	}
}

// An existing volume without the provisioned marker is ErrIncomplete.
func TestProvisionIncomplete(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("b", 40))
	fd.onStart = provisionStart(t, 1, 0)
	j := newTestJail(t, fd)
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: newRepo(t)}); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err %v", err)
	}
}

// Any failed doctor check stops provisioning before anything is created.
func TestProvisionDoctorFailure(t *testing.T) {
	repo := newRepo(t)
	for _, breakIt := range []func(fd *fakeDocker, j *Jail){
		func(fd *fakeDocker, j *Jail) { fd.info = "colima\toverlay2\t4" },
		func(fd *fakeDocker, j *Jail) { fd.imageOut = `{"/data":{}}` },
		func(fd *fakeDocker, j *Jail) { j.colima = fakeColima{mounts: "x /Users/alexis virtiofs rw 0 0\n"} },
	} {
		fd := newFakeDocker()
		j := newTestJail(t, fd)
		storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
		breakIt(fd, j)
		if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo}); !errors.Is(err, ErrDoctor) {
			t.Fatalf("err %v", err)
		}
		if fd.count("volume") != 0 || fd.count("create") != 0 {
			t.Fatalf("doctor failure still touched docker: %v", fd.calls)
		}
	}
}

// A failed clone removes the volume again (no half-provisioned workspace).
func TestProvisionFailedCloneRemovesVolume(t *testing.T) {
	fd := newFakeDocker()
	fd.onStart = provisionStart(t, 1, 128)
	j := newTestJail(t, fd)
	storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
	_, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: newRepo(t)})
	if err == nil || !strings.Contains(err.Error(), "clone failed") {
		t.Fatalf("err %v", err)
	}
	if _, ok := fd.volumes["wj.p1.w1"]; ok || fd.count("volume rm -f wj.p1.w1") != 1 {
		t.Fatalf("volume left behind; calls %v", fd.calls)
	}
}

// Raw shas, option-like refs and unknown refs are refused before any volume exists.
func TestProvisionRefusesBadRefs(t *testing.T) {
	repo := newRepo(t)
	head := git(t, repo, "rev-parse", "HEAD")
	for _, ref := range []string{head, "--all", "nope"} {
		fd := newFakeDocker()
		j := newTestJail(t, fd)
		storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
		_, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo, RefName: ref})
		if err == nil {
			t.Fatalf("ref %q accepted", ref)
		}
		if ref == head && !strings.Contains(err.Error(), "branch, a tag or HEAD") {
			t.Fatalf("raw sha error %v", err)
		}
		if fd.count("volume create") != 0 {
			t.Fatalf("ref %q created a volume", ref)
		}
	}
	fd := newFakeDocker()
	if _, err := newTestJail(t, fd).Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "W"}, Repo: repo}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid worker: %v", err)
	}
}

// worktreeStart answers the existence probe with probeExit and records the stdin of the clone call (the bundle).
func worktreeStart(probeExit int, bundle *[]byte) func(c *fakeCall) int {
	return func(c *fakeCall) int {
		in := readAll(c.stdin)
		if c.argv()[0] == "test" {
			return probeExit
		}
		*bundle = in
		return 0
	}
}

// Provision from a dirty worktree: the base is the snapshot commit, the labels carry the snapshot tree and parent,
// the bundle carries refs/heads/snapshot at that commit with the dirty content, ls shows the labels, the source is
// not written, and a second provision returns the workspace unchanged whatever the worktree looks like now.
func TestProvisionFromWorktree(t *testing.T) {
	dir := dirtyRepo(t)
	head := git(t, dir, "rev-parse", "HEAD")
	fd := newFakeDocker()
	var bundle []byte
	fd.onStart = worktreeStart(1, &bundle)
	j := newTestJail(t, fd)
	storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
	before := fingerprint(t, dir)
	ws, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, FromWorktree: dir})
	if err != nil {
		t.Fatal(err)
	}
	sameFingerprint(t, before, fingerprint(t, dir))
	if ws.Existed || ws.SnapshotParent != head || !shaRE.MatchString(ws.SnapshotTree) || !shaRE.MatchString(ws.Base) || ws.Base == head {
		t.Fatalf("ws %+v", ws)
	}
	l := fd.volumes["wj.p1.w1"]
	if l[LabelBase] != ws.Base || l[LabelSnapshotTree] != ws.SnapshotTree || l[LabelSnapshotParent] != head || l[LabelPolicyRisk] != "MEDIUM" {
		t.Fatalf("labels %v", l)
	}
	if argv := fd.starts[0].argv(); argv[4] != ws.Base {
		t.Fatalf("clone checks out %q, want the snapshot commit %s", argv[4], ws.Base)
	}
	bfile := filepath.Join(t.TempDir(), "b.bundle")
	writeFile(t, bfile, string(bundle))
	if heads := git(t, dir, "bundle", "list-heads", bfile); heads != ws.Base+" refs/heads/snapshot" {
		t.Fatalf("bundle heads %q", heads)
	}
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, filepath.Dir(clone), "clone", "-q", "--no-checkout", bfile, clone)
	git(t, clone, "checkout", "-q", "--detach", ws.Base)
	if b, _ := os.ReadFile(filepath.Join(clone, "untracked.txt")); string(b) != "u\n" || exists(filepath.Join(clone, "gone.txt")) ||
		git(t, clone, "rev-parse", "HEAD^") != head || git(t, clone, "rev-parse", "HEAD^{tree}") != ws.SnapshotTree {
		t.Fatal("bundle does not carry the snapshot commit")
	}
	lst, err := j.List(context.Background(), "p1")
	if err != nil || len(lst.Workspaces) != 1 || lst.Workspaces[0].SnapshotTree != ws.SnapshotTree || lst.Workspaces[0].SnapshotParent != head {
		t.Fatalf("ls %+v %v", lst, err)
	}
	// The snapshot's trees stay in the host store for apply --snapshot-tree; blobs (file content) do not.
	cat := exec.Command("git", "-C", dir, "cat-file", "-t", ws.SnapshotTree)
	cat.Env = append(hostEnv(), "GIT_OBJECT_DIRECTORY="+j.SnapshotStore())
	if out, err := cat.Output(); err != nil || strings.TrimSpace(string(out)) != "tree" {
		t.Fatalf("snapshot tree not in the store: %v %s", err, out)
	}
	writeFile(t, filepath.Join(dir, "later.txt"), "later\n")
	fd.onStart = worktreeStart(0, &bundle)
	again, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, FromWorktree: dir})
	if err != nil || !again.Existed || again.Base != ws.Base || again.SnapshotTree != ws.SnapshotTree || again.SnapshotParent != head {
		t.Fatalf("idempotent provision %+v %v", again, err)
	}
}

// Every refusal of a worktree provision comes before any volume or container exists: a secret, a snapshot
// refusal, a repo or ref next to the worktree, and an override for a policy that egress already refuses in v2.0.
func TestProvisionFromWorktreeRefusals(t *testing.T) {
	secret := newRepo(t)
	writeFile(t, filepath.Join(secret, ".env"), "A=1\n")
	unborn := t.TempDir()
	git(t, unborn, "init", "-q")
	high := strings.Replace(string(testPolicy("p1", "w1")), `"network":{"mode":"none"}`,
		`"network":{"mode":"allowlist","hosts":["registry\\.npmjs\\.org"],"ports":[443],"rate":{"requests_per_min":60,"max_conns":4,"bytes_per_day":1048576}}`, 1)
	high = strings.Replace(high, `"worker":"w1",`, `"worker":"w1","note":"npm",`, 1)
	for _, c := range []struct {
		name   string
		policy string
		spec   ProvisionSpec
		is     error
	}{
		{"secret", "", ProvisionSpec{FromWorktree: secret}, ErrSecret},
		{"unborn HEAD", "", ProvisionSpec{FromWorktree: unborn}, ErrSnapshot},
		{"repo and worktree", "", ProvisionSpec{FromWorktree: secret, Repo: secret}, nil},
		{"ref and worktree", "", ProvisionSpec{FromWorktree: secret, RefName: "HEAD"}, nil},
		{"HIGH policy with an override", high, ProvisionSpec{FromWorktree: secret, SnapshotOptions: SnapshotOptions{AllowSecretPaths: []string{".env"}}}, ErrEgressUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			fd := newFakeDocker()
			j := newTestJail(t, fd)
			pol := testPolicy("p1", "w1")
			if c.policy != "" {
				pol = []byte(c.policy)
			}
			storePolicy(t, j, "p1", "w1", pol)
			c.spec.Ref = Ref{"p1", "w1"}
			_, err := j.Provision(context.Background(), c.spec)
			if err == nil || c.is != nil && !errors.Is(err, c.is) {
				t.Fatalf("err %v, want %v", err, c.is)
			}
			if fd.count("volume create") != 0 || len(fd.starts) != 0 {
				t.Fatalf("refusal after docker work: %v", fd.calls)
			}
		})
	}
	// Control: the same secret passes with an override under a MEDIUM policy.
	fd := newFakeDocker()
	var bundle []byte
	fd.onStart = worktreeStart(1, &bundle)
	j := newTestJail(t, fd)
	storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, FromWorktree: secret,
		SnapshotOptions: SnapshotOptions{AllowSecretPaths: []string{".env"}}}); err != nil {
		t.Fatalf("override under MEDIUM: %v", err)
	}
}
