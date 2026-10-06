package jail

import (
	"bytes"
	"context"
	"errors"
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
