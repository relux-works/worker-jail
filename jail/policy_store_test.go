package jail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// A valid none-mode policy is stored 0600 under policies/P.W.json and reads back with its id and risk.
func TestSetPolicyStores(t *testing.T) {
	j := newTestJail(t, newFakeDocker())
	r := Ref{"worker-jail", "rev-1"}
	sp, err := j.SetPolicy(context.Background(), r, []byte(reviewerExample), SetPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sp.Risk.Level != RiskLow || sp.Policy.ID() != policyID(t, []byte(reviewerExample)) {
		t.Fatalf("stored %+v", sp)
	}
	fi, err := os.Stat(j.policyPath(r))
	if err != nil || fi.Mode().Perm() != 0o600 || !strings.HasSuffix(sp.Path, "/policies/worker-jail.rev-1.json") {
		t.Fatalf("file %v %v %s", fi, err, sp.Path)
	}
	shown, err := j.ShowPolicy(r)
	if err != nil || shown.Policy.ID() != sp.Policy.ID() || string(shown.Raw) != reviewerExample || shown.Risk.Level != RiskLow {
		t.Fatalf("show %+v %v", shown, err)
	}
	if p, err := j.LoadPolicy(r); err != nil || p.ID() != sp.Policy.ID() {
		t.Fatalf("load %v", err)
	}
	if err := j.RemovePolicy(r); err != nil {
		t.Fatal(err)
	}
	if _, err := j.LoadPolicy(r); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("load after rm: %v", err)
	}
	if err := j.RemovePolicy(r); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("second rm: %v", err)
	}
}

// SetPolicy refusals; none of them writes a file.
func TestSetPolicyRefusals(t *testing.T) {
	rate := map[string]any{"requests_per_min": 60, "max_conns": 4, "bytes_per_day": 1 << 20}
	all := mut(t, yoloExample, set("network", map[string]any{"mode": "all", "ports": []any{"*"}, "rate": rate}))
	ctx := context.Background()
	cases := []struct {
		ref   Ref
		data  []byte
		opt   SetPolicyOptions
		want  error
		field string
	}{
		// CRITICAL without accept-risk CRITICAL.
		{Ref{"webapp", "npm-1"}, all, SetPolicyOptions{}, ErrRiskExceeded, ""},
		// accepting HIGH does not accept CRITICAL.
		{Ref{"webapp", "npm-1"}, all, SetPolicyOptions{AcceptRisk: RiskHigh}, ErrRiskExceeded, ""},
		// accepted CRITICAL passes the risk gate and then meets the egress gate: generic modes arrive in a later v2.1 part.
		{Ref{"webapp", "npm-1"}, all, SetPolicyOptions{AcceptRisk: RiskCritical}, ErrEgressUnavailable, ""},
		// HIGH without a note.
		{Ref{"webapp", "npm-1"}, []byte(yoloExample), SetPolicyOptions{}, ErrRiskExceeded, ""},
		// HIGH with a note passes the risk gate and meets the egress gate (allowlist is generic).
		{Ref{"webapp", "npm-1"}, mut(t, yoloExample, set("note", "registry only")), SetPolicyOptions{}, ErrEgressUnavailable, ""},
		// denylist is generic too.
		{Ref{"webapp", "npm-1"}, mut(t, yoloExample, set("network.mode", "denylist"), set("network.ports", []string{"*"})),
			SetPolicyOptions{AcceptRisk: RiskCritical}, ErrEgressUnavailable, ""},
		// The whitelist alias is refused the same way.
		{Ref{"webapp", "npm-1"}, mut(t, yoloExample, set("network.mode", "whitelist"), set("note", "x")), SetPolicyOptions{}, ErrEgressUnavailable, ""},
		// project must equal the target.
		{Ref{"other", "rev-1"}, []byte(reviewerExample), SetPolicyOptions{}, ErrPolicyInvalid, "project"},
		// worker must equal the target.
		{Ref{"worker-jail", "rev-2"}, []byte(reviewerExample), SetPolicyOptions{}, ErrPolicyInvalid, "worker"},
		// An invalid policy.
		{Ref{"worker-jail", "rev-1"}, mut(t, reviewerExample, raw("limits.pids", "2.0")), SetPolicyOptions{}, ErrPolicyInvalid, "limits.pids"},
		// An invalid target name.
		{Ref{"Worker-Jail", "rev-1"}, []byte(reviewerExample), SetPolicyOptions{}, ErrInvalidName, ""},
	}
	for i, c := range cases {
		j := newTestJail(t, newFakeDocker())
		_, err := j.SetPolicy(ctx, c.ref, c.data, c.opt)
		if !errors.Is(err, c.want) {
			t.Errorf("case %d: err %v, want %v", i, err, c.want)
		}
		var pe *PolicyError
		if c.field != "" && (!errors.As(err, &pe) || pe.Field != c.field) {
			t.Errorf("case %d: err %v, want field %s", i, err, c.field)
		}
		if c.want == ErrEgressUnavailable && !strings.Contains(err.Error(), "the generic modes (allowlist, denylist, all) arrive in a later v2.1 part") {
			t.Errorf("case %d: egress message %q does not name v2.1", i, err)
		}
		if files, _ := os.ReadDir(j.state + "/policies"); len(files) != 0 || len(j.docker.(*fakeDocker).calls) != 0 {
			t.Errorf("case %d: refused policy left %d files or called docker", i, len(files))
		}
	}
}

// A stored file that was edited by hand is validated again on load: invalid or for another target, it fails.
func TestLoadPolicyRevalidates(t *testing.T) {
	j := newTestJail(t, newFakeDocker())
	r := Ref{"worker-jail", "rev-1"}
	if err := writeAtomic(j.policyPath(r), []byte(strings.Replace(reviewerExample, `"pids":256`, `"pids":2.0`, 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := j.LoadPolicy(r); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("invalid stored file: %v", err)
	}
	storePolicy(t, j, r.Project, r.Worker, testPolicy("worker-jail", "rev-2"))
	if _, err := j.LoadPolicy(r); !errors.Is(err, ErrPolicyInvalid) || !strings.Contains(err.Error(), "worker") {
		t.Fatalf("other target's file: %v", err)
	}
}

// Provision without a stored policy, or with a generic network mode, fails before any docker call; a none policy
// provisions (control). Provisioning under a modules policy is in egress_test.go.
func TestProvisionNeedsPolicy(t *testing.T) {
	repo := newRepo(t)
	fd := newFakeDocker()
	fd.onStart = provisionStart(t, 1, 0)
	j := newTestJail(t, fd)
	ctx := context.Background()
	if _, err := j.Provision(ctx, ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo}); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("no policy: %v", err)
	}
	storePolicy(t, j, "webapp", "npm-1", []byte(yoloExample))
	if _, err := j.Provision(ctx, ProvisionSpec{Ref: Ref{"webapp", "npm-1"}, Repo: repo}); !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("allowlist policy: %v", err)
	}
	if len(fd.calls) != 0 {
		t.Fatalf("refused provision called docker: %v", fd.calls)
	}
	os.Remove(j.policyPath(Ref{"webapp", "npm-1"})) // else doctor checks the egress service for it
	storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
	if _, err := j.Provision(ctx, ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// Run fails closed before any container is created: deleted policy, changed policy, unlabelled workspace,
// a generic network mode, and timeouts or output caps above the policy's.
func TestRunPolicyFailsClosed(t *testing.T) {
	ctx := context.Background()
	argv := RunSpec{Argv: []string{"true"}}
	cases := []struct {
		name  string
		setup func(fd *fakeDocker, j *Jail)
		spec  RunSpec
		want  error
		msg   string
	}{
		{"policy deleted", func(fd *fakeDocker, j *Jail) { j.RemovePolicy(Ref{"p1", "w1"}) }, argv, ErrNoPolicy, ""},
		{"policy changed", func(fd *fakeDocker, j *Jail) {
			storePolicy(t, j, "p1", "w1", mut(t, string(testPolicy("p1", "w1")), set("limits.pids", 1024)))
		}, argv, ErrPolicyChanged, "provisioned under"},
		{"unlabelled workspace", func(fd *fakeDocker, j *Jail) { delete(fd.volumes["wj.p1.w1"], LabelPolicyID) }, argv, ErrPolicyChanged, "before v2.0"},
		{"generic egress policy", func(fd *fakeDocker, j *Jail) {
			id := storePolicy(t, j, "p1", "w1", mut(t, yoloExample, set("project", "p1"), set("worker", "w1")))
			fd.volumes["wj.p1.w1"][LabelPolicyID] = id
		}, argv, ErrEgressUnavailable, "v2.1"},
		{"timeout above policy", func(fd *fakeDocker, j *Jail) {}, RunSpec{Argv: []string{"true"}, Timeout: 61 * time.Minute}, nil, "outside"},
		{"max output above policy", func(fd *fakeDocker, j *Jail) {}, RunSpec{Argv: []string{"true"}, MaxOutput: 4<<20 + 1}, nil, "max_output_bytes"},
	}
	for _, c := range cases {
		fd := newFakeDocker()
		addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
		j := newTestJail(t, fd)
		c.setup(fd, j)
		_, err := j.Run(ctx, Ref{"p1", "w1"}, c.spec)
		if err == nil || c.want != nil && !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: err %v, want %v (%q)", c.name, err, c.want, c.msg)
		}
		if n := fd.count("create"); n != 0 {
			t.Errorf("%s: %d containers created", c.name, n)
		}
	}
	// Control: the untouched setup runs.
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	if _, err := newTestJail(t, fd).Run(ctx, Ref{"p1", "w1"}, argv); err != nil || fd.count("create") != 1 {
		t.Fatalf("control: %v", err)
	}
}

// policyWorkspace stores data as p1.w1's policy and labels the workspace with its id.
func policyWorkspace(t *testing.T, data []byte) (*fakeDocker, *Jail) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	j := newTestJail(t, fd)
	fd.volumes["wj.p1.w1"][LabelPolicyID] = storePolicy(t, j, "p1", "w1", data)
	return fd, j
}

// workspace.access=read-only and the policy's cpus, memory and pids reach docker create; every
// other hardening flag is unchanged. Control: a read-write policy mounts /work read-write.
func TestRunAppliesPolicy(t *testing.T) {
	ro := mut(t, string(testPolicy("p1", "w1")), set("workspace.access", "read-only"), set("workspace.write_scope", []string{}),
		raw("limits.cpus", "0.5"), set("limits.memory_mib", 512), set("limits.pids", 64), set("limits.call_timeout_s", 30))
	fd, j := policyWorkspace(t, ro)
	addCache(fd, "p1", "gomod")
	res, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}})
	if err != nil || res.Exit != 0 {
		t.Fatal(err)
	}
	a := fd.starts[0].create
	for _, pair := range [][2]string{
		{"--mount", "type=volume,src=wj.p1.w1,dst=/work,readonly"},
		{"--mount", "type=volume,src=wj-cache.p1.gomod,dst=/cache/gomod,readonly"},
		{"--cpus", "0.5"}, {"--memory", "536870912"}, {"--memory-swap", "536870912"}, {"--pids-limit", "64"},
		{"--network", "none"}, {"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"}, {"--user", "10001:10001"},
		{"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=536870912"}, {"--ulimit", "nofile=4096:4096"}, {"-w", "/work/src"},
		{"KILL", "35"}, // call_timeout_s 30 is the default timeout, plus the 5 s backstop
	} {
		if !hasPair(a, pair[0], pair[1]) {
			t.Errorf("create args lack %s %s: %q", pair[0], pair[1], a)
		}
	}
	if !hasPair(a, "--read-only", "--tmpfs") {
		t.Errorf("read-only rootfs lost: %q", a)
	}
	fd, j = policyWorkspace(t, testPolicy("p1", "w1"))
	if _, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	if a := fd.starts[0].create; !hasPair(a, "--mount", "type=volume,src=wj.p1.w1,dst=/work") || !hasPair(a, "--cpus", "2") {
		t.Fatalf("control: rw policy args %q", a)
	}
}

// The policy's call_timeout_s and max_output_bytes are both the defaults and the maximums of a Run.
func TestRunPolicyTimeoutAndOutput(t *testing.T) {
	pol := mut(t, string(testPolicy("p1", "w1")), set("limits.call_timeout_s", 30), set("limits.max_output_bytes", 2048))
	fd, j := policyWorkspace(t, pol)
	ctx := context.Background()
	for _, s := range []RunSpec{{Argv: []string{"x"}, Timeout: 31 * time.Second}, {Argv: []string{"x"}, MaxOutput: 2049}} {
		if _, err := j.Run(ctx, Ref{"p1", "w1"}, s); err == nil {
			t.Errorf("spec %+v accepted", s)
		}
	}
	if fd.count("create") != 0 {
		t.Fatal("refused run created a container")
	}
	fd.onStart = func(c *fakeCall) int {
		buf := bytes.Repeat([]byte("y"), 512)
		for {
			select {
			case <-c.killed:
				return 137
			default:
				c.stdout.Write(buf)
			}
		}
	}
	res, err := j.Run(ctx, Ref{"p1", "w1"}, RunSpec{Argv: []string{"yes"}, Timeout: 30 * time.Second})
	if err != nil || !res.Truncated || len(res.Stdout) != 2048 {
		t.Fatalf("default cap: truncated=%v len=%d err=%v", res.Truncated, len(res.Stdout), err)
	}
}
