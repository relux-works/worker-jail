package jail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// modulesPolicy is testPolicy with network mode modules.
func modulesPolicy(t *testing.T, p, w string, masks ...string) []byte {
	t.Helper()
	if len(masks) == 0 {
		masks = []string{`golang\.org/x/.*`}
	}
	return mut(t, string(testPolicy(p, w)), set("network", map[string]any{"mode": "modules", "go_modules": masks,
		"rate": map[string]any{"requests_per_min": 600, "max_conns": 8, "bytes_per_day": 1 << 30}}))
}

// egressFake is a fake docker with the egress volumes and a service that loads whatever the last policy call wrote:
// on HUP, the stdin of the last `put` becomes the loaded policy of its worker, and a `rm` unloads it.
func egressFake(t *testing.T) *fakeDocker {
	fd := newFakeDocker()
	for _, v := range []string{EgressSockVolume, EgressPolicyVolume, EgressCacheVolume} {
		fd.volumes[v] = map[string]string{LabelRoot: "1", LabelKind: KindEgress}
	}
	files := map[string][]byte{}
	fd.onStart = func(c *fakeCall) int {
		in := readAll(c.stdin)
		if a := c.argv(); len(a) >= 5 && a[2] == egressPolicyScript {
			switch a[4] {
			case "put":
				files[a[5]] = in
			case "rm":
				delete(files, a[5])
			}
		}
		return 0
	}
	fd.onHUP = func() {
		fd.mu.Lock()
		defer fd.mu.Unlock()
		fd.loaded = map[string]string{}
		for key, data := range files {
			if p, err := ParsePolicy(data); err == nil {
				fd.loaded[key] = p.ID()
			}
		}
	}
	return fd
}

func shortEgressWait(t *testing.T) {
	w, p := egressConfirmWait, egressPoll
	egressConfirmWait, egressPoll = 200*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { egressConfirmWait, egressPoll = w, p })
}

// egressCalls returns the create args of the policy-volume calls.
func egressCalls(fd *fakeDocker) []*fakeCall {
	var out []*fakeCall
	for _, c := range fd.starts {
		if hasPair(c.create, "--mount", "type=volume,src="+EgressPolicyVolume+",dst=/work") {
			out = append(out, c)
		}
	}
	return out
}

// policy set of a modules policy stores it, writes the whole file into the policy volume through a hardened call that
// mounts nothing else, signals the service and returns once the service reports the stored id.
func TestSetPolicyModulesDelivers(t *testing.T) {
	shortEgressWait(t)
	fd := egressFake(t)
	j := newTestJail(t, fd)
	data := modulesPolicy(t, "p1", "w1")
	sp, err := j.SetPolicy(context.Background(), Ref{"p1", "w1"}, data, SetPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sp.Policy.ID() != policyID(t, data) || fd.loaded["p1.w1"] != sp.Policy.ID() || fd.hups != 1 {
		t.Fatalf("stored %s loaded %v hups %d", sp.Policy.ID(), fd.loaded, fd.hups)
	}
	calls := egressCalls(fd)
	if len(calls) != 1 {
		t.Fatalf("policy calls %d", len(calls))
	}
	a := calls[0].create
	mounts := 0
	for _, s := range a {
		mounts += strings.Count(s, "type=volume")
	}
	for _, pair := range [][2]string{{"--network", "none"}, {"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"},
		{"--user", "10001:10001"}, {"--label", LabelProject + "=p1"}, {"-w", "/work"}} {
		if !hasPair(a, pair[0], pair[1]) {
			t.Errorf("policy call lacks %s %s: %q", pair[0], pair[1], a)
		}
	}
	if mounts != 1 || !reflect.DeepEqual(calls[0].argv(), []string{"sh", "-c", egressPolicyScript, "sh", "put", "p1.w1"}) {
		t.Fatalf("policy call %q", a)
	}
	if b, err := os.ReadFile(j.policyPath(Ref{"p1", "w1"})); err != nil || !bytes.Equal(b, data) {
		t.Fatalf("host file %q %v", b, err)
	}
}

// Delivery fails closed with ErrEgressUnavailable (CLI exit 5) when the service never confirms, is down, or was never
// set up; the policy stays stored (Run checks the loaded id anyway).
func TestSetPolicyModulesUnconfirmed(t *testing.T) {
	shortEgressWait(t)
	ctx := context.Background()
	data := modulesPolicy(t, "p1", "w1")
	cases := []struct {
		name  string
		setup func(fd *fakeDocker)
		msg   string
	}{
		{"never confirms", func(fd *fakeDocker) { fd.onHUP = nil }, "did not confirm"},
		{"stale id", func(fd *fakeDocker) { fd.onHUP = func() { fd.loaded["p1.w1"] = strings.Repeat("e", 64) } }, "did not confirm"},
		{"service down", func(fd *fakeDocker) { fd.hupExit = 1 }, "not running"},
		{"never set up", func(fd *fakeDocker) { delete(fd.volumes, EgressPolicyVolume) }, "egress up"},
		{"status fails", func(fd *fakeDocker) { fd.statusExit = 1 }, "did not answer"},
	}
	for _, c := range cases {
		fd := egressFake(t)
		c.setup(fd)
		j := newTestJail(t, fd)
		_, err := j.SetPolicy(ctx, Ref{"p1", "w1"}, data, SetPolicyOptions{})
		if !errors.Is(err, ErrEgressUnavailable) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, err := j.LoadPolicy(Ref{"p1", "w1"}); err != nil {
			t.Errorf("%s: policy not stored: %v", c.name, err)
		}
	}
}

// policy rm of a modules policy withdraws it from the service (file removed, signal) before the host file goes;
// a failed withdrawal keeps the host file. A none policy replacing a modules one withdraws it too.
func TestRemovePolicyWithdrawsEgress(t *testing.T) {
	shortEgressWait(t)
	ctx := context.Background()
	fd := egressFake(t)
	j := newTestJail(t, fd)
	r := Ref{"p1", "w1"}
	if _, err := j.SetPolicy(ctx, r, modulesPolicy(t, "p1", "w1"), SetPolicyOptions{}); err != nil {
		t.Fatal(err)
	}
	fd.onStart = func(c *fakeCall) int { return 1 }
	if err := j.RemovePolicy(r); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatalf("failed withdrawal: %v", err)
	}
	if _, err := j.LoadPolicy(r); err != nil {
		t.Fatalf("host file lost: %v", err)
	}
	fd2 := egressFake(t)
	fd2.loaded = fd.loaded
	j.docker = fd2
	if err := j.RemovePolicy(r); err != nil {
		t.Fatal(err)
	}
	calls := egressCalls(fd2)
	if len(calls) != 1 || !reflect.DeepEqual(calls[0].argv()[3:], []string{"sh", "rm", "p1.w1"}) || fd2.hups != 1 || fd2.loaded["p1.w1"] != "" {
		t.Fatalf("withdrawal: calls %d hups %d loaded %v", len(calls), fd2.hups, fd2.loaded)
	}
	if _, err := j.LoadPolicy(r); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("host file kept: %v", err)
	}

	// none replacing modules.
	if _, err := j.SetPolicy(ctx, r, modulesPolicy(t, "p1", "w1"), SetPolicyOptions{}); err != nil {
		t.Fatal(err)
	}
	sp, err := j.SetPolicy(ctx, r, testPolicy("p1", "w1"), SetPolicyOptions{})
	if err != nil || sp.EgressWarning != "" || fd2.loaded["p1.w1"] != "" {
		t.Fatalf("none after modules: %v %q %v", err, sp.EgressWarning, fd2.loaded)
	}
	// Control: a none policy replacing a none policy makes no docker call; a failed withdrawal is a warning.
	n := len(fd2.calls)
	if _, err := j.SetPolicy(ctx, r, testPolicy("p1", "w1"), SetPolicyOptions{}); err != nil || len(fd2.calls) != n {
		t.Fatalf("none after none: %v, %d docker calls", err, len(fd2.calls)-n)
	}
	j.SetPolicy(ctx, r, modulesPolicy(t, "p1", "w1"), SetPolicyOptions{})
	fd2.onStart = func(c *fakeCall) int { return 1 }
	if sp, err := j.SetPolicy(ctx, r, testPolicy("p1", "w1"), SetPolicyOptions{}); err != nil || !strings.Contains(sp.EgressWarning, "withdrawn") {
		t.Fatalf("failed withdrawal on replace: %v %q", err, sp.EgressWarning)
	}
}

// modulesWorkspace stores a modules policy for p1.w1, labels the workspace with it and has the service load it.
func modulesWorkspace(t *testing.T) (*fakeDocker, *Jail, string) {
	fd := egressFake(t)
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	j := newTestJail(t, fd)
	id := storePolicy(t, j, "p1", "w1", modulesPolicy(t, "p1", "w1"))
	fd.volumes["wj.p1.w1"][LabelPolicyID] = id
	fd.loaded["p1.w1"] = id
	return fd, j, id
}

// Run under a modules policy: the worker's socket only, read-only, through a subpath; the modules env instead of the
// gomod cache's; the relay before the tool; and every hardening flag of a v2.0 call, --network none included.
func TestRunModules(t *testing.T) {
	fd, j, _ := modulesWorkspace(t)
	addCache(fd, "p1", "gomod")
	if _, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"go", "mod", "download"}}); err != nil {
		t.Fatal(err)
	}
	a := fd.starts[0].create
	for _, pair := range [][2]string{
		{"--mount", "type=volume,src=wj.p1.w1,dst=/work"},
		{"--mount", "type=volume,src=wj-cache.p1.gomod,dst=/cache/gomod,readonly"},
		{"--mount", "type=volume,src=wj-egress-sock,dst=/run/wj,volume-subpath=p1.w1,readonly"},
		{"-e", "GOPROXY=file:///cache/gomod/cache/download,http://127.0.0.1:3128/gomod"},
		{"-e", "GOMODCACHE=/work/home/go/pkg/mod"}, {"-e", "GOSUMDB=sum.golang.org"}, {"-e", "GOTOOLCHAIN=local"},
		{"--network", "none"}, {"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"}, {"--user", "10001:10001"},
		{"--read-only", "--tmpfs"}, {"--log-driver", "none"},
	} {
		if !hasPair(a, pair[0], pair[1]) {
			t.Errorf("create args lack %s %s", pair[0], pair[1])
		}
	}
	for _, s := range a {
		if s == "GOPROXY=off" || s == "GOMODCACHE=/cache/gomod" {
			t.Errorf("gomod env %s with modules", s)
		}
		if strings.Contains(s, EgressPolicyVolume) || strings.Contains(s, EgressCacheVolume) || strings.Contains(s, "wj-egress-sock,dst=/run/wj,") && !strings.Contains(s, "volume-subpath=p1.w1,readonly") {
			t.Errorf("unexpected egress mount %s", s)
		}
	}
	if !reflect.DeepEqual(fd.starts[0].argv(), []string{"sh", "-c", relayScript, "wj-relay", "go", "mod", "download"}) {
		t.Fatalf("argv %q", fd.starts[0].argv())
	}
	if !strings.Contains(relayScript, "socat TCP-LISTEN:3128,bind=127.0.0.1,fork") || !strings.Contains(relayScript, "UNIX-CONNECT:/run/wj/egress.sock") ||
		!strings.HasSuffix(relayScript, "exec \"$@\"\n") {
		t.Fatalf("relay script %q", relayScript)
	}
}

// Run under a modules policy fails closed before any container unless the service serves exactly the stored id:
// a stale id (a reload that never happened, or another policy), no policy loaded, the service down.
// Control: the matching id runs.
func TestRunModulesChecksLoadedID(t *testing.T) {
	cases := []struct {
		name  string
		setup func(fd *fakeDocker)
		msg   string
	}{
		{"stale id", func(fd *fakeDocker) { fd.loaded["p1.w1"] = strings.Repeat("e", 64) }, "serves eeee"},
		{"not loaded", func(fd *fakeDocker) { delete(fd.loaded, "p1.w1") }, "serves no policy"},
		{"service down", func(fd *fakeDocker) { fd.statusExit = 1 }, "did not answer"},
		{"garbage answer", func(fd *fakeDocker) { fd.loaded["p1.w1"] = "not-an-id" }, "did not answer"},
	}
	for _, c := range cases {
		fd, j, _ := modulesWorkspace(t)
		c.setup(fd)
		_, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}})
		if !errors.Is(err, ErrEgressUnavailable) || !strings.Contains(err.Error(), c.msg) || fd.count("create") != 0 {
			t.Errorf("%s: %v (%d creates)", c.name, err, fd.count("create"))
		}
	}
	fd, j, _ := modulesWorkspace(t)
	if _, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}}); err != nil || fd.count("create") != 1 ||
		fd.count("exec wj-egress wj-egress status p1.w1") != 1 {
		t.Fatalf("control: %v", err)
	}
}

// A none policy produces exactly the v2.0 container args: no egress mount, env, relay or docker exec.
func TestRunNoneKeepsV20Args(t *testing.T) {
	fd, j := policyWorkspace(t, testPolicy("p1", "w1"))
	if _, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"make", "test"}, Timeout: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	got := append([]string(nil), fd.starts[0].create...)
	got[5] = testName
	want := append(hardening("w1"), "--mount", "type=volume,src=wj.p1.w1,dst=/work",
		"-w", "/work/src", "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp",
		DefaultImage, "timeout", "-s", "KILL", "605", "make", "test")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("none args changed:\n got %q\nwant %q", got, want)
	}
	if fd.count("exec") != 0 {
		t.Fatal("a none policy asked the egress service")
	}
}

// createArgs: a modules call is only a read-write call shape; the policy-volume shape mounts that volume alone.
func TestCreateArgsEgressShapes(t *testing.T) {
	ro := baseSpec(shapeCall)
	ro.Egress, ro.ReadOnly = true, true
	seed := baseSpec(shapeSeed)
	seed.Worker, seed.Cache, seed.Egress = "", "gomod", true
	pw := baseSpec(shapeEgressPolicy)
	for name, s := range map[string]callSpec{"read-only egress": ro, "seed egress": seed, "policy shape with a worker": pw} {
		if _, err := createArgs(s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	pw.Worker, pw.Workdir, pw.Argv = "", "/work", []string{"sh", "-c", egressPolicyScript, "sh", "init"}
	a, err := createArgs(pw)
	if err != nil {
		t.Fatal(err)
	}
	want := append(hardening(""), "--mount", "type=volume,src=wj-egress-policy,dst=/work",
		"-w", "/work", "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp",
		DefaultImage, "timeout", "-s", "KILL", "605", "sh", "-c", egressPolicyScript, "sh", "init")
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("policy shape:\n got %q\nwant %q", a, want)
	}
}

// A modules policy provisions (the clone needs no network) once doctor finds the service hardened; without the
// service doctor fails and nothing is created.
func TestProvisionModules(t *testing.T) {
	repo := newRepo(t)
	fd := egressFake(t)
	fd.onStart = provisionStart(t, 1, 0)
	j := newTestJail(t, fd)
	storePolicy(t, j, "p1", "w1", modulesPolicy(t, "p1", "w1"))
	fd.replies["inspect"] = fakeReply{err: "Error: No such object: wj-egress\n", exit: 1}
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo}); !errors.Is(err, ErrDoctor) ||
		!strings.Contains(err.Error(), "egress up") {
		t.Fatalf("service missing: %v", err)
	}
	if _, ok := fd.volumes["wj.p1.w1"]; ok {
		t.Fatal("workspace created without the service")
	}
	fd.replies["inspect"] = fakeReply{out: hardenedEgress}
	ws, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo})
	if err != nil || ws.PolicyID != policyID(t, modulesPolicy(t, "p1", "w1")) || ws.Risk != "MEDIUM" {
		t.Fatalf("provision %+v %v", ws, err)
	}
}

const hardenedEgress = `{"State":{"Running":true},"Config":{"User":"10002:10002","Image":"worker-jail/egress:1"},
 "HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"CapAdd":null,"SecurityOpt":["no-new-privileges"],
  "Memory":536870912,"PidsLimit":256,"NetworkMode":"wj-egress-net","LogConfig":{"Type":"local"},"Binds":null},
 "Mounts":[{"Type":"volume","Name":"wj-egress-sock","Destination":"/egress/sock","RW":true},
  {"Type":"volume","Name":"wj-egress-policy","Destination":"/egress/policy","RW":false},
  {"Type":"volume","Name":"wj-egress-cache","Destination":"/egress/cache","RW":true}]}`

// The doctor egress check passes the hardened service and fails each weakening; it runs only when a stored policy
// has a mode other than none.
func TestDoctorEgress(t *testing.T) {
	ok, d := checkEgressHardening(hardenedEgress)
	if !ok {
		t.Fatalf("hardened: %s", d)
	}
	for name, m := range map[string][2]string{
		"stopped":         {`"Running":true`, `"Running":false`},
		"root":            {`"User":"10002:10002"`, `"User":""`},
		"uid 0":           {`"User":"10002:10002"`, `"User":"0:0"`},
		"other image":     {`worker-jail/egress:1`, `evil:1`},
		"writable rootfs": {`"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`},
		"privileged":      {`"Privileged":false`, `"Privileged":true`},
		"caps kept":       {`"CapDrop":["ALL"]`, `"CapDrop":null`},
		"cap added":       {`"CapAdd":null`, `"CapAdd":["NET_ADMIN"]`},
		"new privileges":  {`"SecurityOpt":["no-new-privileges"]`, `"SecurityOpt":null`},
		"no memory limit": {`"Memory":536870912`, `"Memory":0`},
		"no pids limit":   {`"PidsLimit":256`, `"PidsLimit":null`},
		"log driver":      {`"Type":"local"`, `"Type":"json-file"`},
		"host network":    {`"NetworkMode":"wj-egress-net"`, `"NetworkMode":"host"`},
		"bind":            {`"Binds":null`, `"Binds":["/:/host"]`},
		"policy rw":       {`"Destination":"/egress/policy","RW":false`, `"Destination":"/egress/policy","RW":true`},
		"extra mount":     {`]}`, `,{"Type":"bind","Name":"","Destination":"/host","RW":true}]}`},
		"missing mount": {`,
  {"Type":"volume","Name":"wj-egress-cache","Destination":"/egress/cache","RW":true}`, ``},
	} {
		weak := strings.Replace(hardenedEgress, m[0], m[1], 1)
		if weak == hardenedEgress {
			t.Fatalf("%s: fixture unchanged", name)
		}
		if ok, _ := checkEgressHardening(weak); ok {
			t.Errorf("%s: passed", name)
		}
	}

	fd := egressFake(t)
	j := newTestJail(t, fd)
	if rep, err := j.Doctor(context.Background()); err != nil || len(rep.Checks) != 3 || fd.count("inspect") != 0 {
		t.Fatalf("no network policy: %+v %v", rep, err)
	}
	storePolicy(t, j, "p1", "w1", modulesPolicy(t, "p1", "w1"))
	fd.replies["inspect"] = fakeReply{out: strings.Replace(hardenedEgress, `"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`, 1)}
	if rep, err := j.Doctor(context.Background()); !errors.Is(err, ErrDoctor) || len(rep.Checks) != 4 || !strings.Contains(err.Error(), "rootfs writable") {
		t.Fatalf("weak service: %+v %v", rep, err)
	}
	fd.replies["inspect"] = fakeReply{out: hardenedEgress}
	if _, err := j.Doctor(context.Background()); err != nil {
		t.Fatalf("hardened service: %v", err)
	}
}

// egress up creates the network (with the public resolver on the container), the three volumes, initialises the policy
// volume through a hardened call, and runs the hardened service; a second up with the service running only checks.
func TestEgressUp(t *testing.T) {
	fd := newFakeDocker()
	fd.replies["network inspect"] = fakeReply{err: "Error response from daemon: network wj-egress-net not found\n", exit: 1}
	fd.replies["inspect"] = fakeReply{err: "Error: No such object: wj-egress\n", exit: 1}
	j := newTestJail(t, fd)
	if err := j.EgressUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	var run []string
	for _, c := range fd.calls {
		verbs = append(verbs, c[0]+" "+c[1])
		if c[0] == "run" {
			run = c
		}
		if c[0] == "network" && c[1] == "create" && !reflect.DeepEqual(c, []string{"network", "create", "--driver", "bridge",
			"--label", "ai.relux.worker-jail=1", "--label", "ai.relux.worker-jail.kind=egress", "wj-egress-net"}) {
			t.Errorf("network create %q", c)
		}
	}
	wantVerbs := []string{"network inspect", "network create",
		"volume inspect", "volume create", "volume inspect", "volume create", "volume inspect", "volume create",
		"volume inspect", "create --rm", "start -a", "inspect --type", "run -d"}
	if !reflect.DeepEqual(verbs, wantVerbs) {
		t.Fatalf("docker calls\n got %q\nwant %q", verbs, wantVerbs)
	}
	for _, v := range []string{EgressSockVolume, EgressPolicyVolume, EgressCacheVolume} {
		if fd.volumes[v][LabelKind] != KindEgress {
			t.Errorf("volume %s: %v", v, fd.volumes[v])
		}
	}
	if calls := egressCalls(fd); len(calls) != 1 || calls[0].argv()[4] != "init" || !hasPair(calls[0].create, "--label", LabelProject+"="+egressProject) {
		t.Fatalf("init call %v", calls)
	}
	want := []string{"run", "-d", "--name", "wj-egress", "--label", "ai.relux.worker-jail=1", "--label", "ai.relux.worker-jail.kind=egress",
		"--network", "wj-egress-net", "--dns", "1.1.1.1",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10002:10002",
		"--cpus", "1", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "256",
		"--ulimit", "nofile=8192:8192", "--ulimit", "core=0:0",
		"--log-driver", "local", "--log-opt", "max-size=20m", "--log-opt", "max-file=5", "--restart", "unless-stopped",
		"--mount", "type=volume,src=wj-egress-sock,dst=/egress/sock",
		"--mount", "type=volume,src=wj-egress-policy,dst=/egress/policy,readonly",
		"--mount", "type=volume,src=wj-egress-cache,dst=/egress/cache",
		"worker-jail/egress:1", "serve", "--sockroot", "/egress/sock", "--policydir", "/egress/policy", "--cachedir", "/egress/cache"}
	if !reflect.DeepEqual(run, want) {
		t.Fatalf("run args\n got %q\nwant %q", run, want)
	}
	ok, d := checkEgressHardening(hardenedEgress)
	if !ok {
		t.Fatal(d)
	}

	// Second up: network and volumes exist, the service runs: no create, no run.
	fd.replies["network inspect"] = fakeReply{out: "wj-egress-net\n"}
	fd.replies["inspect"] = fakeReply{out: "running\n"}
	n := len(fd.calls)
	if err := j.EgressUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range fd.calls[n:] {
		if c[0] == "run" || c[1] == "create" && c[0] != "create" {
			t.Errorf("second up: %q", c)
		}
	}
	// A stopped service is started, not run again.
	fd.replies["inspect"] = fakeReply{out: "exited\n"}
	if err := j.EgressUp(context.Background()); err != nil || fd.count("start wj-egress") != 1 {
		t.Fatalf("stopped service: %v", err)
	}
	if err := j.EgressDown(context.Background()); err != nil || fd.count("rm -f wj-egress") != 1 {
		t.Fatalf("down: %v", err)
	}
}

// egress log keeps only the JSON lines of the requested project and worker; status reports each network policy's
// stored and loaded ids.
func TestEgressLogAndStatus(t *testing.T) {
	fd := egressFake(t)
	fd.replies["logs"] = fakeReply{out: `{"ts":"1","project":"p1","worker":"w1","path":"/gomod/a"}
{"ts":"2","project":"p1","worker":"w2","path":"/gomod/b"}
{"ts":"3","project":"p2","worker":"w1","path":"/gomod/c"}
{"ts":"4","event":"policy-dir-unreadable"}
not json
`}
	j := newTestJail(t, fd)
	for _, c := range []struct {
		f    EgressLogFilter
		want string
	}{
		{EgressLogFilter{}, "1234"},
		{EgressLogFilter{Project: "p1"}, "12"},
		{EgressLogFilter{Project: "p1", Worker: "w1"}, "1"},
		{EgressLogFilter{Worker: "w1", Since: "10m"}, "13"},
	} {
		var out bytes.Buffer
		if err := j.EgressLog(context.Background(), c.f, &out); err != nil {
			t.Fatal(err)
		}
		got := ""
		for _, l := range splitLines(out.String()) {
			got += l[7:8]
		}
		if got != c.want {
			t.Errorf("%+v: %q", c.f, out.String())
		}
	}
	if fd.count("logs --since 10m wj-egress") != 1 {
		t.Fatal("--since not passed")
	}
	if err := j.EgressLog(context.Background(), EgressLogFilter{Since: "--follow"}, &bytes.Buffer{}); err == nil {
		t.Fatal("flag injection through --since")
	}

	id := storePolicy(t, j, "p1", "w1", modulesPolicy(t, "p1", "w1"))
	storePolicy(t, j, "p1", "w2", testPolicy("p1", "w2"))
	fd.loaded["p1.w1"] = id
	fd.replies["inspect"] = fakeReply{out: "running\n"}
	rep, err := j.EgressStatus(context.Background())
	if err != nil || rep.State != "running" || len(rep.Workers) != 1 || rep.Workers[0].Stored != id || rep.Workers[0].Loaded != id {
		t.Fatalf("status %+v %v", rep, err)
	}
}
