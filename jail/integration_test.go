package jail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Integration tests run against the real workers VM (WJ_IT=1, images from `make image`).
// Every project is named wjit-* and purged at the end, even on failure.

func itJail(t *testing.T, image string) *Jail {
	t.Helper()
	if os.Getenv("WJ_IT") != "1" {
		t.Skip("set WJ_IT=1 to run integration tests against the workers VM")
	}
	j, err := New(Config{StateDir: t.TempDir(), Image: image})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// vmPolicy stores the policy the VM suites provision under: the v1 call shape (yolo, read-write, network none)
// with the jail's default limits, the protocol's maximum timeout and a 64 MiB output cap. Run re-reads it,
// so a second Jail on another state dir needs it too; the same bytes give the same id.
func vmPolicy(t *testing.T, j *Jail, r Ref) {
	t.Helper()
	data := []byte(`{"version":1,"project":"` + r.Project + `","worker":"` + r.Worker + `","tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},"network":{"mode":"none"},
 "limits":{"cpus":2,"memory_mib":2048,"pids":512,"call_timeout_s":3600,"max_output_bytes":67108864,"disk_soft_mib":4096}}`)
	if _, err := j.SetPolicy(context.Background(), r, data, SetPolicyOptions{}); err != nil {
		t.Fatalf("policy %v: %v", r, err)
	}
}

func itProject(t *testing.T, j *Jail) string {
	t.Helper()
	b := make([]byte, 4)
	rand.Read(b)
	p := "wjit-" + hex.EncodeToString(b)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := j.Purge(ctx, p); err != nil {
			t.Errorf("purge %s: %v", p, err)
		}
		if l, err := j.List(ctx, p); err != nil || len(l.Workspaces)+len(l.Caches) != 0 {
			t.Errorf("leftovers for %s: %+v %v", p, l, err)
		}
	})
	return p
}

func itRun(t *testing.T, j *Jail, r Ref, stdin string, argv ...string) Result {
	t.Helper()
	var in *strings.Reader
	if stdin != "" {
		in = strings.NewReader(stdin)
	}
	s := RunSpec{Argv: argv, Timeout: 5 * time.Minute}
	if in != nil {
		s.Stdin = in
	}
	res, err := j.Run(context.Background(), r, s)
	if err != nil {
		t.Fatalf("run %q: %v", argv, err)
	}
	return res
}

// Doctor passes against the real workers VM.
func TestIntegrationDoctor(t *testing.T) {
	j := itJail(t, "")
	rep, err := j.Doctor(context.Background())
	if err != nil {
		t.Fatalf("%v %+v", err, rep)
	}
}

// Provision → run → export → apply → deprovision: the full change path of the protocol.
func TestIntegrationMainFlow(t *testing.T) {
	j := itJail(t, "")
	ctx := context.Background()
	repo, _ := filepath.Abs("..")
	r := Ref{itProject(t, j), "w1"}
	vmPolicy(t, j, r)
	ws, err := j.Provision(ctx, ProvisionSpec{Ref: r, Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if head := git(t, repo, "rev-parse", "HEAD"); ws.Base != head {
		t.Fatalf("base %s, HEAD %s", ws.Base, head)
	}
	if again, err := j.Provision(ctx, ProvisionSpec{Ref: r, Repo: repo}); err != nil || !again.Existed || again.Base != ws.Base {
		t.Fatalf("idempotent provision: %+v %v", again, err)
	}
	if res := itRun(t, j, r, "", "git", "rev-parse", "HEAD"); strings.TrimSpace(string(res.Stdout)) != ws.Base || res.Exit != 0 {
		t.Fatalf("in-jail HEAD %q (exit %d)", res.Stdout, res.Exit)
	}
	if res := itRun(t, j, r, "hello from the jail\n", "sh", "-c", "cat > new.txt"); res.Exit != 0 {
		t.Fatalf("write: %+v", res)
	}
	var patch bytes.Buffer
	info, err := j.Export(ctx, r, &patch)
	if err != nil {
		t.Fatal(err)
	}
	if info.Base != ws.Base || !strings.Contains(patch.String(), "diff --git a/new.txt b/new.txt") {
		t.Fatalf("patch %q", patch.String())
	}
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, filepath.Dir(clone), "clone", "-q", repo, clone)
	git(t, clone, "checkout", "-q", "--detach", ws.Base)
	if _, err := Apply(ctx, clone, bytes.NewReader(patch.Bytes()), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(clone, "new.txt")); string(b) != "hello from the jail\n" {
		t.Fatalf("applied new.txt %q", b)
	}
	itRun(t, j, r, "", "sh", "-c", "echo more >> new.txt")
	if err := j.Deprovision(ctx, r, false); !errors.Is(err, ErrUnexported) {
		t.Fatalf("unexported deprovision: %v", err)
	}
	if err := j.Deprovision(ctx, r, true); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Run(ctx, r, RunSpec{Argv: []string{"true"}}); !errors.Is(err, ErrNoWorkspace) {
		t.Fatalf("workspace survived deprovision: %v", err)
	}
}

func itWorkspace(t *testing.T, j *Jail) Ref {
	t.Helper()
	repo, _ := filepath.Abs("..")
	r := Ref{itProject(t, j), "w1"}
	vmPolicy(t, j, r)
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: r, Repo: repo}); err != nil {
		t.Fatal(err)
	}
	return r
}

// A call past its timeout is killed and its container is gone within 5 s.
func TestIntegrationTimeout(t *testing.T) {
	j := itJail(t, "")
	r := itWorkspace(t, j)
	res, err := j.Run(context.Background(), r, RunSpec{Argv: []string{"sleep", "600"}, Timeout: 2 * time.Second})
	if err != nil || !res.TimedOut {
		t.Fatalf("res %+v err %v", res, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := j.List(context.Background(), r.Project)
		if err != nil {
			t.Fatal(err)
		}
		if len(l.Calls) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("containers remain: %+v", l.Calls)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// An output flood is killed and reported Truncated with the output capped.
func TestIntegrationFlood(t *testing.T) {
	j := itJail(t, "")
	r := itWorkspace(t, j)
	res, err := j.Run(context.Background(), r, RunSpec{Argv: []string{"yes"}, MaxOutput: 65536, Timeout: time.Minute})
	if err != nil || !res.Truncated || res.TimedOut || len(res.Stdout) != 65536 {
		t.Fatalf("truncated=%v timedout=%v len=%d err=%v", res.Truncated, res.TimedOut, len(res.Stdout), err)
	}
}

// A background process started by one call does not survive into the next.
func TestIntegrationNoSurvivor(t *testing.T) {
	j := itJail(t, "")
	r := itWorkspace(t, j)
	itRun(t, j, r, "", "sh", "-c", "nohup sleep 1000 >/dev/null 2>&1 &")
	res := itRun(t, j, r, "", "ps", "-eo", "comm")
	if res.Exit != 0 || !strings.Contains(string(res.Stdout), "ps") {
		t.Fatalf("control: ps did not list itself: %q", res.Stdout)
	}
	if strings.Contains(string(res.Stdout), "sleep") {
		t.Fatalf("sleep survived: %q", res.Stdout)
	}
}

// A seeded gomod cache makes an offline Go build and test pass; control: without the seed it fails.
func TestIntegrationGoOffline(t *testing.T) {
	j := itJail(t, "worker-jail/go:2")
	ctx := context.Background()
	repo := newRepo(t)
	writeFile(t, filepath.Join(repo, "go.mod"), "module example.com/m\n\ngo 1.25\n")
	writeFile(t, filepath.Join(repo, "main.go"), `package main

import "golang.org/x/sync/errgroup"

func main() { var g errgroup.Group; g.Go(func() error { return nil }); _ = g.Wait() }
`)
	writeFile(t, filepath.Join(repo, "main_test.go"), "package main\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n")
	tidy := exec.Command("go", "get", "golang.org/x/sync@v0.10.0")
	tidy.Dir, tidy.Env = repo, append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("host go get: %v %s", err, out)
	}
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "module")

	seeded := Ref{itProject(t, j), "w1"}
	bare := Ref{itProject(t, j), "w1"}
	for _, r := range []Ref{seeded, bare} {
		vmPolicy(t, j, r)
		if _, err := j.Provision(ctx, ProvisionSpec{Ref: r, Repo: repo}); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.SeedGoMod(ctx, seeded.Project, repo, "HEAD"); err != nil {
		t.Fatal(err)
	}
	build := []string{"sh", "-c", "go build ./... && go test ./..."} // default TMPDIR=/tmp must be exec
	if res := itRun(t, j, seeded, "", build...); res.Exit != 0 {
		t.Fatalf("seeded build failed (exit %d): %s%s", res.Exit, res.Stdout, res.Stderr)
	}
	if res := itRun(t, j, bare, "", build...); res.Exit == 0 {
		t.Fatalf("control: unseeded build succeeded offline: %s", res.Stdout)
	}
}

// v2.1 part A: `go mod download` of a small public module through the egress service (VM and internet only; needs
// `worker-jail egress up` and the base image v2 with socat). policy set confirms the id, the listed module downloads
// through the relay and the service, the egress log names the worker; control: an unlisted module is refused.
func TestIntegrationEgressModules(t *testing.T) {
	j := itJail(t, "worker-jail/go:2")
	ctx := context.Background()
	if state, err := j.egressState(ctx); err != nil || state != "running" {
		t.Fatalf("the egress service is not running (worker-jail egress up): %q %v", state, err)
	}
	r := Ref{itProject(t, j), "w1"}
	t.Cleanup(func() {
		if err := j.RemovePolicy(r); err != nil {
			t.Errorf("withdraw %v: %v", r, err)
		}
	})
	data := modulesPolicy(t, r.Project, r.Worker, `golang\.org/x/sync`)
	if _, err := j.SetPolicy(ctx, r, data, SetPolicyOptions{}); err != nil {
		t.Fatalf("policy set: %v", err)
	}
	if _, err := j.Provision(ctx, ProvisionSpec{Ref: r, Repo: newRepo(t)}); err != nil {
		t.Fatal(err)
	}
	res := itRun(t, j, r, "", "go", "mod", "download", "-json", "golang.org/x/sync@v0.10.0")
	if res.Exit != 0 || !strings.Contains(string(res.Stdout), `"Version": "v0.10.0"`) || !strings.Contains(string(res.Stdout), `"Zip": "/work/home/go/pkg/mod/`) {
		t.Fatalf("download failed (exit %d): %s%s", res.Exit, res.Stdout, res.Stderr)
	}
	res = itRun(t, j, r, "", "go", "mod", "download", "-json", "golang.org/x/text@v0.14.0")
	if res.Exit == 0 || !strings.Contains(string(res.Stdout)+string(res.Stderr), "403") {
		t.Fatalf("control: unlisted module downloaded (exit %d): %s%s", res.Exit, res.Stdout, res.Stderr)
	}
	var log bytes.Buffer
	if err := j.EgressLog(ctx, EgressLogFilter{Project: r.Project, Worker: r.Worker}, &log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), `"path":"/gomod/golang.org/x/sync/@v/v0.10.0.zip"`) || !strings.Contains(log.String(), `"code":"module"`) {
		t.Fatalf("egress log: %s", log.String())
	}
}

// v2.1: an allowlist policy for proxy.golang.org:443 (VM and internet only; needs `worker-jail egress up` and the
// redteam image, the only image with curl; the call's hardening is the same). policy set confirms the id; curl reaches
// https://proxy.golang.org/ through HTTPS_PROXY, the relay and a CONNECT tunnel; https://example.com/ gets 403 host; the
// egress log names both decisions. No TLS interception: the service sees only host and port.
func TestIntegrationEgressAllowlist(t *testing.T) {
	j := itJail(t, rtImage)
	ctx := context.Background()
	if state, err := j.egressState(ctx); err != nil || state != "running" {
		t.Fatalf("the egress service is not running (worker-jail egress up): %q %v", state, err)
	}
	r := Ref{itProject(t, j), "w1"}
	t.Cleanup(func() {
		if err := j.RemovePolicy(r); err != nil {
			t.Errorf("withdraw %v: %v", r, err)
		}
	})
	data := mut(t, string(testPolicy(r.Project, r.Worker)), set("note", "integration: the Go module proxy only"),
		set("network", map[string]any{"mode": NetAllowlist, "hosts": []string{`proxy\.golang\.org`}, "ports": []any{443},
			"rate": map[string]any{"requests_per_min": 600, "max_conns": 8, "bytes_per_day": 1 << 30}}))
	sp, err := j.SetPolicy(ctx, r, data, SetPolicyOptions{})
	if err != nil || sp.Risk.Level != RiskHigh {
		t.Fatalf("policy set: %v (risk %s)", err, sp.Risk.Level)
	}
	if _, err := j.Provision(ctx, ProvisionSpec{Ref: r, Repo: newRepo(t)}); err != nil {
		t.Fatal(err)
	}
	res := itRun(t, j, r, "", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://proxy.golang.org/")
	if code := strings.TrimSpace(string(res.Stdout)); res.Exit != 0 || code == "" || code == "000" {
		t.Fatalf("curl https://proxy.golang.org/ (exit %d): %s%s", res.Exit, res.Stdout, res.Stderr)
	}
	res = itRun(t, j, r, "", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_connect}", "https://example.com/")
	if res.Exit == 0 || !strings.Contains(string(res.Stdout)+string(res.Stderr), "403") {
		t.Fatalf("control: https://example.com/ was not refused (exit %d): %s%s", res.Exit, res.Stdout, res.Stderr)
	}
	var log bytes.Buffer
	if err := j.EgressLog(ctx, EgressLogFilter{Project: r.Project, Worker: r.Worker}, &log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), `"handler":"connect","method":"CONNECT","host":"proxy.golang.org","port":443`) ||
		!strings.Contains(log.String(), `"host":"example.com","port":443,"path":"","decision":"deny","code":"host"`) {
		t.Fatalf("egress log: %s", log.String())
	}
}
