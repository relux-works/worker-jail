package jail

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func hasPair(args []string, a, b string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == a && args[i+1] == b {
			return true
		}
	}
	return false
}

// Argv and stdin reach docker, stdout/stderr/exit come back, and the call is labelled for its worker.
func TestRunPassesArgvAndStdin(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.onStart = func(c *fakeCall) int {
		in := readAll(c.stdin)
		c.stdout.Write([]byte("got:" + string(in)))
		c.stderr.Write([]byte("warn"))
		return 7
	}
	j := newTestJail(t, fd)
	res, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"sh", "-c", "cat"}, Stdin: strings.NewReader("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "got:hello" || string(res.Stderr) != "warn" || res.Exit != 7 || res.TimedOut || res.Truncated {
		t.Fatalf("unexpected result %+v", res)
	}
	c := fd.starts[0]
	if !reflect.DeepEqual(c.argv(), []string{"sh", "-c", "cat"}) {
		t.Fatalf("argv %q", c.argv())
	}
	if !hasPair(c.create, "--label", LabelWorker+"=w1") || !hasPair(c.create, "-w", "/work/src") || !hasPair(c.create, "timeout", "-s") {
		t.Fatalf("create args %q", c.create)
	}
	if len(fd.kills) != 0 {
		t.Fatalf("normal exit issued kill %v", fd.kills)
	}
}

// A call that outlives its timeout is killed with docker kill and reported TimedOut, not as a jail error.
func TestRunTimeoutKills(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.onStart = func(c *fakeCall) int { <-c.killed; return 137 }
	j := newTestJail(t, fd)
	res, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"sleep", "600"}, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Exit != 137 || len(fd.kills) != 1 {
		t.Fatalf("res %+v kills %v", res, fd.kills)
	}
}

// Output beyond MaxOutput kills the call and sets Truncated; only MaxOutput bytes are kept.
func TestRunFloodTruncates(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.onStart = func(c *fakeCall) int {
		buf := []byte(strings.Repeat("y\n", 512))
		for {
			select {
			case <-c.killed:
				return 137
			default:
				c.stdout.Write(buf)
			}
		}
	}
	j := newTestJail(t, fd)
	res, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"yes"}, MaxOutput: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || res.TimedOut || len(res.Stdout) != 4096 || len(fd.kills) != 1 {
		t.Fatalf("truncated=%v len=%d kills=%v", res.Truncated, len(res.Stdout), fd.kills)
	}
}

// Output exactly at the cap is not truncated (control for the flood test).
func TestRunAtCapNotTruncated(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.onStart = func(c *fakeCall) int { c.stdout.Write(make([]byte, 100)); return 0 }
	j := newTestJail(t, fd)
	res, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"x"}, MaxOutput: 100})
	if err != nil || res.Truncated || len(res.Stdout) != 100 {
		t.Fatalf("res %+v err %v", res, err)
	}
}

// Cancelling ctx kills the container and returns an error.
func TestRunCancelKills(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.onStart = func(c *fakeCall) int { <-c.killed; return 137 }
	j := newTestJail(t, fd)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := j.Run(ctx, Ref{"p1", "w1"}, RunSpec{Argv: []string{"sleep"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if len(fd.kills) != 1 {
		t.Fatalf("kills %v", fd.kills)
	}
}

// Bad input and a missing workspace fail before any container is created.
func TestRunRejectsBeforeCreate(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	j := newTestJail(t, fd)
	storePolicy(t, j, "p1", "nope", testPolicy("p1", "nope"))
	ctx := context.Background()
	cases := []struct {
		ref  Ref
		spec RunSpec
		want error
	}{
		{Ref{"p1", "nope"}, RunSpec{Argv: []string{"true"}}, ErrNoWorkspace},
		{Ref{"P1", "w1"}, RunSpec{Argv: []string{"true"}}, ErrInvalidName},
		{Ref{"p1", "w1"}, RunSpec{}, nil},
		{Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}, Timeout: 61 * time.Minute}, nil},
		{Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}, MaxOutput: -1}, nil},
	}
	for i, c := range cases {
		_, err := j.Run(ctx, c.ref, c.spec)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("case %d: err %v, want %v", i, err, c.want)
		}
	}
	if n := fd.count("create"); n != 0 {
		t.Fatalf("%d containers created for rejected input", n)
	}
	if _, err := j.Run(ctx, Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}, Timeout: 60 * time.Minute}); err != nil {
		t.Fatalf("control: valid run failed: %v", err)
	}
}

// A failed docker create is a jail error carrying docker's stderr.
func TestRunCreateFailure(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.createErr = "Error: image not found"
	j := newTestJail(t, fd)
	_, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "image not found") {
		t.Fatalf("err %v", err)
	}
}

// The project's caches are discovered and mounted read-only; Go env is set only with a gomod cache.
func TestRunCachesAndGoEnv(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	addCache(fd, "p1", "npm")
	addCache(fd, "p2", "gomod") // another project's cache must not appear
	j := newTestJail(t, fd)
	ctx := context.Background()
	if _, err := j.Run(ctx, Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	a := fd.starts[0].create
	if !hasPair(a, "--mount", "type=volume,src=wj-cache.p1.npm,dst=/cache/npm,readonly") {
		t.Fatalf("npm cache not mounted ro: %q", a)
	}
	if strings.Contains(strings.Join(a, " "), "p2") || strings.Contains(strings.Join(a, " "), "GOMODCACHE") {
		t.Fatalf("foreign cache or Go env without gomod: %q", a)
	}
	addCache(fd, "p1", "gomod")
	if _, err := j.Run(ctx, Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	a = fd.starts[1].create
	if !hasPair(a, "--mount", "type=volume,src=wj-cache.p1.gomod,dst=/cache/gomod,readonly") || !hasPair(a, "-e", "GOPROXY=off") {
		t.Fatalf("gomod cache/env missing: %q", a)
	}
	if strings.Contains(strings.Join(a, " "), "GOFLAGS") {
		t.Fatalf("GOFLAGS is the image's policy, jail must not set it: %q", a)
	}
}

// cappedWriter keeps max bytes, counts the rest and signals once.
func TestCappedWriter(t *testing.T) {
	var sb strings.Builder
	ch := make(chan struct{}, 4)
	c := &cappedWriter{w: &sb, max: 5, overflow: ch, once: new(sync.Once)}
	io.WriteString(c, "abc")
	io.WriteString(c, "defg")
	io.WriteString(c, "h")
	if sb.String() != "abcde" || c.n != 8 || len(ch) != 1 {
		t.Fatalf("kept %q n=%d signals=%d", sb.String(), c.n, len(ch))
	}
}

// If start never returns after kill, the call fails with an error instead of hanging; control: a start that honours kill returns TimedOut.
func TestRunKillWaitBounded(t *testing.T) {
	old := killWait
	killWait = 100 * time.Millisecond
	t.Cleanup(func() { killWait = old })
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	fd.onStart = func(c *fakeCall) int { <-stuck; return 137 }
	j := newTestJail(t, fd)
	start := time.Now()
	_, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"sleep"}, Timeout: 50 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "did not stop after kill") || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
	fd.onStart = func(c *fakeCall) int { <-c.killed; return 137 }
	res, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"sleep"}, Timeout: 50 * time.Millisecond})
	if err != nil || !res.TimedOut {
		t.Fatalf("control: %+v %v", res, err)
	}
}

// Result.Duration reports the call's run time (regression: it was always 0); a 50 ms start yields ≥ 50 ms.
func TestRunReportsDuration(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.onStart = func(c *fakeCall) int { time.Sleep(50 * time.Millisecond); return 0 }
	j := newTestJail(t, fd)
	res, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}})
	if err != nil || res.Duration < 50*time.Millisecond {
		t.Fatalf("duration %v err %v", res.Duration, err)
	}
}
