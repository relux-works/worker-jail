package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/remote-workplace/egress"
	"github.com/relux-works/remote-workplace/workplace"
)

const policy = `{"version":1,"project":"p","worker":"w","tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},
 "network":{"mode":"modules","go_modules":["golang\\.org/x/.*"],"rate":{"requests_per_min":60,"max_conns":4,"bytes_per_day":1048576}},
 "limits":{"cpus":2,"memory_mib":2048,"pids":512,"call_timeout_s":600,"max_output_bytes":4194304,"disk_soft_mib":4096}}`

// status prints the loaded id (exit 0) or none (exit 3) from a running service, fails (exit 1) when the service is
// unreachable, and takes exactly one P.W (exit 2).
func TestStatus(t *testing.T) {
	root, err := os.MkdirTemp("", "rwpc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	sock, pol, cache := filepath.Join(root, "s"), filepath.Join(root, "p"), filepath.Join(root, "c")
	for _, d := range []string{sock, pol} {
		os.MkdirAll(d, 0o755)
	}
	if err := os.WriteFile(filepath.Join(pol, "p.w.json"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := workplace.ParsePolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := egress.New(egress.Config{SockRoot: sock, PolicyDir: pol, CacheDir: cache, Log: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- svc.Serve(ctx, nil) }()
	status := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"status", "--cachedir", cache}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, _ := status("p.w"); code == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, out := status("p.w"); code != 0 || strings.TrimSpace(out) != p.ID() {
		t.Fatalf("loaded: %d %q", code, out)
	}
	if code, out := status("p.other"); code != 3 || strings.TrimSpace(out) != "none" {
		t.Fatalf("not loaded: %d %q", code, out)
	}
	if code, _ := status(); code != 2 {
		t.Fatalf("no P.W: %d", code)
	}
	if code, _ := status("p.w", "extra"); code != 2 {
		t.Fatalf("two args: %d", code)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code, out := status("p.w"); code != 1 || !strings.Contains(out, "unreachable") {
		t.Fatalf("stopped service: %d %q", code, out)
	}
	if code, _ := status("../etc"); code != 1 {
		t.Fatalf("invalid P.W: %d", code)
	}
}
