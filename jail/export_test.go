package jail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

const patchText = "diff --git a/new.txt b/new.txt\nnew file mode 100644\n"

func exportStart(out string, exit int) func(c *fakeCall) int {
	return func(c *fakeCall) int { c.stdout.Write([]byte(out)); return exit }
}

// Export uses the workspace's base label, mounts it read-only, streams the patch and records its digest.
func TestExportRecordsDigest(t *testing.T) {
	fd := newFakeDocker()
	base := strings.Repeat("c", 40)
	addWorkspace(fd, "p1", "w1", base)
	fd.onStart = exportStart(patchText, 0)
	j := newTestJail(t, fd)
	var buf bytes.Buffer
	info, err := j.Export(context.Background(), Ref{"p1", "w1"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(patchText))
	if buf.String() != patchText || info.Base != base || info.Bytes != int64(len(patchText)) || info.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("info %+v out %q", info, buf.String())
	}
	c := fd.starts[0]
	if argv := c.argv(); argv[len(argv)-1] != base || !hasPair(c.create, "-w", "/work/src") ||
		!hasPair(c.create, "--mount", "type=volume,src=wj.p1.w1,dst=/work,readonly") {
		t.Fatalf("export call %q", c.create)
	}
	d, _ := os.ReadFile(j.digestPath(Ref{"p1", "w1"}))
	if strings.TrimSpace(string(d)) != info.SHA256 {
		t.Fatalf("digest file %q", d)
	}
}

// A failing export or a missing/invalid base records no digest.
func TestExportFailureRecordsNothing(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("c", 40))
	addWorkspace(fd, "p1", "w2", "HEAD; rm -rf /")
	fd.onStart = exportStart(patchText, 128)
	j := newTestJail(t, fd)
	ctx := context.Background()
	if _, err := j.Export(ctx, Ref{"p1", "w1"}, &bytes.Buffer{}); err == nil {
		t.Fatal("nonzero exit accepted")
	}
	if _, err := j.Export(ctx, Ref{"p1", "w2"}, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid base label accepted")
	}
	if _, err := j.Export(ctx, Ref{"p1", "w9"}, &bytes.Buffer{}); !errors.Is(err, ErrNoWorkspace) {
		t.Fatalf("missing workspace: %v", err)
	}
	for _, w := range []string{"w1", "w2"} {
		if _, err := os.Stat(j.digestPath(Ref{"p1", w})); !os.IsNotExist(err) {
			t.Fatalf("digest recorded for failed export %s", w)
		}
	}
}

// A patch over 64 MiB is killed and refused with ErrExportTooLarge, with no digest.
func TestExportCap(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("c", 40))
	chunk := make([]byte, 1<<20)
	fd.onStart = func(c *fakeCall) int {
		for i := 0; i < 70; i++ {
			select {
			case <-c.killed:
				return 137
			default:
				c.stdout.Write(chunk)
			}
		}
		<-c.killed
		return 137
	}
	j := newTestJail(t, fd)
	var n counter
	if _, err := j.Export(context.Background(), Ref{"p1", "w1"}, &n); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("err %v", err)
	}
	if n.n > ExportCap {
		t.Fatalf("wrote %d bytes past the cap", n.n)
	}
	if _, err := os.Stat(j.digestPath(Ref{"p1", "w1"})); !os.IsNotExist(err) {
		t.Fatal("digest recorded for oversized export")
	}
}

// Deprovision: unexported changes are refused; empty, exported (matching digest) and forced removals proceed; busy is ErrBusy.
func TestDeprovision(t *testing.T) {
	ctx := context.Background()
	r := Ref{"p1", "w1"}
	setup := func(out string) (*fakeDocker, *Jail) {
		fd := newFakeDocker()
		addWorkspace(fd, "p1", "w1", strings.Repeat("c", 40))
		fd.onStart = exportStart(out, 0)
		return fd, newTestJail(t, fd)
	}

	fd, j := setup(patchText)
	if err := j.Deprovision(ctx, r, false); !errors.Is(err, ErrUnexported) {
		t.Fatalf("unexported: %v", err)
	}
	if _, ok := fd.volumes["wj.p1.w1"]; !ok {
		t.Fatal("unexported workspace removed")
	}
	if _, err := j.Export(ctx, r, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := j.Deprovision(ctx, r, false); err != nil {
		t.Fatalf("matching digest refused: %v", err)
	}
	if _, ok := fd.volumes["wj.p1.w1"]; ok {
		t.Fatal("volume not removed")
	}
	if _, err := os.Stat(j.digestPath(r)); !os.IsNotExist(err) {
		t.Fatal("digest not removed")
	}
	if err := j.Deprovision(ctx, r, false); err != nil {
		t.Fatalf("missing workspace should be a no-op: %v", err)
	}

	fd, j = setup("")
	if err := j.Deprovision(ctx, r, false); err != nil {
		t.Fatalf("empty diff refused: %v", err)
	}

	fd, j = setup(patchText)
	if _, err := j.Export(ctx, r, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	fd.onStart = exportStart(patchText+"more", 0) // changed after the export
	if err := j.Deprovision(ctx, r, false); !errors.Is(err, ErrUnexported) {
		t.Fatalf("changed since export: %v", err)
	}

	fd, j = setup(patchText)
	if err := j.Deprovision(ctx, r, true); err != nil || len(fd.starts) != 0 {
		t.Fatalf("force: err %v starts %d", err, len(fd.starts))
	}

	fd, j = setup("")
	fd.busy["wj.p1.w1"] = true
	if err := j.Deprovision(ctx, r, true); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
}

// The export script fails on a failing pipeline stage (pipefail), not only on the last command.
func TestExportScriptPipefail(t *testing.T) {
	if !strings.HasPrefix(exportScript, "set -eu\nset -o pipefail\n") {
		t.Fatalf("script head %q", exportScript[:30])
	}
}
