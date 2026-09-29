package jail

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// List reports workspaces, caches and calls; the project filter narrows volumes.
func TestList(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	addWorkspace(fd, "p2", "w1", strings.Repeat("b", 40))
	addCache(fd, "p1", "gomod")
	fd.ps = "abc\tp1\tw1\tUp 2 seconds\n"
	j := newTestJail(t, fd)
	l, err := j.List(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Workspaces) != 1 || l.Workspaces[0].Base != strings.Repeat("a", 40) || l.Workspaces[0].Created.IsZero() ||
		len(l.Caches) != 1 || l.Caches[0].Name != "gomod" || len(l.Calls) != 1 || l.Calls[0].Status != "Up 2 seconds" {
		t.Fatalf("listing %+v", l)
	}
	if l, _ := j.List(context.Background(), ""); len(l.Workspaces) != 2 {
		t.Fatalf("all: %+v", l)
	}
	if _, err := j.List(context.Background(), "../x"); !errors.Is(err, ErrInvalidName) {
		t.Fatal(err)
	}
}

// Kill filters by project and worker, kills the found ids and counts them; nothing found means no kill.
func TestKill(t *testing.T) {
	fd := newFakeDocker()
	j := newTestJail(t, fd)
	if n, err := j.Kill(context.Background(), "p1", "w1"); n != 0 || err != nil || len(fd.kills) != 0 {
		t.Fatalf("empty: %d %v %v", n, err, fd.kills)
	}
	fd.ps = "a\nb\n"
	n, err := j.Kill(context.Background(), "p1", "w1")
	if n != 2 || err != nil || len(fd.kills) != 2 {
		t.Fatalf("n=%d err=%v kills=%v", n, err, fd.kills)
	}
	ps := fd.calls[len(fd.calls)-2]
	f := labelFilters(ps)
	if f[LabelKind] != KindCall || f[LabelProject] != "p1" || f[LabelWorker] != "w1" {
		t.Fatalf("ps filters %q", ps)
	}
	if _, err := j.Kill(context.Background(), "", "w1"); err == nil {
		t.Fatal("worker without project accepted")
	}
}

// Purge removes only the project's volumes and digests, retrying while a volume is in use.
func TestPurge(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	addCache(fd, "p1", "gomod")
	addWorkspace(fd, "p2", "w1", strings.Repeat("a", 40))
	j := newTestJail(t, fd)
	writeFile(t, j.digestPath(Ref{"p1", "w1"}), "x")
	writeFile(t, j.digestPath(Ref{"p2", "w1"}), "x")
	if err := j.Purge(context.Background(), "p1"); err != nil {
		t.Fatal(err)
	}
	if len(fd.volumes) != 1 || fd.volumes["wj.p2.w1"] == nil {
		t.Fatalf("volumes left %v", fd.volumes)
	}
	if exists(j.digestPath(Ref{"p1", "w1"})) || !exists(j.digestPath(Ref{"p2", "w1"})) {
		t.Fatal("digest cleanup wrong")
	}
	fd.busy["wj.p2.w1"] = true
	if err := j.Purge(context.Background(), "p2"); err == nil || fd.count("volume rm -f wj.p2.w1") != 10 {
		t.Fatalf("busy purge: %v, %d attempts", err, fd.count("volume rm -f wj.p2.w1"))
	}
}

// Usage runs du read-only in /work and converts KiB to bytes.
func TestUsage(t *testing.T) {
	fd := newFakeDocker()
	addWorkspace(fd, "p1", "w1", strings.Repeat("a", 40))
	fd.onStart = func(c *fakeCall) int { c.stdout.Write([]byte("220\t/work\n")); return 0 }
	j := newTestJail(t, fd)
	n, err := j.Usage(context.Background(), Ref{"p1", "w1"})
	if err != nil || n != 220*1024 || !hasPair(fd.starts[0].create, "-w", "/work") {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := j.Usage(context.Background(), Ref{"p1", "w2"}); !errors.Is(err, ErrNoWorkspace) {
		t.Fatal(err)
	}
	fd.onStart = func(c *fakeCall) int { return 1 }
	if _, err := j.Usage(context.Background(), Ref{"p1", "w1"}); err == nil {
		t.Fatal("failed du accepted")
	}
}

// SeedCache creates the labelled cache volume once and extracts the tar in a seed call.
func TestSeedCache(t *testing.T) {
	fd := newFakeDocker()
	var got []byte
	fd.onStart = func(c *fakeCall) int { got = readAll(c.stdin); return 0 }
	j := newTestJail(t, fd)
	ctx := context.Background()
	if err := j.SeedCache(ctx, "p1", "npm", strings.NewReader("TAR")); err != nil {
		t.Fatal(err)
	}
	l := fd.volumes["wj-cache.p1.npm"]
	if l[LabelKind] != KindCache || l[LabelCache] != "npm" || string(got) != "TAR" {
		t.Fatalf("labels %v stdin %q", l, got)
	}
	a := fd.starts[0].create
	if !hasPair(a, "--mount", "type=volume,src=wj-cache.p1.npm,dst=/work") || strings.Contains(strings.Join(a, " "), "src=wj.") {
		t.Fatalf("seed args %q", a)
	}
	if err := j.SeedCache(ctx, "p1", "npm", strings.NewReader("TAR")); err != nil || fd.count("volume create") != 1 {
		t.Fatalf("second seed: %v creates=%d", err, fd.count("volume create"))
	}
	fd.onStart = func(c *fakeCall) int { return 2 }
	if err := j.SeedCache(ctx, "p1", "npm", strings.NewReader("")); err == nil {
		t.Fatal("failed extraction accepted")
	}
	if err := j.SeedCache(ctx, "p1", "../x", strings.NewReader("")); !errors.Is(err, ErrInvalidName) {
		t.Fatal(err)
	}
}

// SeedGoMod builds the module cache from the base revision on the host and seeds cache "gomod" with a tar.
func TestSeedGoMod(t *testing.T) {
	repo := newRepo(t)
	writeFile(t, filepath.Join(repo, "go.mod"), "module example.com/m\n\ngo 1.25\n")
	writeFile(t, filepath.Join(repo, "main.go"), "package main\n\nfunc main() {}\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "mod")
	fd := newFakeDocker()
	var got []byte
	fd.onStart = func(c *fakeCall) int { got = readAll(c.stdin); return 0 }
	j := newTestJail(t, fd)
	if err := j.SeedGoMod(context.Background(), "p1", repo, "HEAD"); err != nil {
		t.Fatal(err)
	}
	if fd.volumes["wj-cache.p1.gomod"] == nil {
		t.Fatal("gomod cache not created")
	}
	if _, err := tar.NewReader(bytes.NewReader(got)).Next(); err != nil && err.Error() != "EOF" {
		t.Fatalf("seed stdin is not a tar: %v", err)
	}
	if err := j.SeedGoMod(context.Background(), "p1", repo, "nope"); err == nil {
		t.Fatal("unknown ref accepted")
	}
}

// untar extracts regular files and dirs, skips links without creating them, and rejects traversal and absolute paths.
func TestUntar(t *testing.T) {
	mk := func(hs ...*tar.Header) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for _, h := range hs {
			tw.WriteHeader(h)
			if h.Size > 0 {
				tw.Write(make([]byte, h.Size))
			}
		}
		tw.Close()
		return b.Bytes()
	}
	ok := mk(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755}, &tar.Header{Name: "d/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	dst := t.TempDir()
	if err := untar(bytes.NewReader(ok), dst); err != nil || !exists(filepath.Join(dst, "d", "f")) {
		t.Fatalf("control: %v", err)
	}
	for name, h := range map[string]*tar.Header{
		"dotdot": {Name: "../evil", Typeflag: tar.TypeReg, Size: 1},
		"abs":    {Name: "/etc/evil", Typeflag: tar.TypeReg, Size: 1},
		"fifo":   {Name: "p", Typeflag: tar.TypeFifo},
	} {
		d := t.TempDir()
		if err := untar(bytes.NewReader(mk(h)), d); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	links := mk(&tar.Header{Name: "s", Typeflag: tar.TypeSymlink, Linkname: "/etc"},
		&tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: "g"},
		&tar.Header{Name: "g", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	d3 := t.TempDir()
	if err := untar(bytes.NewReader(links), d3); err != nil {
		t.Fatalf("links: %v", err)
	}
	if !exists(filepath.Join(d3, "g")) || exists(filepath.Join(d3, "s")) || exists(filepath.Join(d3, "h")) {
		t.Fatal("links not skipped or regular file missing")
	}
	// writeTar round-trips through untar.
	var b bytes.Buffer
	if err := writeTar(dst, &b); err != nil {
		t.Fatal(err)
	}
	d2 := t.TempDir()
	if err := untar(&b, d2); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(d2, "d", "f")); err != nil || fi.Size() != 3 {
		t.Fatalf("round trip: %v", err)
	}
}
