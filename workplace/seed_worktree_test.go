package workplace

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// moduleRepo is a repository with a committed Go module that has no dependencies (nothing to download).
func moduleRepo(t *testing.T) string {
	t.Helper()
	dir := newRepo(t)
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	commitAll(t, dir, "module")
	return dir
}

// goModRefusal refuses a toolchain line and every filesystem replace (single line or block, relative, absolute,
// quoted), and accepts module replacements, comments and ordinary directives.
func TestGoModRefusal(t *testing.T) {
	for _, c := range []struct {
		mod, want string // want "" means accepted
	}{
		{"module m\ngo 1.21\nrequire example.com/a v1.0.0\n", ""},
		{"module m\nreplace example.com/a => example.com/b v1.2.3\n", ""},
		{"module m\nreplace example.com/a v1.0.0 => example.com/b v1.2.3 // pinned\n", ""},
		{"module m\n// replace example.com/a => ../a\n", ""},
		{"module m\nreplace (\n\texample.com/a => example.com/b v1.0.0\n)\n", ""},
		{"module m\nreplace example.com/a => ./a\n", "replace to a filesystem path"},
		{"module m\nreplace example.com/a v1.0.0 => ../a\n", "replace to a filesystem path"},
		{"module m\nreplace example.com/a => /Users/someone/src/a\n", "replace to a filesystem path"},
		{"module m\nreplace example.com/a => \"../a b\"\n", "replace to a filesystem path"},
		{"module m\nreplace (\n\texample.com/b => example.com/c v1.0.0\n\texample.com/a => ../a\n)\n", "replace to a filesystem path"},
		{"module m\ngo 1.21\ntoolchain go1.25.0\n", "toolchain line"},
	} {
		if got := goModRefusal(c.mod); c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%q: %q, want %q", c.mod, got, c.want)
		}
	}
}

// The Go commands of a worktree seed get a fixed environment: no host variable but PATH, so no credentials,
// GOPRIVATE, GOFLAGS, NETRC or HOME of the owner; the public proxy only; HOME and caches under the temp dir.
func TestWorktreeGoEnv(t *testing.T) {
	for k, v := range map[string]string{"GOPRIVATE": "corp.example", "GONOPROXY": "corp.example", "GONOSUMDB": "corp.example",
		"GOFLAGS": "-insecure", "NETRC": "/Users/x/.netrc", "GH_TOKEN": "secret", "GOPROXY": "https://corp.example", "GOINSECURE": "*"} {
		t.Setenv(k, v)
	}
	tmp := t.TempDir()
	env, err := worktreeGoEnv(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range []string{"GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly -modcacherw", "GOENV=off", "GOPRIVATE=", "GONOPROXY=",
		"GOPROXY=https://proxy.golang.org", "GOWORK=off", "GOAUTH=off", "CGO_ENABLED=0", "HOME=" + filepath.Join(tmp, "home"),
		"GOCACHE=" + filepath.Join(tmp, "gocache"), "GOMODCACHE=" + filepath.Join(tmp, "mod")} {
		if !slices.Contains(env, kv) {
			t.Errorf("missing %s", kv)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains([]string{"GONOSUMDB", "NETRC", "GH_TOKEN", "GOINSECURE", "GOSUMDB", "SSH_AUTH_SOCK"}, name) ||
			strings.Contains(kv, "corp.example") || strings.Contains(kv, "secret") {
			t.Errorf("leaked %s", kv)
		}
	}
}

// Each refusal of seed-gomod --from-worktree is ErrSeed (or the snapshot's own refusal) and happens before any
// docker call; the source stays unchanged. The dirty states are what an unreviewed worktree could hold.
func TestSeedGoModWorktreeRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(dir string)
		is    error
		want  string
	}{
		{"filesystem replace", func(d string) {
			writeFile(t, filepath.Join(d, "go.mod"), "module example.com/m\n\ngo 1.21\n\nreplace example.com/a => ../a\n")
		}, ErrSeed, "go.mod: replace to a filesystem path"},
		{"filesystem replace in a nested module", func(d string) {
			writeFile(t, filepath.Join(d, "tools", "go.mod"), "module example.com/tools\n\nreplace example.com/a => /tmp/a\n")
		}, ErrSeed, "tools/go.mod: replace"},
		{"go.work", func(d string) { writeFile(t, filepath.Join(d, "go.work"), "go 1.21\n\nuse .\n") }, ErrSeed, "go.work"},
		{"toolchain", func(d string) {
			writeFile(t, filepath.Join(d, "go.mod"), "module example.com/m\n\ngo 1.21\n\ntoolchain go1.25.0\n")
		}, ErrSeed, "toolchain line"},
		{"vendor disagrees", func(d string) {
			writeFile(t, filepath.Join(d, "go.mod"), "module example.com/m\n\ngo 1.21\n\nrequire example.com/a v1.0.0\n")
			writeFile(t, filepath.Join(d, "vendor", "modules.txt"), "# example.com/a v1.1.0\n## explicit\nexample.com/a\n")
			writeFile(t, filepath.Join(d, "vendor", "example.com", "a", "a.go"), "package a\n")
		}, ErrSeed, "vendor/ disagrees with go.mod"},
		{"no go.mod", func(d string) { git(t, d, "rm", "-q", "go.mod") }, ErrSeed, "no go.mod"},
		{"secret", func(d string) { writeFile(t, filepath.Join(d, ".netrc"), "machine x\n") }, ErrSecret, ".netrc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := moduleRepo(t)
			c.setup(dir)
			before := fingerprint(t, dir)
			fd := newFakeDocker()
			j := newTestWorkplace(t, fd)
			_, err := j.SeedGoModWorktree(context.Background(), "p1", dir, SnapshotOptions{})
			if !errors.Is(err, c.is) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %v %q", err, c.is, c.want)
			}
			if len(fd.calls) != 0 {
				t.Fatalf("docker used: %v", fd.calls)
			}
			sameFingerprint(t, before, fingerprint(t, dir))
		})
	}
}

// Control: a dirty module (unlanded go.mod change, untracked package, a vendor/ that agrees) seeds cache gomod
// offline (no dependencies), the source is unchanged, the cache records the snapshot tree, which ls shows, and no
// temporary directory survives.
func TestSeedGoModWorktree(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // the snapshot's temporary directory goes here
	dir := moduleRepo(t)
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.22\n")
	writeFile(t, filepath.Join(dir, "lib", "lib.go"), "package lib\n")
	writeFile(t, filepath.Join(dir, "vendor", "modules.txt"), "")
	before := fingerprint(t, dir)
	fd := newFakeDocker()
	j := newTestWorkplace(t, fd)
	tree, err := j.SeedGoModWorktree(context.Background(), "p1", dir, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sameFingerprint(t, before, fingerprint(t, dir))
	if want, _ := SnapshotTree(context.Background(), dir); tree != want {
		t.Fatalf("tree %s, want %s", tree, want)
	}
	if fd.count("volume create") != 1 || len(fd.starts) != 1 || fd.starts[0].argv()[0] != "tar" {
		t.Fatalf("seed calls %v", fd.calls)
	}
	l, err := j.List(context.Background(), "p1")
	if err != nil || len(l.Caches) != 1 || l.Caches[0].Name != "gomod" || l.Caches[0].SnapshotTree != tree {
		t.Fatalf("ls %+v %v", l, err)
	}
	if err := j.Purge(context.Background(), "p1"); err != nil || exists(j.seedPath("p1", "gomod")) {
		t.Fatalf("purge left the seed record: %v", err)
	}
	time.Sleep(time.Second) // a go telemetry process would write after the seed returned
	if left, _ := filepath.Glob(filepath.Join(tmp, "rwp-snapshot-*")); len(left) > 0 {
		t.Fatalf("temporary directories left behind: %v", left)
	}
}
