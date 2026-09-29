package jail

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testName = "wj-call-0123456789abcdef"

func baseSpec(sh shape) callSpec {
	return callSpec{Shape: sh, Name: testName, Project: "p1", Worker: "w1", Workdir: "/work/src",
		Image: DefaultImage, Limits: DefaultLimits, Timeout: 10 * time.Minute, Argv: []string{"make", "test"}}
}

func hardening(worker string) []string {
	a := []string{"create", "--rm", "-i", "--init", "--name", testName,
		"--label", "ai.relux.worker-jail=1", "--label", "ai.relux.worker-jail.kind=call",
		"--label", "ai.relux.worker-jail.project=p1"}
	if worker != "" {
		a = append(a, "--label", "ai.relux.worker-jail.worker="+worker)
	}
	return append(a, "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=536870912", "--user", "10001:10001", "--cpus", "2",
		"--memory", "2147483648", "--memory-swap", "2147483648", "--pids-limit", "512",
		"--ulimit", "nofile=4096:4096", "--ulimit", "fsize=2147483648:2147483648", "--ulimit", "core=0:0",
		"--log-driver", "none")
}

// Golden argv for every spec shape: the exact flags and order of the brief.
func TestCreateArgsGolden(t *testing.T) {
	call := baseSpec(shapeCall)
	call.Caches = []string{"npm", "gomod"}
	ro := baseSpec(shapeReadOnly)
	ro.Workdir, ro.Timeout, ro.Argv = "/work", 1500*time.Millisecond, []string{"du", "-skx", "/work"}
	seed := baseSpec(shapeSeed)
	seed.Worker, seed.Cache, seed.Workdir, seed.Argv = "", "gomod", "/work", []string{"tar", "-x", "-f", "-", "-C", "/work"}
	plain := baseSpec(shapeCall)

	tail := func(xs ...string) []string { return xs }
	cases := []struct {
		name string
		spec callSpec
		want []string
	}{
		{"call with caches", call, append(hardening("w1"), tail(
			"--mount", "type=volume,src=wj.p1.w1,dst=/work",
			"--mount", "type=volume,src=wj-cache.p1.gomod,dst=/cache/gomod,readonly",
			"--mount", "type=volume,src=wj-cache.p1.npm,dst=/cache/npm,readonly",
			"-w", "/work/src", "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp",
			"-e", "GOMODCACHE=/cache/gomod", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local",
			DefaultImage, "timeout", "-s", "KILL", "605", "make", "test")...)},
		{"call without caches", plain, append(hardening("w1"), tail(
			"--mount", "type=volume,src=wj.p1.w1,dst=/work",
			"-w", "/work/src", "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp",
			DefaultImage, "timeout", "-s", "KILL", "605", "make", "test")...)},
		{"read-only", ro, append(hardening("w1"), tail(
			"--mount", "type=volume,src=wj.p1.w1,dst=/work,readonly",
			"-w", "/work", "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp",
			DefaultImage, "timeout", "-s", "KILL", "7", "du", "-skx", "/work")...)},
		{"seed", seed, append(hardening(""), tail(
			"--mount", "type=volume,src=wj-cache.p1.gomod,dst=/work",
			"-w", "/work", "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp",
			DefaultImage, "timeout", "-s", "KILL", "605", "tar", "-x", "-f", "-", "-C", "/work")...)},
	}
	for _, c := range cases {
		got, err := createArgs(c.spec)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// checkForbidden reports any flag before the image that could weaken the boundary.
func forbidden(args []string, image string) []string {
	var bad []string
	end := -1
	for i, a := range args {
		if a == image && i > 0 && args[i-1] != "--name" {
			end = i
			break
		}
	}
	if end < 0 {
		return []string{"image not found"}
	}
	for i := 0; i < end; i++ {
		a, v := args[i], ""
		if i+1 < end {
			v = args[i+1]
		}
		switch {
		case a == "--privileged", a == "--cap-add", a == "--device", a == "-v", a == "--volume", a == "--volumes-from",
			strings.HasPrefix(a, "--cap-add="), strings.HasPrefix(a, "--privileged="), strings.HasPrefix(a, "--device="):
			bad = append(bad, a)
		case a == "--security-opt" && v != "no-new-privileges":
			bad = append(bad, a+" "+v)
		case a == "--network" && v != "none":
			bad = append(bad, a+" "+v)
		case a == "--pid", a == "--ipc", a == "--uts", a == "--userns":
			bad = append(bad, a)
		case a == "--mount":
			if !strings.HasPrefix(v, "type=volume,src=wj.") && !strings.HasPrefix(v, "type=volume,src=wj-cache.") || strings.Contains(v, "bind") {
				bad = append(bad, a+" "+v)
			}
		}
	}
	for _, need := range []string{"--cap-drop", "--read-only", "--user", "--pids-limit", "--memory"} {
		found := false
		for _, a := range args[:end] {
			found = found || a == need
		}
		if !found {
			bad = append(bad, "missing "+need)
		}
	}
	return bad
}

// For every shape, even with hostile argv, no forbidden flag appears before the image.
func TestCreateArgsForbiddenInvariant(t *testing.T) {
	hostile := []string{"--privileged", "--network", "host", "-v", "/:/host", "--pid", "host"}
	specs := []callSpec{baseSpec(shapeCall), baseSpec(shapeReadOnly)}
	c := baseSpec(shapeCall)
	c.Caches = []string{"gomod", "a"}
	s := baseSpec(shapeSeed)
	s.Worker, s.Cache, s.Workdir = "", "gomod", "/work"
	specs = append(specs, c, s)
	for _, sp := range specs {
		sp.Argv = hostile
		args, err := createArgs(sp)
		if err != nil {
			t.Fatal(err)
		}
		if bad := forbidden(args, sp.Image); len(bad) > 0 {
			t.Errorf("shape %d: forbidden %q", sp.Shape, bad)
		}
		if !reflect.DeepEqual(args[len(args)-len(hostile):], hostile) {
			t.Errorf("argv not passed verbatim after the image: %q", args)
		}
	}
	// Control: the checker detects each weakening of a valid argv.
	good, _ := createArgs(baseSpec(shapeCall))
	for _, weak := range [][]string{{"--privileged"}, {"--cap-add", "SYS_ADMIN"}, {"--network", "host"},
		{"--mount", "type=bind,src=/,dst=/h"}, {"-v", "/:/h"}, {"--security-opt", "seccomp=unconfined"}, {"--pid", "host"}} {
		w := append(append([]string{good[0]}, weak...), good[1:]...)
		if len(forbidden(w, DefaultImage)) == 0 {
			t.Errorf("control: checker missed %q", weak)
		}
	}
}

// An invalid name, workdir or shape never produces argv; a valid spec (control) does.
func TestCreateArgsRejectsInvalid(t *testing.T) {
	mut := []struct {
		name string
		f    func(*callSpec)
	}{
		{"project upper", func(s *callSpec) { s.Project = "P" }},
		{"project traversal", func(s *callSpec) { s.Project = "../x" }},
		{"worker slash", func(s *callSpec) { s.Worker = "a/b" }},
		{"worker comma injects mount opt", func(s *callSpec) { s.Worker = "w,dst=/etc" }},
		{"cache dots", func(s *callSpec) { s.Caches = []string{"a..b"} }},
		{"duplicate cache", func(s *callSpec) { s.Caches = []string{"a", "a"} }},
		{"container name", func(s *callSpec) { s.Name = "evil" }},
		{"workdir", func(s *callSpec) { s.Workdir = "/" }},
		{"image flag", func(s *callSpec) { s.Image = "--privileged" }},
		{"empty argv", func(s *callSpec) { s.Argv = nil }},
		{"zero timeout", func(s *callSpec) { s.Timeout = 0 }},
		{"ro with caches", func(s *callSpec) { s.Shape, s.Caches = shapeReadOnly, []string{"gomod"} }},
		{"seed with worker", func(s *callSpec) { s.Shape, s.Cache = shapeSeed, "gomod" }},
		{"seed bad cache", func(s *callSpec) { s.Shape, s.Worker, s.Cache = shapeSeed, "", "-x" }},
		{"unknown shape", func(s *callSpec) { s.Shape = 99 }},
	}
	for _, m := range mut {
		s := baseSpec(shapeCall)
		m.f(&s)
		if args, err := createArgs(s); err == nil {
			t.Errorf("%s: accepted, argv %q", m.name, args)
		}
	}
	if _, err := createArgs(baseSpec(shapeCall)); err != nil {
		t.Fatalf("control: valid spec rejected: %v", err)
	}
	s := baseSpec(shapeCall)
	s.Project = "UP"
	if _, err := createArgs(s); !errors.Is(err, ErrInvalidName) {
		t.Errorf("want ErrInvalidName, got %v", err)
	}
}

// Name validation accepts the protocol's pattern and nothing else.
func TestValidName(t *testing.T) {
	for _, n := range []string{"a", "0", "p1", "my-project", "a-", strings.Repeat("a", 32)} {
		if err := ValidName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	for _, n := range []string{"", "A", "-x", "a..b", "a.b", "a/b", "../x", "a_b", "a b", "é", strings.Repeat("a", 33)} {
		if err := ValidName(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q accepted", n)
		}
	}
}

// /tmp is mounted exec (go test links binaries there) but never suid or dev, in every shape.
func TestCreateArgsTmpfsExec(t *testing.T) {
	for _, sh := range []shape{shapeCall, shapeReadOnly} {
		a, err := createArgs(baseSpec(sh))
		if err != nil {
			t.Fatal(err)
		}
		v := flagValue(a, "--tmpfs")
		if !strings.Contains(v, ",exec,") || strings.Contains(v, "noexec") || !strings.Contains(v, "nosuid") || !strings.Contains(v, "nodev") {
			t.Fatalf("tmpfs %q", v)
		}
	}
}
