package jail

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type shape int

const (
	shapeCall     shape = iota // workspace rw at /work, caches ro
	shapeReadOnly              // workspace ro at /work
	shapeSeed                  // cache volume rw at /work, nothing else
)

// callSpec describes one container. Mounts are expressed only as names;
// volume names are derived here, so no other mount can be built.
type callSpec struct {
	Shape    shape
	Name     string // wj-call-<16 hex>
	Project  string
	Worker   string   // call and read-only shapes
	ReadOnly bool     // call shape: mount the workspace read-only (policy workspace.access)
	Cache    string   // seed shape: the cache being seeded
	Caches   []string // call shape: caches mounted read-only
	Workdir  string   // "/work" or "/work/src"
	Image    string
	Limits   Limits
	Timeout  time.Duration
	Argv     []string
}

var callNameRE = regexp.MustCompile(`^wj-call-[0-9a-f]{16}$`)

func createArgs(s callSpec) ([]string, error) {
	if !callNameRE.MatchString(s.Name) {
		return nil, fmt.Errorf("%w: container %q", ErrInvalidName, s.Name)
	}
	if err := ValidName(s.Project); err != nil {
		return nil, err
	}
	if s.Workdir != "/work" && s.Workdir != "/work/src" {
		return nil, fmt.Errorf("jail: invalid workdir %q", s.Workdir)
	}
	if s.Image == "" || strings.HasPrefix(s.Image, "-") {
		return nil, fmt.Errorf("jail: invalid image %q", s.Image)
	}
	if len(s.Argv) == 0 {
		return nil, fmt.Errorf("jail: empty argv")
	}
	if s.Timeout <= 0 {
		return nil, fmt.Errorf("jail: invalid timeout %v", s.Timeout)
	}
	l := s.Limits
	a := []string{"create", "--rm", "-i", "--init", "--name", s.Name,
		"--label", LabelRoot + "=1", "--label", LabelKind + "=" + KindCall,
		"--label", LabelProject + "=" + s.Project}
	var mount string
	var caches []string
	switch s.Shape {
	case shapeCall, shapeReadOnly:
		if err := ValidName(s.Worker); err != nil {
			return nil, err
		}
		a = append(a, "--label", LabelWorker+"="+s.Worker)
		mount = "type=volume,src=" + WorkspaceVolume(s.Project, s.Worker) + ",dst=/work"
		if s.ReadOnly && s.Shape == shapeCall {
			mount += ",readonly"
		}
		if s.Shape == shapeReadOnly {
			mount += ",readonly"
			if len(s.Caches) > 0 {
				return nil, fmt.Errorf("jail: read-only call mounts no caches")
			}
		}
		caches = append(caches, s.Caches...)
		sort.Strings(caches)
		for i, c := range caches {
			if err := ValidName(c); err != nil {
				return nil, err
			}
			if i > 0 && caches[i-1] == c {
				return nil, fmt.Errorf("jail: duplicate cache %q", c)
			}
		}
	case shapeSeed:
		if err := ValidName(s.Cache); err != nil {
			return nil, err
		}
		if s.Worker != "" || len(s.Caches) > 0 || s.ReadOnly {
			return nil, fmt.Errorf("jail: seed call mounts only its cache")
		}
		mount = "type=volume,src=" + CacheVolume(s.Project, s.Cache) + ",dst=/work"
	default:
		return nil, fmt.Errorf("jail: unknown call shape %d", s.Shape)
	}
	a = append(a,
		"--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size="+i64(l.Tmp),
		"--user", "10001:10001",
		"--cpus", strconv.FormatFloat(l.CPUs, 'f', -1, 64),
		"--memory", i64(l.Memory), "--memory-swap", i64(l.Memory),
		"--pids-limit", strconv.Itoa(l.Pids),
		"--ulimit", fmt.Sprintf("nofile=%d:%d", l.NoFile, l.NoFile),
		"--ulimit", fmt.Sprintf("fsize=%d:%d", l.FileSize, l.FileSize),
		"--ulimit", "core=0:0", "--log-driver", "none",
		"--mount", mount)
	gomod := false
	for _, c := range caches {
		a = append(a, "--mount", "type=volume,src="+CacheVolume(s.Project, c)+",dst=/cache/"+c+",readonly")
		gomod = gomod || c == "gomod"
	}
	a = append(a, "-w", s.Workdir, "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp")
	if gomod {
		a = append(a, "-e", "GOMODCACHE=/cache/gomod", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local")
	}
	secs := int64(math.Ceil(s.Timeout.Seconds())) + 5
	a = append(a, s.Image, "timeout", "-s", "KILL", strconv.FormatInt(secs, 10))
	return append(a, s.Argv...), nil
}

func i64(v int64) string { return strconv.FormatInt(v, 10) }
