package workplace

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
	shapeCall         shape = iota // workspace rw at /work, caches ro; with Egress also the worker's egress socket
	shapeReadOnly                  // workspace ro at /work
	shapeSeed                      // cache volume rw at /work, nothing else
	shapeEgressPolicy              // the egress policy volume rw at /work, nothing else (v2.1)
)

// Environment and relay of a call whose policy has a network mode other than none (egress.md §1, §2). The relay is
// socat from the base image: it listens on the call's loopback and forwards to the worker's socket. The wrapper waits
// until it listens (0100007F:0C38 is 127.0.0.1:3128 in /proc/net/tcp), then execs the tool; the relay dies with the
// call. modules replaces the gomod cache's environment with modulesEnv. The generic modes add proxyEnv, hints for
// the tools (the missing route is the enforcement), and keep the gomod cache's environment: GOPROXY is not touched.
var modulesEnv = []string{"GOPROXY=file:///cache/gomod/cache/download,http://127.0.0.1:3128/gomod",
	"GOMODCACHE=/work/home/go/pkg/mod", "GOSUMDB=sum.golang.org", "GOTOOLCHAIN=local"}

var proxyEnv = []string{"HTTP_PROXY=http://127.0.0.1:3128", "HTTPS_PROXY=http://127.0.0.1:3128",
	"ALL_PROXY=http://127.0.0.1:3128", "NO_PROXY="}

const relayScript = `socat TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/rwp/egress.sock &
i=0
until grep -q ' 0100007F:0C38 00000000:0000 0A ' /proc/net/tcp; do
	i=$((i+1))
	if [ "$i" -ge 100 ]; then echo 'remote-workplace: the egress relay (socat, base image v2) did not start' >&2; exit 125; fi
	sleep 0.05
done
exec "$@"
`

// callSpec describes one container. Mounts are expressed only as names;
// volume names are derived here, so no other mount can be built.
type callSpec struct {
	Shape    shape
	Name     string // rwp-call-<16 hex>
	Project  string
	Worker   string   // call and read-only shapes
	ReadOnly bool     // call shape: mount the workspace read-only (policy workspace.access)
	Egress   string   // call shape: a network mode but none: the worker's egress socket, the mode's env and the relay
	Cache    string   // seed shape: the cache being seeded
	Caches   []string // call shape: caches mounted read-only
	Workdir  string   // "/work" or "/work/src"
	Image    string
	Limits   Limits
	Timeout  time.Duration
	Argv     []string
}

var callNameRE = regexp.MustCompile(`^rwp-call-[0-9a-f]{16}$`)

func createArgs(s callSpec) ([]string, error) {
	if !callNameRE.MatchString(s.Name) {
		return nil, fmt.Errorf("%w: container %q", ErrInvalidName, s.Name)
	}
	if err := ValidName(s.Project); err != nil {
		return nil, err
	}
	if s.Workdir != "/work" && s.Workdir != "/work/src" {
		return nil, fmt.Errorf("workplace: invalid workdir %q", s.Workdir)
	}
	if s.Image == "" || strings.HasPrefix(s.Image, "-") {
		return nil, fmt.Errorf("workplace: invalid image %q", s.Image)
	}
	if len(s.Argv) == 0 {
		return nil, fmt.Errorf("workplace: empty argv")
	}
	if s.Timeout <= 0 {
		return nil, fmt.Errorf("workplace: invalid timeout %v", s.Timeout)
	}
	l := s.Limits
	switch s.Egress {
	case "":
	case NetModules, NetAllowlist, NetDenylist, NetAll:
		if s.Shape != shapeCall || s.ReadOnly && s.Egress == NetModules {
			return nil, fmt.Errorf("workplace: only a call mounts an egress socket, and only a read-write one for modules")
		}
	default:
		return nil, fmt.Errorf("workplace: invalid egress mode %q", s.Egress)
	}
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
				return nil, fmt.Errorf("workplace: read-only call mounts no caches")
			}
		}
		caches = append(caches, s.Caches...)
		sort.Strings(caches)
		for i, c := range caches {
			if err := ValidName(c); err != nil {
				return nil, err
			}
			if i > 0 && caches[i-1] == c {
				return nil, fmt.Errorf("workplace: duplicate cache %q", c)
			}
		}
	case shapeSeed:
		if err := ValidName(s.Cache); err != nil {
			return nil, err
		}
		if s.Worker != "" || len(s.Caches) > 0 || s.ReadOnly {
			return nil, fmt.Errorf("workplace: seed call mounts only its cache")
		}
		mount = "type=volume,src=" + CacheVolume(s.Project, s.Cache) + ",dst=/work"
	case shapeEgressPolicy:
		if s.Worker != "" || s.Cache != "" || len(s.Caches) > 0 || s.ReadOnly {
			return nil, fmt.Errorf("workplace: egress policy call mounts only the policy volume")
		}
		mount = "type=volume,src=" + EgressPolicyVolume + ",dst=/work"
	default:
		return nil, fmt.Errorf("workplace: unknown call shape %d", s.Shape)
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
	if s.Egress != "" {
		a = append(a, "--mount", "type=volume,src="+EgressSockVolume+",dst=/run/rwp,volume-subpath="+s.Project+"."+s.Worker+",readonly")
	}
	a = append(a, "-w", s.Workdir, "-e", "HOME=/work/home", "-e", "TMPDIR=/tmp")
	switch {
	case s.Egress == NetModules:
		for _, e := range modulesEnv {
			a = append(a, "-e", e)
		}
	case gomod:
		a = append(a, "-e", "GOMODCACHE=/cache/gomod", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local")
	}
	if s.Egress != "" && s.Egress != NetModules {
		for _, e := range proxyEnv {
			a = append(a, "-e", e)
		}
	}
	secs := int64(math.Ceil(s.Timeout.Seconds())) + 5
	a = append(a, s.Image, "timeout", "-s", "KILL", strconv.FormatInt(secs, 10))
	if s.Egress != "" {
		a = append(a, "sh", "-c", relayScript, "rwp-relay")
	}
	return append(a, s.Argv...), nil
}

func i64(v int64) string { return strconv.FormatInt(v, 10) }
