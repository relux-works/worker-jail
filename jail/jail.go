// Package jail is the reference implementation of the worker-jail protocol v1
// (docs/protocol.md): every call runs in a fresh hardened container inside the
// colima "workers" VM, against a per-worker workspace volume.
package jail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Labels carried by every volume and container the jail creates.
const (
	LabelRoot    = "ai.relux.worker-jail"
	LabelKind    = LabelRoot + ".kind"
	LabelProject = LabelRoot + ".project"
	LabelWorker  = LabelRoot + ".worker"
	LabelCache   = LabelRoot + ".cache"
	LabelBase    = LabelRoot + ".base"
	LabelCreated = LabelRoot + ".created"
	// LabelPolicyID and LabelPolicyRisk record the policy a workspace was provisioned under (v2.0).
	LabelPolicyID   = LabelRoot + ".policy-id"
	LabelPolicyRisk = LabelRoot + ".policy-risk"
	// LabelSnapshotTree and LabelSnapshotParent record a workspace provisioned from a worktree snapshot (v2.0):
	// the snapshot's tree and the worktree's HEAD at snapshot time. The base label is the snapshot commit.
	LabelSnapshotTree   = LabelRoot + ".snapshot-tree"
	LabelSnapshotParent = LabelRoot + ".snapshot-parent"

	KindWorkspace = "workspace"
	KindCache     = "cache"
	KindCall      = "call"
)

// Defaults and protocol maximums.
const (
	DefaultImage     = "worker-jail/base:1"
	DefaultTimeout   = 10 * time.Minute
	MaxTimeout       = 60 * time.Minute
	DefaultMaxOutput = 4 << 20
	ExportCap        = 64 << 20
	seedTimeout      = 30 * time.Minute
	stderrTail       = 4 << 10
)

var (
	ErrInvalidName    = errors.New("invalid name")
	ErrNoWorkspace    = errors.New("no such workspace")
	ErrIncomplete     = errors.New("workspace exists but is not provisioned")
	ErrUnexported     = errors.New("workspace has unexported changes")
	ErrBusy           = errors.New("workspace is in use")
	ErrExportTooLarge = errors.New("export exceeds 64 MiB")
	ErrDirty          = errors.New("target worktree is dirty")
	ErrGitPath        = errors.New("patch touches a .git path")
	ErrReviewRequired = errors.New("patch touches review-required paths")
	ErrOutOfScope     = errors.New("patch touches paths outside the write scope")
	ErrDoctor         = errors.New("doctor checks failed")

	ErrPolicyInvalid     = errors.New("invalid policy")
	ErrNoPolicy          = errors.New("no stored policy")
	ErrPolicyChanged     = errors.New("stored policy differs from the workspace's")
	ErrEgressUnavailable = errors.New("egress unavailable: network modes other than none arrive in v2.1")
	ErrRiskExceeded      = errors.New("policy risk above the accepted level")

	ErrSnapshot    = errors.New("worktree cannot be snapshotted")
	ErrSecret      = errors.New("secret guard: the snapshot holds likely secrets")
	ErrSeed        = errors.New("worktree cannot seed the module cache")
	ErrDirtyTarget = errors.New("target worktree refused for a dirty apply")
)

// Limits are per-call resource limits. Zero fields take the defaults.
type Limits struct {
	CPUs         float64
	Memory, Tmp  int64
	FileSize     int64
	Pids, NoFile int
}

// DefaultLimits are the protocol's default call limits.
var DefaultLimits = Limits{CPUs: 2, Memory: 2 << 30, Tmp: 512 << 20, FileSize: 2 << 30, Pids: 512, NoFile: 4096}

// Config configures a Jail.
type Config struct {
	Image        string // default worker-jail/base:1
	StateDir     string // default ~/.local/state/worker-jail
	Slots        int    // 0: VM CPU count
	ProjectSlots int    // 0: ceil(Slots/2)
	Limits       Limits // zero fields take defaults
	Docker       Docker // nil: docker CLI against the workers VM
	Colima       Colima // nil: `colima ssh -p workers -- cat /proc/mounts`
}

// Jail drives the workers VM.
type Jail struct {
	image  string
	state  string
	home   string
	limits Limits
	docker Docker
	colima Colima

	slotMu       sync.Mutex
	slots        int
	projectSlots int
}

// New validates cfg, fills defaults and creates the state directories. It makes no docker call.
func New(cfg Config) (*Jail, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("jail: home: %w", err)
	}
	j := &Jail{image: cfg.Image, state: cfg.StateDir, home: home, limits: cfg.Limits,
		docker: cfg.Docker, colima: cfg.Colima, slots: cfg.Slots, projectSlots: cfg.ProjectSlots}
	if j.image == "" {
		j.image = DefaultImage
	}
	if strings.HasPrefix(j.image, "-") || strings.ContainsAny(j.image, " \t\n") {
		return nil, fmt.Errorf("jail: invalid image %q", j.image)
	}
	if j.state == "" {
		j.state = filepath.Join(home, ".local", "state", "worker-jail")
	}
	if j.slots < 0 || j.projectSlots < 0 {
		return nil, errors.New("jail: negative slot count")
	}
	l, d := &j.limits, DefaultLimits
	if l.CPUs == 0 {
		l.CPUs = d.CPUs
	}
	if l.Memory == 0 {
		l.Memory = d.Memory
	}
	if l.Tmp == 0 {
		l.Tmp = d.Tmp
	}
	if l.FileSize == 0 {
		l.FileSize = d.FileSize
	}
	if l.Pids == 0 {
		l.Pids = d.Pids
	}
	if l.NoFile == 0 {
		l.NoFile = d.NoFile
	}
	if l.CPUs < 0 || l.Memory < 0 || l.Tmp < 0 || l.FileSize < 0 || l.Pids < 0 || l.NoFile < 0 {
		return nil, errors.New("jail: negative limit")
	}
	for _, sub := range []string{"", "slots", "locks", "exports", "policies", "seeds", "snapshots", "docker-config"} {
		if err := os.MkdirAll(filepath.Join(j.state, sub), 0o700); err != nil {
			return nil, fmt.Errorf("jail: state dir: %w", err)
		}
	}
	if err := os.Chmod(j.state, 0o700); err != nil {
		return nil, fmt.Errorf("jail: state dir: %w", err)
	}
	if j.docker == nil {
		j.docker = NewDockerCLI(home, filepath.Join(j.state, "docker-config"))
	}
	if j.colima == nil {
		j.colima = ColimaCLI{}
	}
	return j, nil
}

// Ref names one workspace.
type Ref struct{ Project, Worker string }

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidName reports whether s is a valid project, worker or cache name.
func ValidName(s string) error {
	if !nameRE.MatchString(s) {
		return fmt.Errorf("%w: %q", ErrInvalidName, s)
	}
	return nil
}

func (r Ref) validate() error {
	if err := ValidName(r.Project); err != nil {
		return err
	}
	return ValidName(r.Worker)
}

// WorkspaceVolume is the volume name of a workspace.
func WorkspaceVolume(project, worker string) string { return "wj." + project + "." + worker }

// CacheVolume is the volume name of a project cache.
func CacheVolume(project, name string) string { return "wj-cache." + project + "." + name }

func newCallName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "wj-call-" + hex.EncodeToString(b)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func tail(b []byte) string {
	if len(b) > stderrTail {
		b = b[len(b)-stderrTail:]
	}
	return strings.TrimSpace(string(b))
}

// Workspace describes a provisioned workspace.
type Workspace struct {
	Ref
	Volume, Base   string
	PolicyID, Risk string // from the labels; empty for a workspace provisioned before v2.0
	// SnapshotTree and SnapshotParent are set for a workspace provisioned from a worktree (v2.0):
	// the snapshot's tree and the worktree's HEAD at snapshot time. Base is then the snapshot commit.
	SnapshotTree, SnapshotParent string
	Created                      time.Time
	Existed                      bool
}

// ProvisionSpec is the input of Provision. Exactly one source: Repo (with RefName, default "HEAD"),
// or FromWorktree, a worktree whose current state, dirty and untracked files included, is snapshotted.
// SnapshotOptions apply to FromWorktree only.
type ProvisionSpec struct {
	Ref
	Repo, RefName string
	FromWorktree  string
	SnapshotOptions
}

// RunSpec is the input of Run.
type RunSpec struct {
	Argv      []string
	Stdin     io.Reader
	Timeout   time.Duration
	MaxOutput int
}

// Result is the outcome of a call.
type Result struct {
	Stdout, Stderr      []byte
	Exit                int
	TimedOut, Truncated bool
	QueueWait, Duration time.Duration
}

type ExportInfo struct {
	Bytes  int64
	SHA256 string
	Base   string
}

type Cache struct {
	Project, Name, Volume string
	SnapshotTree          string // the last worktree snapshot that seeded the cache (v2.0), from host state
	Created               time.Time
}

type Call struct{ ID, Project, Worker, Status string }

type Listing struct {
	Workspaces []Workspace
	Caches     []Cache
	Calls      []Call
}

type Check struct {
	Name   string
	OK     bool
	Detail string
}

type DoctorReport struct{ Checks []Check }

// volumeLabels returns the labels of a volume, or ok=false if it does not exist.
func (j *Jail) volumeLabels(ctx context.Context, vol string) (map[string]string, bool, error) {
	out, errb, exit, err := j.dockerOut(ctx, nil, "volume", "inspect", "--format", "{{json .Labels}}", vol)
	if err != nil {
		return nil, false, err
	}
	if exit != 0 {
		if strings.Contains(strings.ToLower(errb), "no such volume") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("docker volume inspect %s: %s", vol, errb)
	}
	labels := map[string]string{}
	if s := strings.TrimSpace(out); s != "" && s != "null" {
		if err := jsonUnmarshal([]byte(s), &labels); err != nil {
			return nil, false, fmt.Errorf("docker volume inspect %s: %w", vol, err)
		}
	}
	return labels, true, nil
}

func (j *Jail) volumeCreate(ctx context.Context, vol string, labels ...string) error {
	args := []string{"volume", "create"}
	for _, l := range labels {
		args = append(args, "--label", l)
	}
	args = append(args, vol)
	_, errb, exit, err := j.dockerOut(ctx, nil, args...)
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("docker volume create %s: %s", vol, errb)
	}
	return nil
}
