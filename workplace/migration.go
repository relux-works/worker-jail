package workplace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Legacy spellings are confined to this expiring, explicit cold importer.
const legacyRoot = "ai.relux.worker-jail"
const legacyWorkspacePrefix = "wj."
const legacyCachePrefix = "wj-cache."
const legacyEgressPrefix = "wj-egress"
const legacyCallPrefix = "wj-call-"
const legacyAdmin = ".wj"
const migrationLabel = LabelRoot + ".migration-id"
const migrationStateLabel = LabelRoot + ".migration-state-root"
const migrationReceipt = "migration.json"

var (
	ErrMigrationInvalid    = errors.New("invalid cold migration input")
	ErrMigrationCollision  = errors.New("cold migration destination exists")
	ErrMigrationBusy       = errors.New("cold migration requires drained callers and stopped services")
	ErrMigrationExpired    = errors.New("cold migration reader expired")
	ErrMigrationIncomplete = errors.New("cold migration is not published")
	ErrMigrationCopy       = errors.New("cold migration copy or verification failed")
)

// LegacyMigrationSpec requires explicit, disjoint paths and a trusted canonical
// helper image. Docker nil pins the same workers VM as normal operations.
// The operator must hold dispatch throughout; this cannot lock an old runtime
// that has not implemented the migration protocol.
type LegacyMigrationSpec struct {
	SourceStateDir, StateDir, Image string
	DryRun                          bool
	Docker                          Docker
}

type LegacyObjectMapping struct {
	DestinationOwned                             bool
	Source, Target, Kind                         string
	Labels                                       map[string]string
	PolicyID, Base, SnapshotTree, SnapshotParent string
	Files                                        uint64
	SHA256                                       string
}

// LegacyMigrationReport contains technical identities and digests, never user
// file names or bodies. Incomplete destinations are retained for scoped recovery.
type LegacyMigrationReport struct {
	ID, State, Error                  string
	StateDir, RetainedStageDir        string
	Objects                           []LegacyObjectMapping
	HostFiles                         uint64
	HostSHA256                        string
	SourceRetained, SocketRegenerated bool
}

// MigrateLegacy copies all owned cold data and atomically publishes host state.
// It never creates legacy data, rewrites policies or changes original snapshots.
func MigrateLegacy(ctx context.Context, s LegacyMigrationSpec) (LegacyMigrationReport, error) {
	return migrateLegacy(ctx, s, time.Now().UTC())
}

func migrateLegacy(ctx context.Context, s LegacyMigrationSpec, clock time.Time) (rep LegacyMigrationReport, err error) {
	rep.State, rep.SourceRetained = "refused", true
	defer func() {
		if err != nil {
			rep.Error = err.Error()
		}
	}()
	if !clock.Before(time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)) {
		return rep, ErrMigrationExpired
	}
	if err = migrationPaths(s); err != nil {
		return rep, err
	}
	// Resolve parent symlinks before reserving or labelling anything. This is
	// immutable publication authority, not a caller-selected receipt field.
	s.StateDir, err = normalizedStateRoot(s.StateDir)
	if err != nil {
		return rep, ErrMigrationInvalid
	}
	rep.StateDir = s.StateDir
	if !regexp.MustCompile(`^remote-workplace/[a-z0-9-]+:[a-zA-Z0-9_.-]+$`).MatchString(s.Image) {
		return rep, ErrMigrationInvalid
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return rep, ErrMigrationInvalid
	}
	if s.Docker == nil {
		// No client credentials or ambient daemon override are consulted.
		dir, e := os.MkdirTemp(filepath.Dir(s.StateDir), ".rwp-docker-*")
		if e != nil {
			return rep, ErrMigrationInvalid
		}
		defer os.RemoveAll(dir)
		s.Docker = NewDockerCLI(home, dir)
	}
	m := migrationTransport{s.Docker, s.Image}
	if err = m.image(ctx); err != nil {
		return rep, err
	}
	objects, err := m.inventory(ctx)
	if err != nil {
		return rep, err
	}
	rep.Objects = objects
	if err = m.cold(ctx, objects); err != nil {
		return rep, err
	}
	releases, err := migrationLocks(s.SourceStateDir)
	if err != nil {
		return rep, err
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	if err = validateMigrationState(s.SourceStateDir); err != nil {
		return rep, err
	}
	before, count, err := hostManifest(s.SourceStateDir)
	if err != nil {
		return rep, err
	}
	rep.HostFiles, rep.HostSHA256 = count, before
	for i := range rep.Objects {
		o := &rep.Objects[i]
		if o.Kind == KindWorkspace {
			raw, e := migrationPolicyBytes(filepath.Join(s.SourceStateDir, "policies", o.Labels[LabelProject]+"."+o.Labels[LabelWorker]+".json"))
			if e != nil {
				return rep, ErrMigrationInvalid
			}
			p, e := ParsePolicy(raw)
			if e != nil || matchTarget(p, Ref{o.Labels[LabelProject], o.Labels[LabelWorker]}) != nil || p.ID() != o.PolicyID || EffectiveRisk(p).Level.String() != o.Labels[LabelPolicyRisk] {
				return rep, ErrMigrationInvalid
			}
			if e = riskGate(p, EffectiveRisk(p).Level, RiskCritical); e != nil {
				return rep, ErrMigrationInvalid
			}
			if err = m.workspace(ctx, *o); err != nil {
				return rep, err
			}
		}
		if o.Source == legacyEgressPrefix+"-policy" {
			if err = m.egressPolicies(ctx, *o, s.SourceStateDir); err != nil {
				return rep, err
			}
		}
		if o.Source != legacyEgressPrefix+"-sock" {
			o.SHA256, o.Files, err = m.manifest(ctx, o.Source, o.Kind == KindWorkspace)
			if err != nil {
				return rep, err
			}
		}
		if _, exists, e := m.labels(ctx, o.Target); e != nil {
			return rep, e
		} else if exists {
			return rep, ErrMigrationCollision
		}
	}
	if s.DryRun {
		rep.State = "dry-run"
		return rep, nil
	}
	// Reserve the entire destination before creating any canonical object. This
	// sibling stays on all failures, including cancellation and process death.
	rep.ID = strings.TrimPrefix(newCallName(), "rwp-call-")
	guard := s.StateDir + ".migration-incomplete"
	f, err := os.OpenFile(guard, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return rep, ErrMigrationCollision
	}
	rep.State = "incomplete"
	if _, err = f.WriteString(rep.ID + "\n"); err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return rep, ErrMigrationCopy
	}
	stage, err := os.MkdirTemp(filepath.Dir(s.StateDir), ".rwp-migration-*")
	if err != nil {
		return rep, ErrMigrationCopy
	}
	stageOwned := true
	defer func() {
		if stageOwned {
			if e := removeMigrationStage(stage); e != nil {
				rep.RetainedStageDir = stage
				err = fmt.Errorf("%w: staging cleanup failed", ErrMigrationCopy)
			}
		}
	}()
	if err = copyHostState(ctx, s.SourceStateDir, stage); err != nil {
		return rep, err
	}
	after, copied, err := hostManifest(stage)
	if err != nil || before != after || count != copied {
		return rep, ErrMigrationCopy
	}
	for i := range rep.Objects {
		o := &rep.Objects[i]
		// Docker volume create adopts existing volumes; explicitly refuse immediately
		// before each creation too. Dispatch hold is part of operator admission.
		if _, exists, e := m.labels(ctx, o.Target); e != nil {
			return rep, e
		} else if exists {
			return rep, ErrMigrationCollision
		}
		labels := cloneLabels(o.Labels)
		labels[migrationLabel] = rep.ID
		labels[migrationStateLabel] = s.StateDir
		args := []string{"volume", "create"}
		for _, k := range sortedLabelKeys(labels) {
			args = append(args, "--label", k+"="+labels[k])
		}
		args = append(args, o.Target)
		if _, err = m.out(ctx, args...); err != nil {
			return rep, ErrMigrationCopy
		}
		actual, exists, e := m.labels(ctx, o.Target)
		if e != nil || !exists || !equalLabels(actual, labels) {
			return rep, ErrMigrationCopy
		}
		o.DestinationOwned = true
		if o.Source == legacyEgressPrefix+"-sock" {
			rep.SocketRegenerated = true
			continue
		}
		if err = m.copy(ctx, *o); err != nil {
			return rep, err
		}
		digest, files, e := m.manifest(ctx, o.Target, false)
		if e != nil || digest != o.SHA256 || files != o.Files {
			return rep, ErrMigrationCopy
		}
		if o.Kind == KindWorkspace {
			if err = m.workspaceTarget(ctx, *o); err != nil {
				return rep, err
			}
		}
	}
	// Re-read all relevant source and destination identities and source contents;
	// source drift or a caller appearing during the copy never publishes.
	latest, e := m.inventory(ctx)
	if e != nil || !sameInventory(objects, latest) {
		return rep, ErrMigrationInvalid
	}
	if err = m.cold(ctx, rep.Objects); err != nil {
		return rep, err
	}
	for _, o := range rep.Objects {
		labels, exists, e := m.labels(ctx, o.Target)
		expected := cloneLabels(o.Labels)
		expected[migrationLabel] = rep.ID
		expected[migrationStateLabel] = s.StateDir
		if e != nil || !exists || !equalLabels(labels, expected) {
			return rep, ErrMigrationCopy
		}
		if o.Source != legacyEgressPrefix+"-sock" {
			digest, files, e := m.manifest(ctx, o.Source, o.Kind == KindWorkspace)
			if e != nil || digest != o.SHA256 || files != o.Files {
				return rep, ErrMigrationCopy
			}
		}
	}
	current, n, e := hostManifest(s.SourceStateDir)
	if e != nil || current != before || n != count {
		return rep, ErrMigrationCopy
	}
	if err = ctx.Err(); err != nil {
		return rep, err
	}
	if _, e = os.Lstat(s.StateDir); !errors.Is(e, fs.ErrNotExist) {
		return rep, ErrMigrationCollision
	}
	rep.State = "published"
	raw, _ := json.Marshal(rep)
	// Verification above includes the original root mode. Temporarily restore
	// write access only on our staging root to add publication evidence, then
	// restore the required source metadata before the atomic rename.
	rootInfo, e := os.Lstat(s.SourceStateDir)
	if e != nil || os.Chmod(stage, 0700) != nil {
		rep.State = "incomplete"
		return rep, ErrMigrationCopy
	}
	if err = writeAtomic(filepath.Join(stage, migrationReceipt), raw); err != nil {
		rep.State = "incomplete"
		return rep, ErrMigrationCopy
	}
	if err = preserveHostMetadata(stage, rootInfo); err != nil {
		rep.State = "incomplete"
		return rep, err
	}
	if err = os.Rename(stage, s.StateDir); err != nil {
		rep.State = "incomplete"
		return rep, ErrMigrationCopy
	}
	stageOwned = false
	if err = os.Remove(guard); err != nil {
		rep.State = "incomplete"
		return rep, ErrMigrationCopy
	}
	return rep, nil
}

func migrationPaths(s LegacyMigrationSpec) error {
	if !filepath.IsAbs(s.SourceStateDir) || !filepath.IsAbs(s.StateDir) || filepath.Clean(s.SourceStateDir) != s.SourceStateDir || filepath.Clean(s.StateDir) != s.StateDir {
		return ErrMigrationInvalid
	}
	source, e := filepath.EvalSymlinks(s.SourceStateDir)
	if e != nil {
		return ErrMigrationInvalid
	}
	st, e := os.Lstat(s.SourceStateDir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return ErrMigrationInvalid
	}
	// Publication owns this root name. Refuse source-owned entries (including
	// dangling links) before Docker access, staging or canonical reservation.
	if _, e = os.Lstat(filepath.Join(s.SourceStateDir, migrationReceipt)); !errors.Is(e, fs.ErrNotExist) {
		if e == nil {
			return ErrMigrationCollision
		}
		return ErrMigrationInvalid
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(s.StateDir))
	if e != nil {
		return ErrMigrationInvalid
	}
	dest := filepath.Join(parent, filepath.Base(s.StateDir))
	if source == dest || strings.HasPrefix(dest, source+string(os.PathSeparator)) || strings.HasPrefix(source, dest+string(os.PathSeparator)) {
		return ErrMigrationInvalid
	}
	for _, p := range []string{s.StateDir, s.StateDir + ".migration-incomplete"} {
		if _, e = os.Lstat(p); !errors.Is(e, fs.ErrNotExist) {
			if e == nil {
				return ErrMigrationCollision
			}
			return ErrMigrationInvalid
		}
	}
	return nil
}

// migrationGuard also protects Workplace instances created before reservation.
func migrationGuard(state string) error {
	var err error
	state, err = normalizedStateRoot(state)
	if err != nil {
		return ErrMigrationIncomplete
	}
	if _, err := os.Lstat(state + ".migration-incomplete"); !errors.Is(err, fs.ErrNotExist) {
		return ErrMigrationIncomplete
	}
	return nil
}

// Docker/host administrators are trusted operators. Ordinary callers cannot
// adopt a copy by choosing another state root or copying/minting a receipt:
// immutable labels pin the root and its reservation, and receipt membership
// must match the actual inspected object and preserved metadata.
func (j *Workplace) migrationVolume(volume string, labels map[string]string) error {
	if id := labels[migrationLabel]; id != "" {
		root, e := normalizedStateRoot(j.state)
		if e != nil || labels[migrationStateLabel] != root || migrationGuard(root) != nil {
			return ErrMigrationIncomplete
		}
		var rep LegacyMigrationReport
		b, e := migrationBoundedBytes(filepath.Join(root, migrationReceipt), 4<<20)
		if e != nil || json.Unmarshal(b, &rep) != nil || rep.State != "published" || rep.ID != id || rep.StateDir != root {
			return ErrMigrationIncomplete
		}
		matches := 0
		for _, o := range rep.Objects {
			if o.Target == volume {
				expected := cloneLabels(o.Labels)
				expected[migrationLabel], expected[migrationStateLabel] = id, root
				if !o.DestinationOwned || !equalLabels(labels, expected) {
					return ErrMigrationIncomplete
				}
				matches++
			}
		}
		if matches != 1 {
			return ErrMigrationIncomplete
		}
	} else if labels[migrationStateLabel] != "" {
		return ErrMigrationIncomplete
	}
	return nil
}

// New may select a not-yet-existing nested root. Resolve the nearest existing
// ancestor, refusing lookup errors rather than treating them as absent paths.
func normalizedStateRoot(state string) (string, error) {
	abs, err := filepath.Abs(state)
	if err != nil {
		return "", err
	}
	ancestor := abs
	for {
		resolved, e := filepath.EvalSymlinks(ancestor)
		if e == nil {
			rel, e := filepath.Rel(ancestor, abs)
			return filepath.Join(resolved, rel), e
		}
		if !errors.Is(e, fs.ErrNotExist) || ancestor == filepath.Dir(ancestor) {
			return "", e
		}
		ancestor = filepath.Dir(ancestor)
	}
}

// Only the task-owned staging copy is made removable. Never follow symlinks or
// chmod the source; restrictive copied directory modes cannot hide cleanup loss.
func removeMigrationStage(stage string) error {
	if err := filepath.WalkDir(stage, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(stage)
}

type migrationTransport struct {
	docker    Docker
	imageName string
}

func (m migrationTransport) out(ctx context.Context, args ...string) (string, error) {
	var out, errb bytes.Buffer
	capped := &limitBuffer{buf: &out, max: 4 << 20}
	exit, err := m.docker.Run(ctx, args, nil, capped, &limitBuffer{buf: &errb, max: 4096})
	if err != nil || exit != 0 || out.Len() >= 4<<20 {
		return "", fmt.Errorf("%w: transport exit %d", ErrMigrationInvalid, exit)
	}
	return out.String(), nil
}
func (m migrationTransport) labels(ctx context.Context, name string) (map[string]string, bool, error) {
	var out, errb bytes.Buffer
	exit, e := m.docker.Run(ctx, []string{"volume", "inspect", "--format", "{{json .Labels}}", name}, nil, &limitBuffer{buf: &out, max: 1 << 20}, &limitBuffer{buf: &errb, max: 4096})
	if e != nil {
		return nil, false, ErrMigrationInvalid
	}
	if exit != 0 {
		if strings.Contains(strings.ToLower(errb.String()), "no such volume") {
			return nil, false, nil
		}
		return nil, false, ErrMigrationInvalid
	}
	var labels map[string]string
	if json.Unmarshal(out.Bytes(), &labels) != nil {
		return nil, false, ErrMigrationInvalid
	}
	return labels, true, nil
}
func (m migrationTransport) image(ctx context.Context) error {
	out, e := m.out(ctx, "image", "inspect", "--format", "{{json .Config}}", m.imageName)
	if e != nil {
		return e
	}
	var cfg struct {
		Labels     map[string]string
		Volumes    map[string]any
		Entrypoint []string
	}
	if json.Unmarshal([]byte(out), &cfg) != nil || cfg.Labels[LabelImageBase] != "2" || len(cfg.Volumes) != 0 || len(cfg.Entrypoint) != 0 {
		return ErrMigrationInvalid
	}
	return nil
}
func (m migrationTransport) inventory(ctx context.Context) ([]LegacyObjectMapping, error) {
	out, e := m.out(ctx, "volume", "ls", "-q")
	if e != nil {
		return nil, e
	}
	names := splitLines(out)
	slices.Sort(names)
	var objects []LegacyObjectMapping
	for _, name := range names {
		labels, exists, e := m.labels(ctx, name)
		if e != nil || !exists {
			return nil, ErrMigrationInvalid
		}
		legacy := strings.HasPrefix(name, legacyWorkspacePrefix) || strings.HasPrefix(name, legacyCachePrefix) || strings.HasPrefix(name, legacyEgressPrefix)
		if !legacy && labels[legacyRoot] == "" {
			continue
		}
		if labels[legacyRoot] != "1" || labels[LabelRoot] != "" {
			return nil, ErrMigrationInvalid
		}
		translated := map[string]string{}
		allowed := []string{LabelRoot, LabelKind, LabelProject, LabelWorker, LabelCache, LabelBase, LabelCreated, LabelPolicyID, LabelPolicyRisk, LabelSnapshotTree, LabelSnapshotParent}
		for k, v := range labels {
			if !strings.HasPrefix(k, legacyRoot) {
				return nil, ErrMigrationInvalid
			}
			key := LabelRoot + strings.TrimPrefix(k, legacyRoot)
			if !slices.Contains(allowed, key) {
				return nil, ErrMigrationInvalid
			}
			translated[key] = v
		}
		o := LegacyObjectMapping{Source: name, Kind: translated[LabelKind], Labels: translated, PolicyID: translated[LabelPolicyID], Base: translated[LabelBase], SnapshotTree: translated[LabelSnapshotTree], SnapshotParent: translated[LabelSnapshotParent]}
		if _, e := time.Parse(time.RFC3339, translated[LabelCreated]); e != nil {
			return nil, ErrMigrationInvalid
		}
		p, w, c := translated[LabelProject], translated[LabelWorker], translated[LabelCache]
		switch o.Kind {
		case KindWorkspace:
			if ValidName(p) != nil || ValidName(w) != nil || c != "" || name != legacyWorkspacePrefix+p+"."+w || !shaRE.MatchString(o.Base) || !policyIDRE.MatchString(o.PolicyID) || translated[LabelPolicyRisk] == "" {
				return nil, ErrMigrationInvalid
			}
			if (o.SnapshotTree == "") != (o.SnapshotParent == "") || o.SnapshotTree != "" && (!shaRE.MatchString(o.SnapshotTree) || !shaRE.MatchString(o.SnapshotParent)) {
				return nil, ErrMigrationInvalid
			}
			if _, err := ParseRisk(translated[LabelPolicyRisk]); err != nil {
				return nil, ErrMigrationInvalid
			}
			o.Target = WorkspaceVolume(p, w)
		case KindCache:
			if ValidName(p) != nil || ValidName(c) != nil || w != "" || name != legacyCachePrefix+p+"."+c || o.Base != "" || o.PolicyID != "" || o.SnapshotTree != "" || o.SnapshotParent != "" || translated[LabelPolicyRisk] != "" {
				return nil, ErrMigrationInvalid
			}
			o.Target = CacheVolume(p, c)
		case KindEgress:
			if p != "" || w != "" || c != "" || o.Base != "" || o.PolicyID != "" || o.SnapshotTree != "" || o.SnapshotParent != "" || translated[LabelPolicyRisk] != "" || !slices.Contains([]string{legacyEgressPrefix + "-sock", legacyEgressPrefix + "-policy", legacyEgressPrefix + "-cache"}, name) {
				return nil, ErrMigrationInvalid
			}
			o.Target = EgressContainer + strings.TrimPrefix(name, legacyEgressPrefix)
		default:
			return nil, ErrMigrationInvalid
		}
		objects = append(objects, o)
	}
	if len(objects) == 0 {
		return nil, ErrMigrationInvalid
	}
	// Cold egress storage is a complete three-volume set, never a partial service.
	egress := 0
	for _, o := range objects {
		if o.Kind == KindEgress {
			egress++
		}
	}
	if egress != 0 && egress != 3 {
		return nil, ErrMigrationInvalid
	}
	return objects, nil
}

func (m migrationTransport) cold(ctx context.Context, objects []LegacyObjectMapping) error {
	out, e := m.out(ctx, "ps", "-q")
	if e != nil {
		return e
	}
	for _, id := range splitLines(out) {
		raw, e := m.out(ctx, "inspect", "--type", "container", id)
		if e != nil {
			return e
		}
		var containers []struct {
			Name   string
			Config struct{ Labels map[string]string }
			Mounts []struct{ Name string }
		}
		if json.Unmarshal([]byte(raw), &containers) != nil || len(containers) != 1 {
			return ErrMigrationInvalid
		}
		c := containers[0]
		name := strings.TrimPrefix(c.Name, "/")
		if strings.HasPrefix(name, legacyCallPrefix) || strings.HasPrefix(name, "rwp-call-") || name == legacyEgressPrefix || name == EgressContainer || c.Config.Labels[legacyRoot] != "" || c.Config.Labels[LabelRoot] != "" {
			return ErrMigrationBusy
		}
		for _, mount := range c.Mounts {
			for _, o := range objects {
				if mount.Name == o.Source || mount.Name == o.Target {
					return ErrMigrationBusy
				}
			}
		}
	}
	return nil
}

// Helpers are a separate trusted operator lane. Root plus narrowly listed file
// capabilities is necessary to preserve uid 10001/10002 and restrictive modes;
// normal worker gates and their unprivileged call shapes remain unchanged.
func (m migrationTransport) helper(ctx context.Context, source, target, script string, args ...string) (out string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	name := newCallName()
	defer func() {
		if err == nil {
			return
		}
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer stop()
		var stderr bytes.Buffer
		exit, e := m.docker.Run(cleanupCtx, []string{"rm", "-f", name}, nil, io.Discard, &limitBuffer{buf: &stderr, max: 4096})
		if e != nil || exit != 0 && !strings.Contains(strings.ToLower(stderr.String()), "no such container") {
			err = fmt.Errorf("%w: exact helper cleanup unconfirmed", ErrMigrationCopy)
		}
	}()
	a := []string{"run", "--rm", "--init", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges", "--user", "0:0", "--cpus", "1", "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "64", "--ulimit", "nofile=256:256", "--ulimit", "fsize=8589934592:8589934592", "--ulimit", "core=0:0", "--log-driver", "none", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16777216", "--mount", "type=volume,src=" + source + ",dst=/from,readonly,volume-nocopy"}
	if target != "" {
		a = append(a, "--mount", "type=volume,src="+target+",dst=/to,volume-nocopy")
	}
	a = append(a, "--entrypoint", "/bin/bash", m.imageName, "-c", script, "rwp-migration")
	a = append(a, args...)
	out, e := m.out(ctx, a...)
	if e != nil {
		return "", ErrMigrationCopy
	}
	return out, nil
}

// Sort by the names that will exist in the destination, then map only the
// literal administration prefix back for source reads. NUL records preserve
// arbitrary names; tar must not recurse because the list contains every entry.
// Source/target now choose the same first hard-link member and archive order.
const migrationPathOrderScript = `migration_translate_paths() {
 while IFS= read -r -d '' path; do
  if [ "$1" = translate ]; then
   if [ "$2" = canonical ]; then
    case "$path" in
     ./.wj|./.wj/*) path="./.rwp${path#./.wj}" ;;
    esac
   else
    case "$path" in
     ./.rwp|./.rwp/*) path="./.wj${path#./.rwp}" ;;
    esac
   fi
  fi
  printf '%s\0' "$path"
 done
}
migration_paths() {
 find . -xdev -print0 | migration_translate_paths "$1" canonical | LC_ALL=C sort -z | migration_translate_paths "$1" source
}
`

const migrationManifestScript = `set -eu
set -o pipefail
cd /from
` + migrationPathOrderScript + `
if [ "$1" = translate ]; then
 migration_paths "$1" | tar --null --verbatim-files-from --no-recursion --numeric-owner --format=gnu --transform='flags=rh;s,^\./\.wj\(/\|$\),./.rwp\1,' -cf - -T - | sha256sum | cut -d ' ' -f 1
else
 migration_paths "$1" | tar --null --verbatim-files-from --no-recursion --numeric-owner --format=gnu -cf - -T - | sha256sum | cut -d ' ' -f 1
fi
find . -xdev -printf x | wc -c
`

func (m migrationTransport) manifest(ctx context.Context, volume string, translate bool) (string, uint64, error) {
	flag := "keep"
	if translate {
		flag = "translate"
	}
	out, e := m.helper(ctx, volume, "", migrationManifestScript, flag)
	if e != nil {
		return "", 0, e
	}
	f := strings.Fields(out)
	if len(f) != 2 || !policyIDRE.MatchString(f[0]) {
		return "", 0, ErrMigrationCopy
	}
	n, e := strconv.ParseUint(f[1], 10, 64)
	if e != nil || n == 0 {
		return "", 0, ErrMigrationCopy
	}
	return f[0], n, nil
}

const migrationWorkspaceScript = `set -eu
[ -d /from/src ]
[ ! -L /from/src ]
[ -d /from/src/.git ]
[ ! -L /from/src/.git ]
[ -d /from/home ]
[ ! -L /from/home ]
[ -d "/from/$1" ]
[ ! -L "/from/$1" ]
[ -f "/from/$1/provisioned" ]
[ ! -L "/from/$1/provisioned" ]
[ ! -e "/from/$2" ]
[ ! -L "/from/$2" ]
git -c safe.directory=/from/src -c core.hooksPath=/dev/null -c core.fsmonitor=false -C /from/src cat-file -e "$3^{commit}"
git -c safe.directory=/from/src -c core.hooksPath=/dev/null -c core.fsmonitor=false -C /from/src fsck --no-reflogs --no-dangling "$3"
if [ -n "$4" ]; then
 [ "$(git -c safe.directory=/from/src -C /from/src rev-parse "$3^{tree}")" = "$4" ]
 [ "$(git -c safe.directory=/from/src -C /from/src rev-parse "$3^1")" = "$5" ]
fi
`

func (m migrationTransport) workspace(ctx context.Context, o LegacyObjectMapping) error {
	_, e := m.helper(ctx, o.Source, "", migrationWorkspaceScript, legacyAdmin, ".rwp", o.Base, o.SnapshotTree, o.SnapshotParent)
	if e != nil {
		return ErrMigrationInvalid
	}
	return nil
}
func (m migrationTransport) workspaceTarget(ctx context.Context, o LegacyObjectMapping) error {
	_, e := m.helper(ctx, o.Target, "", migrationWorkspaceScript, ".rwp", legacyAdmin, o.Base, o.SnapshotTree, o.SnapshotParent)
	return e
}

const migrationCopyScript = `set -eu
[ -z "$(find /to -mindepth 1 -maxdepth 1 -printf x)" ]
cp -a /from/. /to/
if [ "$1" = workspace ]; then
 mv /to/.wj /to/.rwp
 touch -r /from /to
fi
`

func (m migrationTransport) copy(ctx context.Context, o LegacyObjectMapping) error {
	_, e := m.helper(ctx, o.Source, o.Target, migrationCopyScript, o.Kind)
	return e
}

func cloneLabels(m map[string]string) map[string]string {
	c := map[string]string{}
	for k, v := range m {
		c[k] = v
	}
	return c
}
func sortedLabelKeys(m map[string]string) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	slices.Sort(k)
	return k
}
func equalLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func sameInventory(a, b []LegacyObjectMapping) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Source != b[i].Source || a[i].Target != b[i].Target || !equalLabels(a[i].Labels, b[i].Labels) {
			return false
		}
	}
	return true
}

// Only already-existing lock files are opened. No source path is created or
// chmod'ed. Holding the operator dispatch barrier is required even in dry-run.
func migrationLocks(root string) ([]func(), error) {
	var release []func()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return ErrMigrationInvalid
		}
		rel, _ := filepath.Rel(root, path)
		if !strings.HasPrefix(rel, "locks"+string(os.PathSeparator)) && !strings.HasPrefix(rel, "slots"+string(os.PathSeparator)) {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return ErrMigrationInvalid
		}
		f, e := os.OpenFile(path, os.O_RDONLY, 0)
		if e != nil {
			return ErrMigrationInvalid
		}
		if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			f.Close()
			if errors.Is(e, syscall.EWOULDBLOCK) {
				return ErrMigrationBusy
			}
			return ErrMigrationInvalid
		}
		release = append(release, func() { f.Close() })
		return nil
	})
	if err != nil {
		for _, r := range release {
			r()
		}
		return nil, err
	}
	return release, nil
}

// A manifest hashes paths, kinds, modes, ownership, mtimes, hard-link identity,
// symlink targets and file bytes without exposing them in the report.
func hostManifest(root string) (string, uint64, error) {
	h := sha256.New()
	var count uint64
	links := map[[2]uint64]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return ErrMigrationInvalid
		}
		info, e := d.Info()
		if e != nil {
			return ErrMigrationInvalid
		}
		rel, _ := filepath.Rel(root, path)
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrMigrationInvalid
		}
		if info.Mode().IsDir() && info.Mode().Perm()&0500 != 0500 || info.Mode().IsRegular() && info.Mode().Perm()&0400 == 0 {
			return ErrMigrationInvalid
		}
		fmt.Fprintf(h, "%q:%d:%d:%d:%d:", rel, info.Mode(), st.Uid, st.Gid, info.ModTime().UnixNano())
		switch {
		case info.IsDir():
		case info.Mode().IsRegular():
			key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
			if prior, ok := links[key]; ok {
				fmt.Fprintf(h, "link:%q", prior)
			} else {
				links[key] = rel
				f, e := os.Open(path)
				if e != nil {
					return ErrMigrationInvalid
				}
				_, e = io.Copy(h, f)
				f.Close()
				if e != nil {
					return ErrMigrationInvalid
				}
			}
		case info.Mode()&os.ModeSymlink != 0:
			target, e := os.Readlink(path)
			if e != nil {
				return ErrMigrationInvalid
			}
			// Do not dereference links, including snapshot objects. External links in
			// host state are not self-contained migration inputs.
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
			if filepath.IsAbs(target) || resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
				return ErrMigrationInvalid
			}
			fmt.Fprintf(h, "symlink:%q", target)
		default:
			return ErrMigrationInvalid
		}
		h.Write([]byte{0})
		count++
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), count, nil
}

func copyHostState(ctx context.Context, source, dest string) error {
	links := map[[2]uint64]string{}
	var dirs []string
	err := filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return ErrMigrationInvalid
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(source, path)
		target := filepath.Join(dest, rel)
		info, e := d.Info()
		if e != nil {
			return ErrMigrationInvalid
		}
		st := info.Sys().(*syscall.Stat_t)
		switch {
		case info.IsDir():
			if rel != "." {
				if e = os.Mkdir(target, 0700); e != nil {
					return ErrMigrationCopy
				}
			}
			dirs = append(dirs, path)
			return nil
		case info.Mode().IsRegular():
			key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
			if prior, ok := links[key]; ok {
				if e = os.Link(prior, target); e != nil {
					return ErrMigrationCopy
				}
			} else {
				links[key] = target
				in, e := os.Open(path)
				if e != nil {
					return ErrMigrationInvalid
				}

				out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return ErrMigrationCopy
				}
				_, e = io.Copy(out, in)
				in.Close()
				if e == nil {
					e = out.Sync()
				}
				closeErr := out.Close()
				if e != nil || closeErr != nil {
					return ErrMigrationCopy
				}
			}
		case info.Mode()&os.ModeSymlink != 0:
			return preserveHostSymlink(path, target, info)
		default:
			return ErrMigrationInvalid
		}
		return preserveHostMetadata(target, info)
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		info, e := os.Lstat(dirs[i])
		if e != nil {
			return ErrMigrationInvalid
		}
		rel, _ := filepath.Rel(source, dirs[i])
		if e = preserveHostMetadata(filepath.Join(dest, rel), info); e != nil {
			return e
		}
	}
	return nil
}
func preserveHostMetadata(target string, info fs.FileInfo) error {
	st := info.Sys().(*syscall.Stat_t)
	if os.Chown(target, int(st.Uid), int(st.Gid)) != nil || os.Chmod(target, info.Mode()) != nil || os.Chtimes(target, info.ModTime(), info.ModTime()) != nil {
		return ErrMigrationCopy
	}
	return nil
}

func preserveHostSymlink(source, target string, info fs.FileInfo) error {
	cmd := exec.Command("cp", "-pP", source, target)
	cmd.Env = hostEnv()
	if cmd.Run() != nil {
		return ErrMigrationCopy
	}
	st := info.Sys().(*syscall.Stat_t)
	if os.Lchown(target, int(st.Uid), int(st.Gid)) != nil {
		return ErrMigrationCopy
	}
	return nil
}

// Stored host contracts are checked independently of workspace references, so
// an unused policy or export/seed record is never silently imported corrupt.
func validateMigrationState(root string) error {
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return ErrMigrationInvalid
		}
		info, err := d.Info()
		if err != nil {
			return ErrMigrationInvalid
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSymlink == 0 {
			return ErrMigrationInvalid
		}
		return nil
	}); err != nil {
		return err
	}

	for _, dir := range []string{"policies", "exports", "seeds", "snapshots", "locks", "slots", "docker-config"} {
		st, err := os.Lstat(filepath.Join(root, dir))
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrMigrationInvalid
		}
	}
	for _, kind := range []string{"policies", "exports", "seeds"} {
		files, err := os.ReadDir(filepath.Join(root, kind))
		if err != nil {
			return ErrMigrationInvalid
		}
		for _, file := range files {
			if !file.Type().IsRegular() {
				return ErrMigrationInvalid
			}
			name := file.Name()
			suffix := ".json"
			if kind == "exports" {
				suffix = ".sha256"
			}
			if kind == "seeds" {
				suffix = ".tree"
			}
			if !strings.HasSuffix(name, suffix) {
				return ErrMigrationInvalid
			}
			p, w, ok := strings.Cut(strings.TrimSuffix(name, suffix), ".")
			if !ok || ValidName(p) != nil || ValidName(w) != nil {
				return ErrMigrationInvalid
			}
			limit := 65
			if kind == "policies" {
				limit = PolicyMaxBytes
			}
			raw, err := migrationBoundedBytes(filepath.Join(root, kind, name), limit)
			if err != nil {
				return ErrMigrationInvalid
			}
			if kind == "policies" {
				policy, err := ParsePolicy(raw)
				if err != nil || matchTarget(policy, Ref{p, w}) != nil || riskGate(policy, EffectiveRisk(policy).Level, RiskCritical) != nil {
					return ErrMigrationInvalid
				}
			} else if kind == "exports" {
				if !policyIDRE.MatchString(strings.TrimSuffix(string(raw), "\n")) {
					return ErrMigrationInvalid
				}
			} else if !shaRE.MatchString(strings.TrimSuffix(string(raw), "\n")) {
				return ErrMigrationInvalid
			}
		}
	}
	return nil
}

func migrationPolicyBytes(path string) ([]byte, error) {
	return migrationBoundedBytes(path, PolicyMaxBytes)
}
func migrationBoundedBytes(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrMigrationInvalid
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, ErrMigrationInvalid
	}
	return b, nil
}

// Cold service policies are accepted only when their raw bytes match a validated
// host policy. No policy body leaves the VM and no stale service authority is
// inferred from an equal-shaped label or a restart.
const migrationEgressPolicyScript = `set -eu
set -o pipefail
pairs=("$@")
for file in /from/* /from/.[!.]* /from/..?*; do
 if [ ! -e "$file" ] && [ ! -L "$file" ]; then continue; fi
 [ -f "$file" ]
 [ ! -L "$file" ]
 name=${file##*/}
 found=no
 for ((i=0;i<${#pairs[@]};i+=2)); do
  if [ "$name" = "${pairs[i]}" ]; then
   [ "$(sha256sum "$file" | cut -d ' ' -f 1)" = "${pairs[i+1]}" ]
   found=yes
   break
  fi
 done
 [ "$found" = yes ]
done
`

func (m migrationTransport) egressPolicies(ctx context.Context, o LegacyObjectMapping, state string) error {
	files, err := os.ReadDir(filepath.Join(state, "policies"))
	if err != nil {
		return ErrMigrationInvalid
	}
	var args []string
	for _, file := range files {
		raw, err := migrationPolicyBytes(filepath.Join(state, "policies", file.Name()))
		if err != nil {
			return err
		}
		hash := sha256.Sum256(raw)
		args = append(args, file.Name(), hex.EncodeToString(hash[:]))
	}
	if _, err = m.helper(ctx, o.Source, "", migrationEgressPolicyScript, args...); err != nil {
		return ErrMigrationInvalid
	}
	return nil
}
