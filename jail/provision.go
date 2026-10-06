package jail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const provisionScript = `set -eu
mkdir -p /work/.wj /work/home
cat > /work/.wj/base.bundle
git clone -q --no-checkout /work/.wj/base.bundle /work/src
rm -f /work/.wj/base.bundle
cd /work/src
git checkout -q --detach "$1"
git remote remove origin
git config user.name "$2"
git config user.email "$3"
touch /work/.wj/provisioned
`

func hostGit(ctx context.Context, repo string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	cmd.Env = hostEnv()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", &cmdError{"git " + strings.Join(args, " "), err, errb.Bytes()}
	}
	return strings.TrimSpace(out.String()), nil
}

// resolveBase returns the commit of refName in repo and its full ref name ("" for a raw sha).
func resolveBase(ctx context.Context, repo, refName string) (base, fullref string, err error) {
	if refName == "" {
		refName = "HEAD"
	}
	if strings.HasPrefix(refName, "-") {
		return "", "", fmt.Errorf("jail: invalid ref %q", refName)
	}
	if base, err = hostGit(ctx, repo, "rev-parse", "--verify", "--end-of-options", refName+"^{commit}"); err != nil {
		return "", "", fmt.Errorf("jail: resolve %s: %w", refName, err)
	}
	out, err := hostGit(ctx, repo, "rev-parse", "--symbolic-full-name", "--end-of-options", refName)
	if err != nil {
		return "", "", fmt.Errorf("jail: resolve %s: %w", refName, err)
	}
	// git (2.53) echoes "--end-of-options" in --symbolic-full-name mode; keep only ref lines.
	for _, l := range splitLines(out) {
		if l == "--end-of-options" {
			continue
		}
		if fullref != "" || !strings.HasPrefix(l, "refs/") && l != "HEAD" {
			return "", "", fmt.Errorf("jail: resolve %s: unexpected full name %q", refName, out)
		}
		fullref = l
	}
	return base, fullref, nil
}

// Provision creates and clones a workspace, or returns the existing one.
// It refuses without a stored policy, and refuses a stored HIGH policy without a note (the store holds only what
// SetPolicy's risk gates passed, unless a file was placed by hand). A policy with egress provisions like none: the
// clone needs no network, and doctor checks the egress service; but the image must carry the egress relay
// (ErrImageNoRelay, before any volume exists). A new workspace is labelled with the policy's id and risk. A
// secret-guard override is refused for a HIGH or CRITICAL policy.
// With FromWorktree the base is a snapshot commit of the worktree's current state (snapshot.go); the
// worktree is never written, and the workspace is also labelled with the snapshot tree and parent.
func (j *Jail) Provision(ctx context.Context, s ProvisionSpec) (Workspace, error) {
	ws := Workspace{Ref: s.Ref, Volume: WorkspaceVolume(s.Project, s.Worker)}
	if err := s.Ref.validate(); err != nil {
		return ws, err
	}
	pol, err := j.LoadPolicy(s.Ref)
	if err != nil {
		return ws, err
	}
	risk := EffectiveRisk(pol).Level
	if risk == RiskHigh && pol.Note == "" {
		return ws, fmt.Errorf("%w: the stored %s policy has no note; store it with `worker-jail policy set`", ErrRiskExceeded, risk)
	}
	if s.FromWorktree != "" {
		if s.Repo != "" || s.RefName != "" {
			return ws, errors.New("jail: provision from a worktree takes no repo or ref")
		}
		if err := secretOverrideAllowed(s.AllowSecretPaths, risk); err != nil {
			return ws, err
		}
	}
	unlock, err := j.lockPath(ctx, "ws."+s.Project+"."+s.Worker)
	if err != nil {
		return ws, err
	}
	defer unlock()
	if pol.Network.Mode != NetNone {
		if err := j.checkImageRelay(ctx, pol.Network.Mode); err != nil {
			return ws, err
		}
	}
	if _, err := j.doctor(ctx, pol.Network.Mode != NetNone); err != nil {
		return ws, err
	}
	labels, ok, err := j.volumeLabels(ctx, ws.Volume)
	if err != nil {
		return ws, err
	}
	if ok {
		res, errb, err := j.call(ctx, callSpec{Shape: shapeReadOnly, Project: s.Project, Worker: s.Worker, Workdir: "/work",
			Timeout: time.Minute, Argv: []string{"test", "-f", "/work/.wj/provisioned"}}, nil, &bytes.Buffer{}, 0)
		if err != nil {
			return ws, err
		}
		if res.Exit != 0 {
			return ws, fmt.Errorf("%w: %s (exit %d: %s)", ErrIncomplete, ws.Volume, res.Exit, tail(errb))
		}
		ws.Existed, ws.Base = true, labels[LabelBase]
		ws.PolicyID, ws.Risk = labels[LabelPolicyID], labels[LabelPolicyRisk]
		ws.SnapshotTree, ws.SnapshotParent = labels[LabelSnapshotTree], labels[LabelSnapshotParent]
		ws.Created, _ = time.Parse(time.RFC3339, labels[LabelCreated])
		return ws, nil
	}
	var base string
	var bundle func(context.Context) *exec.Cmd
	var extra []string
	if s.FromWorktree != "" {
		snap, err := takeSnapshot(ctx, s.FromWorktree, s.SnapshotOptions, j.SnapshotStore())
		defer snap.close()
		if err != nil {
			return ws, err
		}
		if err := snap.guard(ctx, s.AllowSecretPaths); err != nil {
			return ws, err
		}
		if err := snap.commit(ctx); err != nil {
			return ws, err
		}
		base, bundle = snap.Commit, snap.bundle
		ws.SnapshotTree, ws.SnapshotParent = snap.Tree, snap.Parent
		extra = []string{LabelSnapshotTree + "=" + snap.Tree, LabelSnapshotParent + "=" + snap.Parent}
	} else {
		if s.Repo == "" {
			return ws, errors.New("jail: provision needs a repo or a worktree")
		}
		var fullref string
		if base, fullref, err = resolveBase(ctx, s.Repo, s.RefName); err != nil {
			return ws, err
		}
		if fullref == "" {
			return ws, fmt.Errorf("jail: ref %q resolves to a raw sha; RefName must be a branch, a tag or HEAD", s.RefName)
		}
		bundle = func(ctx context.Context) *exec.Cmd {
			cmd := exec.CommandContext(ctx, "git", "-C", s.Repo, "bundle", "create", "-", fullref)
			cmd.Env = hostEnv()
			return cmd
		}
	}
	created := time.Now().UTC().Truncate(time.Second)
	labelList := append([]string{LabelRoot + "=1", LabelKind + "=" + KindWorkspace, LabelProject + "=" + s.Project,
		LabelWorker + "=" + s.Worker, LabelBase + "=" + base, LabelCreated + "=" + created.Format(time.RFC3339),
		LabelPolicyID + "=" + pol.ID(), LabelPolicyRisk + "=" + risk.String()}, extra...)
	if err := j.volumeCreate(ctx, ws.Volume, labelList...); err != nil {
		return ws, err
	}
	if err := j.cloneInto(ctx, s.Ref, base, bundle); err != nil {
		rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		j.dockerOut(rmCtx, nil, "volume", "rm", "-f", ws.Volume)
		return ws, err
	}
	ws.Base, ws.Created, ws.PolicyID, ws.Risk = base, created, pol.ID(), risk.String()
	return ws, nil
}

// SnapshotStore is the host object dir that keeps the trees of provisioned snapshots (paths and blob ids, no file
// content), so apply --snapshot-tree can count diverged paths after the snapshot's temporary repository is gone.
// Pass it as ApplyOptions.SnapshotObjects.
func (j *Jail) SnapshotStore() string { return filepath.Join(j.state, "snapshots") }

// secretOverrideAllowed refuses a secret-guard override for a worker whose policy is HIGH or above:
// such a worker can send data out (design-owner decision 8).
func secretOverrideAllowed(allow []string, risk Risk) error {
	if len(allow) > 0 && risk >= RiskHigh {
		return fmt.Errorf("%w: --allow-secret-path is refused for a %s policy", ErrSecret, risk)
	}
	return nil
}

// cloneInto streams the bundle that newBundle writes into a provisioning call, which clones it and checks out base.
func (j *Jail) cloneInto(ctx context.Context, r Ref, base string, newBundle func(context.Context) *exec.Cmd) error {
	bctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bundle := newBundle(bctx)
	var berr bytes.Buffer
	bundle.Stderr = &berr
	pipe, err := bundle.StdoutPipe()
	if err != nil {
		return err
	}
	if err := bundle.Start(); err != nil {
		return fmt.Errorf("jail: git bundle: %w", err)
	}
	email := r.Worker + "@" + r.Project + ".worker-jail.invalid"
	res, errb, cerr := j.call(ctx, callSpec{Shape: shapeCall, Project: r.Project, Worker: r.Worker, Workdir: "/work",
		Timeout: DefaultTimeout, Argv: []string{"sh", "-c", provisionScript, "sh", base, r.Worker, email}}, pipe, &bytes.Buffer{}, 0)
	pipe.Close()
	werr := bundle.Wait()
	if cerr != nil {
		return fmt.Errorf("jail: provision clone: %w", cerr)
	}
	if werr != nil {
		return fmt.Errorf("jail: git bundle: %w: %s", werr, tail(berr.Bytes()))
	}
	if res.Exit != 0 || res.TimedOut {
		return fmt.Errorf("jail: provision clone failed (exit %d, timed out %v): %s", res.Exit, res.TimedOut, tail(errb))
	}
	return nil
}

// Deprovision removes a workspace, refusing unexported changes unless force.
func (j *Jail) Deprovision(ctx context.Context, r Ref, force bool) error {
	if err := r.validate(); err != nil {
		return err
	}
	unlock, err := j.lockPath(ctx, "ws."+r.Project+"."+r.Worker)
	if err != nil {
		return err
	}
	defer unlock()
	vol := WorkspaceVolume(r.Project, r.Worker)
	_, ok, err := j.volumeLabels(ctx, vol)
	if err != nil || !ok {
		return err
	}
	if !force {
		info, err := j.export(ctx, r, discard{}, false)
		if err != nil {
			return err
		}
		if info.Bytes != 0 {
			stored, _ := os.ReadFile(j.digestPath(r))
			if strings.TrimSpace(string(stored)) != info.SHA256 {
				return fmt.Errorf("%w: %s", ErrUnexported, vol)
			}
		}
	}
	_, errb, exit, err := j.dockerOut(ctx, nil, "volume", "rm", vol)
	if err != nil {
		return err
	}
	if exit != 0 {
		if strings.Contains(errb, "in use") {
			return fmt.Errorf("%w: %s: %s", ErrBusy, vol, errb)
		}
		return fmt.Errorf("jail: docker volume rm %s: %s", vol, errb)
	}
	if err := os.Remove(j.digestPath(r)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Purge kills P's calls and removes all of P's volumes, digests and seed records.
func (j *Jail) Purge(ctx context.Context, project string) error {
	if err := ValidName(project); err != nil {
		return err
	}
	if _, err := j.Kill(ctx, project, ""); err != nil {
		return err
	}
	out, errb, exit, err := j.dockerOut(ctx, nil, "volume", "ls", "-q", "--filter", "label="+LabelRoot+"=1",
		"--filter", "label="+LabelProject+"="+project)
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("jail: docker volume ls: %s", errb)
	}
	var errs []error
	for _, vol := range splitLines(out) {
		for i := 0; ; i++ {
			_, errb, exit, err := j.dockerOut(ctx, nil, "volume", "rm", "-f", vol)
			if err != nil {
				return err
			}
			if exit == 0 {
				break
			}
			if !strings.Contains(errb, "in use") || i >= 9 {
				errs = append(errs, fmt.Errorf("jail: docker volume rm %s: %s", vol, errb))
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	digests, _ := filepath.Glob(filepath.Join(j.state, "exports", project+".*.sha256"))
	seeds, _ := filepath.Glob(filepath.Join(j.state, "seeds", project+".*.tree"))
	for _, d := range append(digests, seeds...) {
		os.Remove(d)
	}
	return errors.Join(errs...)
}
