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
func (j *Jail) Provision(ctx context.Context, s ProvisionSpec) (Workspace, error) {
	ws := Workspace{Ref: s.Ref, Volume: WorkspaceVolume(s.Project, s.Worker)}
	if err := s.Ref.validate(); err != nil {
		return ws, err
	}
	unlock, err := j.lockPath(ctx, "ws."+s.Project+"."+s.Worker)
	if err != nil {
		return ws, err
	}
	defer unlock()
	if _, err := j.Doctor(ctx); err != nil {
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
		ws.Created, _ = time.Parse(time.RFC3339, labels[LabelCreated])
		return ws, nil
	}
	if s.Repo == "" {
		return ws, errors.New("jail: provision needs a repo")
	}
	if s.FromWorktree && s.RefName != "" {
		return ws, errors.New("jail: FromWorktree and RefName are mutually exclusive")
	}
	var base string
	var bundle *exec.Cmd
	var extra []string
	if s.FromWorktree {
		snap, err := snapshotWorktree(ctx, s.Repo)
		if err != nil {
			return ws, err
		}
		defer snap.Cleanup()
		base = snap.Snap
		bundle = exec.CommandContext(ctx, "git", "bundle", "create", "-", "refs/heads/snapshot")
		bundle.Env = append(hostEnv(), "GIT_DIR="+snap.seed.gitDir)
		extra = []string{LabelSource + "=worktree", LabelHead + "=" + snap.Head}
	} else {
		b, fullref, err := resolveBase(ctx, s.Repo, s.RefName)
		if err != nil {
			return ws, err
		}
		if fullref == "" {
			return ws, fmt.Errorf("jail: ref %q resolves to a raw sha; RefName must be a branch, a tag or HEAD", s.RefName)
		}
		base = b
		bundle = exec.CommandContext(ctx, "git", "-C", s.Repo, "bundle", "create", "-", fullref)
		bundle.Env = hostEnv()
	}
	created := time.Now().UTC().Truncate(time.Second)
	vlabels := append([]string{LabelRoot + "=1", LabelKind + "=" + KindWorkspace, LabelProject + "=" + s.Project,
		LabelWorker + "=" + s.Worker, LabelBase + "=" + base, LabelCreated + "=" + created.Format(time.RFC3339)}, extra...)
	if err := j.volumeCreate(ctx, ws.Volume, vlabels...); err != nil {
		return ws, err
	}
	if err := j.cloneInto(ctx, s, base, bundle); err != nil {
		rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		j.dockerOut(rmCtx, nil, "volume", "rm", "-f", ws.Volume)
		return ws, err
	}
	ws.Base, ws.Created = base, created
	return ws, nil
}

// cloneInto streams bundle's stdout (a not yet started `git bundle create -`) into the provision script.
func (j *Jail) cloneInto(ctx context.Context, s ProvisionSpec, base string, bundle *exec.Cmd) error {
	var berr bytes.Buffer
	bundle.Stderr = &berr
	pipe, err := bundle.StdoutPipe()
	if err != nil {
		return err
	}
	if err := bundle.Start(); err != nil {
		return fmt.Errorf("jail: git bundle: %w", err)
	}
	email := s.Worker + "@" + s.Project + ".worker-jail.invalid"
	res, errb, cerr := j.call(ctx, callSpec{Shape: shapeCall, Project: s.Project, Worker: s.Worker, Workdir: "/work",
		Timeout: DefaultTimeout, Argv: []string{"sh", "-c", provisionScript, "sh", base, s.Worker, email}}, pipe, &bytes.Buffer{}, 0)
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

// Purge kills P's calls and removes all of P's volumes and digests.
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
	for _, d := range digests {
		os.Remove(d)
	}
	return errors.Join(errs...)
}
