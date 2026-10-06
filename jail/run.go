package jail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Run executes argv in a fresh container against the workspace. It errors only when the jail itself failed.
// It re-reads the stored policy and fails closed before any container starts if the policy is gone or differs
// from the one the workspace was provisioned under; then it applies the policy's access and limits.
// For a network mode other than none it also fails closed (ErrEgressUnavailable) unless the egress service serves
// exactly the stored policy, and (ErrImageNoRelay) unless the image carries the relay; the call then gets the
// worker's socket (read-only), the mode's env and the relay.
func (j *Jail) Run(ctx context.Context, r Ref, s RunSpec) (Result, error) {
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if len(s.Argv) == 0 {
		return Result{}, errors.New("jail: empty argv")
	}
	pol, err := j.LoadPolicy(r)
	if err != nil {
		return Result{}, err
	}
	pl := pol.Limits
	policyTimeout := time.Duration(pl.CallTimeoutS) * time.Second
	if s.Timeout == 0 {
		s.Timeout = policyTimeout
	}
	if s.Timeout < 0 || s.Timeout > MaxTimeout {
		return Result{}, fmt.Errorf("jail: timeout %v outside (0, %v]", s.Timeout, MaxTimeout)
	}
	if s.Timeout > policyTimeout {
		return Result{}, fmt.Errorf("jail: timeout %v exceeds the policy's call_timeout_s %d", s.Timeout, pl.CallTimeoutS)
	}
	if s.MaxOutput == 0 {
		s.MaxOutput = int(pl.MaxOutputBytes)
	}
	if s.MaxOutput < 0 {
		return Result{}, errors.New("jail: negative max output")
	}
	if int64(s.MaxOutput) > pl.MaxOutputBytes {
		return Result{}, fmt.Errorf("jail: max output %d exceeds the policy's max_output_bytes %d", s.MaxOutput, pl.MaxOutputBytes)
	}
	vol := WorkspaceVolume(r.Project, r.Worker)
	labels, ok, err := j.volumeLabels(ctx, vol)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrNoWorkspace, vol)
	}
	switch id := labels[LabelPolicyID]; {
	case id == "":
		return Result{}, fmt.Errorf("%w: %s has no policy label (provisioned before v2.0); export, deprovision and provision it again", ErrPolicyChanged, vol)
	case id != pol.ID():
		return Result{}, fmt.Errorf("%w: %s was provisioned under %s, the stored policy is %s; export, deprovision and provision it again",
			ErrPolicyChanged, vol, id, pol.ID())
	}
	egress := ""
	if pol.Network.Mode != NetNone {
		egress = pol.Network.Mode
		if err := j.checkImageRelay(ctx, egress); err != nil {
			return Result{}, err
		}
		if err := j.checkEgressLoaded(ctx, r, pol); err != nil {
			return Result{}, err
		}
	}
	caches, err := j.caches(ctx, r.Project)
	if err != nil {
		return Result{}, err
	}
	lim := j.limits
	lim.CPUs, lim.Memory, lim.Pids = pl.CPUs, pl.MemoryMiB<<20, int(pl.Pids)
	var out bytes.Buffer
	res, _, err := j.call(ctx, callSpec{Shape: shapeCall, Project: r.Project, Worker: r.Worker, Workdir: "/work/src",
		ReadOnly: pol.Workspace.Access == "read-only", Egress: egress, Limits: lim, Caches: caches, Timeout: s.Timeout, Argv: s.Argv},
		s.Stdin, &out, s.MaxOutput)
	res.Stdout = out.Bytes()
	return res, err
}

const cacheNameFormat = `{{.Label "` + LabelCache + `"}}`

// caches lists the names of P's cache volumes.
func (j *Jail) caches(ctx context.Context, project string) ([]string, error) {
	out, errb, exit, err := j.dockerOut(ctx, nil, "volume", "ls", "--filter", "label="+LabelKind+"="+KindCache,
		"--filter", "label="+LabelProject+"="+project, "--format", cacheNameFormat)
	if err != nil {
		return nil, err
	}
	if exit != 0 {
		return nil, fmt.Errorf("jail: docker volume ls: %s", errb)
	}
	var names []string
	for _, n := range splitLines(out) {
		if ValidName(n) == nil {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}
