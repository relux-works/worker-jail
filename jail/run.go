package jail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
)

// Run executes argv in a fresh container against the workspace. It errors only when the jail itself failed.
func (j *Jail) Run(ctx context.Context, r Ref, s RunSpec) (Result, error) {
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if len(s.Argv) == 0 {
		return Result{}, errors.New("jail: empty argv")
	}
	if s.Timeout == 0 {
		s.Timeout = DefaultTimeout
	}
	if s.Timeout < 0 || s.Timeout > MaxTimeout {
		return Result{}, fmt.Errorf("jail: timeout %v outside (0, %v]", s.Timeout, MaxTimeout)
	}
	if s.MaxOutput == 0 {
		s.MaxOutput = DefaultMaxOutput
	}
	if s.MaxOutput < 0 {
		return Result{}, errors.New("jail: negative max output")
	}
	vol := WorkspaceVolume(r.Project, r.Worker)
	if _, ok, err := j.volumeLabels(ctx, vol); err != nil {
		return Result{}, err
	} else if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrNoWorkspace, vol)
	}
	caches, err := j.caches(ctx, r.Project)
	if err != nil {
		return Result{}, err
	}
	var out bytes.Buffer
	res, _, err := j.call(ctx, callSpec{Shape: shapeCall, Project: r.Project, Worker: r.Worker, Workdir: "/work/src",
		Caches: caches, Timeout: s.Timeout, Argv: s.Argv}, s.Stdin, &out, s.MaxOutput)
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
