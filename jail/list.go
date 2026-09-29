package jail

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const volumeFormat = `{{.Name}}\t{{.Label "` + LabelKind + `"}}\t{{.Label "` + LabelProject + `"}}\t{{.Label "` +
	LabelWorker + `"}}\t{{.Label "` + LabelCache + `"}}\t{{.Label "` + LabelBase + `"}}\t{{.Label "` + LabelCreated + `"}}`

const callFormat = `{{.ID}}\t{{.Label "` + LabelProject + `"}}\t{{.Label "` + LabelWorker + `"}}\t{{.Status}}`

func callFilters(project, worker string) []string {
	f := []string{"--filter", "label=" + LabelKind + "=" + KindCall}
	if project != "" {
		f = append(f, "--filter", "label="+LabelProject+"="+project)
	}
	if worker != "" {
		f = append(f, "--filter", "label="+LabelWorker+"="+worker)
	}
	return f
}

// List returns workspaces, caches and calls in flight ("" = every project).
func (j *Jail) List(ctx context.Context, project string) (Listing, error) {
	var l Listing
	args := []string{"volume", "ls", "--filter", "label=" + LabelRoot + "=1"}
	if project != "" {
		if err := ValidName(project); err != nil {
			return l, err
		}
		args = append(args, "--filter", "label="+LabelProject+"="+project)
	}
	out, errb, exit, err := j.dockerOut(ctx, nil, append(args, "--format", volumeFormat)...)
	if err != nil {
		return l, err
	}
	if exit != 0 {
		return l, fmt.Errorf("jail: docker volume ls: %s", errb)
	}
	for _, line := range splitLines(out) {
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		created, _ := time.Parse(time.RFC3339, f[6])
		switch f[1] {
		case KindWorkspace:
			l.Workspaces = append(l.Workspaces, Workspace{Ref: Ref{f[2], f[3]}, Volume: f[0], Base: f[5], Created: created})
		case KindCache:
			l.Caches = append(l.Caches, Cache{Project: f[2], Name: f[4], Volume: f[0], Created: created})
		}
	}
	out, errb, exit, err = j.dockerOut(ctx, nil, append(append([]string{"ps", "-a"}, callFilters(project, "")...), "--format", callFormat)...)
	if err != nil {
		return l, err
	}
	if exit != 0 {
		return l, fmt.Errorf("jail: docker ps: %s", errb)
	}
	for _, line := range splitLines(out) {
		if f := strings.Split(line, "\t"); len(f) >= 4 {
			l.Calls = append(l.Calls, Call{ID: f[0], Project: f[1], Worker: f[2], Status: f[3]})
		}
	}
	return l, nil
}

// Kill kills the calls in flight of project (and worker, if given). It returns how many it found.
func (j *Jail) Kill(ctx context.Context, project, worker string) (int, error) {
	for _, n := range []string{project, worker} {
		if n != "" {
			if err := ValidName(n); err != nil {
				return 0, err
			}
		}
	}
	if project == "" && worker != "" {
		return 0, fmt.Errorf("jail: kill by worker needs a project")
	}
	out, errb, exit, err := j.dockerOut(ctx, nil, append([]string{"ps", "-q"}, callFilters(project, worker)...)...)
	if err != nil {
		return 0, err
	}
	if exit != 0 {
		return 0, fmt.Errorf("jail: docker ps: %s", errb)
	}
	ids := splitLines(out)
	if len(ids) == 0 {
		return 0, nil
	}
	_, errb, exit, err = j.dockerOut(ctx, nil, append([]string{"kill"}, ids...)...)
	if err != nil {
		return 0, err
	}
	if exit != 0 && !strings.Contains(errb, "No such container") && !strings.Contains(errb, "is not running") {
		return 0, fmt.Errorf("jail: docker kill: %s", errb)
	}
	return len(ids), nil
}

// Usage returns the bytes a workspace uses.
func (j *Jail) Usage(ctx context.Context, r Ref) (int64, error) {
	if err := r.validate(); err != nil {
		return 0, err
	}
	vol := WorkspaceVolume(r.Project, r.Worker)
	if _, ok, err := j.volumeLabels(ctx, vol); err != nil {
		return 0, err
	} else if !ok {
		return 0, fmt.Errorf("%w: %s", ErrNoWorkspace, vol)
	}
	var out limitBuffer
	out.buf, out.max = new(bytes.Buffer), 4096
	res, errb, err := j.call(ctx, callSpec{Shape: shapeReadOnly, Project: r.Project, Worker: r.Worker, Workdir: "/work",
		Timeout: DefaultTimeout, Argv: []string{"du", "-skx", "/work"}}, nil, &out, 0)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(out.buf.String())
	if res.Exit != 0 || len(f) == 0 {
		return 0, fmt.Errorf("jail: usage %s failed (exit %d): %s", vol, res.Exit, tail(errb))
	}
	kib, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("jail: usage %s: %w", vol, err)
	}
	return kib * 1024, nil
}
