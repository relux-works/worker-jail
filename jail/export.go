package jail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const exportScript = `set -eu
set -o pipefail
objs=$(git rev-parse --git-path objects); case "$objs" in /*) ;; *) objs="$PWD/$objs";; esac
mkdir -p /tmp/wj-objects
export GIT_INDEX_FILE=/tmp/wj-export.idx GIT_OBJECT_DIRECTORY=/tmp/wj-objects GIT_ALTERNATE_OBJECT_DIRECTORIES="$objs"
G="git -c core.fsmonitor=false -c core.untrackedCache=false -c core.hooksPath=/dev/null -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.suppressBlankEmpty=false"
$G read-tree "$1"
$G ls-files -z --others --exclude-standard | xargs -0 -r $G add -N --
$G diff --binary --full-index --no-color --no-ext-diff --no-textconv --no-renames --no-relative --src-prefix=a/ --dst-prefix=b/ "$1"
`

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func (j *Jail) digestPath(r Ref) string {
	return filepath.Join(j.state, "exports", r.Project+"."+r.Worker+".sha256")
}

// Export writes the patch from base to the workspace into w and records its digest.
func (j *Jail) Export(ctx context.Context, r Ref, w io.Writer) (ExportInfo, error) {
	if err := r.validate(); err != nil {
		return ExportInfo{}, err
	}
	return j.export(ctx, r, w, true)
}

type counter struct{ n int64 }

func (c *counter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func (j *Jail) export(ctx context.Context, r Ref, w io.Writer, record bool) (ExportInfo, error) {
	vol := WorkspaceVolume(r.Project, r.Worker)
	labels, ok, err := j.volumeLabels(ctx, vol)
	if err != nil {
		return ExportInfo{}, err
	}
	if !ok {
		return ExportInfo{}, fmt.Errorf("%w: %s", ErrNoWorkspace, vol)
	}
	info := ExportInfo{Base: labels[LabelBase]}
	if !shaRE.MatchString(info.Base) {
		return info, fmt.Errorf("jail: workspace %s has no valid base label", vol)
	}
	h, n := sha256.New(), &counter{}
	res, errb, err := j.call(ctx, callSpec{Shape: shapeReadOnly, Project: r.Project, Worker: r.Worker, Workdir: "/work/src",
		Timeout: DefaultTimeout, Argv: []string{"sh", "-c", exportScript, "sh", info.Base}}, nil, io.MultiWriter(w, h, n), ExportCap)
	info.Bytes = n.n
	if err != nil {
		return info, err
	}
	if res.Truncated {
		return info, fmt.Errorf("%w: %s", ErrExportTooLarge, vol)
	}
	if res.Exit != 0 || res.TimedOut {
		return info, fmt.Errorf("jail: export %s failed (exit %d, timed out %v): %s", vol, res.Exit, res.TimedOut, tail(errb))
	}
	info.SHA256 = hex.EncodeToString(h.Sum(nil))
	if record {
		if err := writeAtomic(j.digestPath(r), []byte(info.SHA256+"\n")); err != nil {
			return info, err
		}
	}
	return info, nil
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
