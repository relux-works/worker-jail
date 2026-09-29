package jail

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// SeedCache extracts a tar into the project's cache volume, inside a call.
func (j *Jail) SeedCache(ctx context.Context, project, name string, tr io.Reader) error {
	if err := ValidName(project); err != nil {
		return err
	}
	if err := ValidName(name); err != nil {
		return err
	}
	unlock, err := j.lockPath(ctx, "cache."+project+"."+name)
	if err != nil {
		return err
	}
	defer unlock()
	vol := CacheVolume(project, name)
	_, ok, err := j.volumeLabels(ctx, vol)
	if err != nil {
		return err
	}
	if !ok {
		if err := j.volumeCreate(ctx, vol, LabelRoot+"=1", LabelKind+"="+KindCache, LabelProject+"="+project,
			LabelCache+"="+name, LabelCreated+"="+now()); err != nil {
			return err
		}
	}
	res, errb, err := j.call(ctx, callSpec{Shape: shapeSeed, Project: project, Cache: name, Workdir: "/work",
		Timeout: seedTimeout, Argv: []string{"tar", "-x", "-f", "-", "-C", "/work"}}, tr, discard{}, 0)
	if err != nil {
		return err
	}
	if res.Exit != 0 || res.TimedOut {
		return fmt.Errorf("jail: seed %s failed (exit %d, timed out %v): %s", vol, res.Exit, res.TimedOut, tail(errb))
	}
	return nil
}

// SeedGoMod downloads the base revision's module graph with the host's Go and seeds cache "gomod" with it.
func (j *Jail) SeedGoMod(ctx context.Context, project, repo, refName string) error {
	if err := ValidName(project); err != nil {
		return err
	}
	base, _, err := resolveBase(ctx, repo, refName)
	if err != nil {
		return err
	}
	return j.seedGoModFrom(ctx, project, func(src string) error {
		return extractArchive(ctx, hostEnv(), base, src, "-C", repo)
	})
}

// SeedGoModWorktree is SeedGoMod with a snapshot of repo's working tree as the source tree.
func (j *Jail) SeedGoModWorktree(ctx context.Context, project, repo string) error {
	if err := ValidName(project); err != nil {
		return err
	}
	snap, err := snapshotWorktree(ctx, repo)
	if err != nil {
		return err
	}
	defer snap.Cleanup()
	return j.seedGoModFrom(ctx, project, func(src string) error {
		return extractArchive(ctx, append(hostEnv(), "GIT_DIR="+snap.seed.gitDir), snap.Snap, src)
	})
}

// seedGoModFrom downloads the module graph of the tree that extract writes into src and seeds cache "gomod".
func (j *Jail) seedGoModFrom(ctx context.Context, project string, extract func(src string) error) error {
	tmp, err := os.MkdirTemp("", "wj-gomod-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	src, mod := filepath.Join(tmp, "src"), filepath.Join(tmp, "mod")
	if err := extract(src); err != nil {
		return err
	}
	hostMod, err := goEnv(ctx, "GOMODCACHE")
	if err != nil {
		return err
	}
	hostProxy, err := goEnv(ctx, "GOPROXY")
	if err != nil {
		return err
	}
	env := append(hostEnv(), "GOMODCACHE="+mod, "GOFLAGS=-modcacherw", "GOTOOLCHAIN=local", "CGO_ENABLED=0",
		"GOPROXY=file://"+filepath.ToSlash(filepath.Join(hostMod, "cache", "download"))+","+hostProxy)
	for _, args := range [][]string{{"mod", "download"}, {"list", "-deps", "-test", "./..."}} {
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir, cmd.Env, cmd.Stdout = src, env, io.Discard
		var errb limitBuffer
		errb.buf, errb.max = new(bytes.Buffer), 1<<20
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			return &cmdError{"go " + strings.Join(args, " "), err, errb.buf.Bytes()}
		}
	}
	if err := os.MkdirAll(mod, 0o755); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeTar(mod, pw)) }()
	err = j.SeedCache(ctx, project, "gomod", pr)
	pr.CloseWithError(errors.New("seed finished"))
	return err
}

func goEnv(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", name)
	cmd.Env = hostEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("jail: go env %s: %w", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// extractArchive extracts `git [gitArgs] archive` of rev, run with env, into dst: regular files and
// directories; links are skipped.
func extractArchive(ctx context.Context, env []string, rev, dst string, gitArgs ...string) error {
	cmd := exec.CommandContext(ctx, "git", append(gitArgs, "archive", "--format=tar", rev)...)
	var errb limitBuffer
	errb.buf, errb.max = new(bytes.Buffer), 1<<20
	cmd.Stderr, cmd.Env = &errb, env
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	xerr := untar(pipe, dst)
	io.Copy(io.Discard, pipe)
	werr := cmd.Wait()
	if xerr != nil {
		return xerr
	}
	if werr != nil {
		return &cmdError{"git archive", werr, errb.buf.Bytes()}
	}
	return nil
}

func untar(r io.Reader, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("jail: archive: %w", err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name := h.Name
		if path.IsAbs(name) || strings.HasPrefix(name, "/") {
			return fmt.Errorf("jail: archive: absolute path %q", name)
		}
		for _, c := range strings.Split(name, "/") {
			if c == ".." {
				return fmt.Errorf("jail: archive: path %q escapes", name)
			}
		}
		target := filepath.Join(dst, filepath.FromSlash(path.Clean(name)))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, fs.FileMode(h.Mode)&0o755|0o600)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(f, tr)
			if err := errors.Join(cerr, f.Close()); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Links are skipped: nothing is created for them.
		default:
			return fmt.Errorf("jail: archive: unsupported entry %q (type %c)", name, h.Typeflag)
		}
	}
}

// writeTar writes root's directories and regular files as a tar with relative paths and modes kept.
func writeTar(root string, w io.Writer) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsDir() && !info.Mode().IsRegular() {
			return nil
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), Mode: int64(info.Mode().Perm()), ModTime: info.ModTime(), Format: tar.FormatPAX}
		if info.IsDir() {
			h.Typeflag, h.Name = tar.TypeDir, h.Name+"/"
			return tw.WriteHeader(h)
		}
		h.Typeflag, h.Size = tar.TypeReg, info.Size()
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	return tw.Close()
}
