package workplace

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
	"slices"
	"strings"
)

// SeedCache extracts a tar into the project's cache volume, inside a call.
func (j *Workplace) SeedCache(ctx context.Context, project, name string, tr io.Reader) error {
	if err := migrationGuard(j.state); err != nil {
		return err
	}
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
		return fmt.Errorf("workplace: seed %s failed (exit %d, timed out %v): %s", vol, res.Exit, res.TimedOut, tail(errb))
	}
	return nil
}

// SeedGoMod downloads the base revision's module graph with the host's Go and seeds cache "gomod" with it.
func (j *Workplace) SeedGoMod(ctx context.Context, project, repo, refName string) error {
	if err := migrationGuard(j.state); err != nil {
		return err
	}
	if err := ValidName(project); err != nil {
		return err
	}
	base, _, err := resolveBase(ctx, repo, refName)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "rwp-gomod-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	src, mod := filepath.Join(tmp, "src"), filepath.Join(tmp, "mod")
	if err := extractArchive(ctx, repo, base, src); err != nil {
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

// SeedGoModWorktree seeds cache "gomod" from a snapshot of dir's worktree (worktree-seeding.md §3) and returns the
// snapshot tree, which the host records as the cache's seed (ls). The snapshot takes the same refusals and secret
// guard as provision --from-worktree; dir is never written. A dirty go.mod is unreviewed, so the module graph is
// downloaded without credentials: a fixed environment with an empty HOME, no .netrc, no GOPRIVATE and only the public
// proxy. A filesystem replace, a go.work, a toolchain line or a vendor/ that disagrees with go.mod is ErrSeed.
func (j *Workplace) SeedGoModWorktree(ctx context.Context, project, dir string, o SnapshotOptions) (string, error) {
	if err := migrationGuard(j.state); err != nil {
		return "", err
	}
	if err := ValidName(project); err != nil {
		return "", err
	}
	snap, err := takeSnapshot(ctx, dir, o, "")
	defer snap.close()
	if err != nil {
		return "", err
	}
	if err := snap.guard(ctx, o.AllowSecretPaths); err != nil {
		return "", err
	}
	if err := snap.checkGoModules(ctx); err != nil {
		return "", err
	}
	src, mod := filepath.Join(snap.tmp, "src"), filepath.Join(snap.tmp, "mod")
	if err := extractFrom(snap.cmd(ctx, "", "archive", "--format=tar", snap.Tree), src); err != nil {
		return "", err
	}
	env, err := worktreeGoEnv(snap.tmp)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(src, "vendor")); err == nil {
		venv := append(slices.Clone(env), "GOPROXY=off", "GOFLAGS=-modcacherw")
		if err := runGo(ctx, src, venv, "list", "-mod=vendor", "-deps", "./..."); err != nil {
			return "", fmt.Errorf("%w: vendor/ disagrees with go.mod: %v", ErrSeed, err)
		}
	}
	for _, args := range [][]string{{"mod", "download"}, {"list", "-deps", "-test", "./..."}} {
		if err := runGo(ctx, src, env, args...); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(mod, 0o755); err != nil {
		return "", err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeTar(mod, pw)) }()
	err = j.SeedCache(ctx, project, "gomod", pr)
	pr.CloseWithError(errors.New("seed finished"))
	if err != nil {
		return "", err
	}
	return snap.Tree, writeAtomic(j.seedPath(project, "gomod"), []byte(snap.Tree+"\n"))
}

func (j *Workplace) seedPath(project, name string) string {
	return filepath.Join(j.state, "seeds", project+"."+name+".tree")
}

// seedTree returns the snapshot tree of the last worktree seed of a cache, or "".
func (j *Workplace) seedTree(project, name string) string {
	b, err := os.ReadFile(j.seedPath(project, name))
	if t := strings.TrimSpace(string(b)); err == nil && shaRE.MatchString(t) {
		return t
	}
	return ""
}

// worktreeGoEnv is the whole environment of the Go commands of a worktree seed (no host variable but PATH):
// HOME, XDG_CONFIG_HOME, GOPATH, GOCACHE, GOMODCACHE and TMPDIR under tmp, the public proxy only, no auth, local
// toolchain. Telemetry is off in that HOME: otherwise go starts a telemetry process that outlives it and writes
// into tmp after it is removed.
func worktreeGoEnv(tmp string) ([]string, error) {
	env := []string{"PATH=" + os.Getenv("PATH"), "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly -modcacherw", "GOENV=off",
		"GOPRIVATE=", "GONOPROXY=", "GOPROXY=https://proxy.golang.org", "GOWORK=off", "GOAUTH=off", "CGO_ENABLED=0"}
	for _, d := range []struct{ name, dir string }{{"HOME", "home"}, {"XDG_CONFIG_HOME", "config"}, {"GOPATH", "gopath"},
		{"GOCACHE", "gocache"}, {"GOMODCACHE", "mod"}, {"TMPDIR", "gotmp"}} {
		p := filepath.Join(tmp, d.dir)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, err
		}
		env = append(env, d.name+"="+p)
	}
	for _, cfg := range []string{filepath.Join(tmp, "home", "Library", "Application Support"), filepath.Join(tmp, "config")} {
		mode := filepath.Join(cfg, "go", "telemetry", "mode")
		if err := os.MkdirAll(filepath.Dir(mode), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(mode, []byte("off\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return env, nil
}

func runGo(ctx context.Context, dir string, env []string, args ...string) error {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir, cmd.Env, cmd.Stdout = dir, env, io.Discard
	var errb limitBuffer
	errb.buf, errb.max = new(bytes.Buffer), 1<<20
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return &cmdError{"go " + strings.Join(args, " "), err, errb.buf.Bytes()}
	}
	return nil
}

// checkGoModules refuses a snapshot whose tree has a go.work, or a go.mod (at any depth) with a filesystem
// replace or a toolchain line. A root go.mod is required.
func (s *snapshot) checkGoModules(ctx context.Context) error {
	out, err := s.git(ctx, nil, "", "ls-tree", "-r", "-z", "--name-only", s.Tree)
	if err != nil {
		return err
	}
	var mods []string
	for _, p := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
		switch path.Base(p) {
		case "go.work":
			return fmt.Errorf("%w: %s: a workspace file pulls in modules outside go.mod", ErrSeed, p)
		case "go.mod":
			mods = append(mods, p)
		}
	}
	if !slices.Contains(mods, "go.mod") {
		return fmt.Errorf("%w: no go.mod at the top level", ErrSeed)
	}
	for _, p := range mods {
		data, err := s.git(ctx, nil, "", "cat-file", "blob", s.Tree+":"+p)
		if err != nil {
			return err
		}
		if why := goModRefusal(data); why != "" {
			return fmt.Errorf("%w: %s: %s", ErrSeed, p, why)
		}
	}
	return nil
}

// goModRefusal returns why a go.mod cannot seed a cache from an unreviewed worktree, or "": a toolchain line, or a
// replace whose target is a filesystem path (a target without a version), which would copy a host path into the cache.
func goModRefusal(data string) string {
	inReplace := false
	for _, line := range strings.Split(data, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		spec := ""
		switch {
		case inReplace && f[0] == ")":
			inReplace = false
			continue
		case inReplace:
			spec = line
		case f[0] == "toolchain":
			return "toolchain line"
		case f[0] == "replace" && len(f) == 2 && f[1] == "(", f[0] == "replace(" && len(f) == 1:
			inReplace = true
			continue
		case f[0] == "replace":
			spec = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "replace"))
		default:
			continue
		}
		_, target, ok := strings.Cut(spec, "=>")
		if !ok || len(modFields(target)) != 2 {
			return "replace to a filesystem path: " + strings.TrimSpace(spec)
		}
	}
	return ""
}

// modFields splits a go.mod line into tokens; a double- or back-quoted string is one token.
func modFields(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		end := strings.IndexAny(s, " \t")
		if q := s[0]; q == '"' || q == '`' {
			if i := strings.IndexByte(s[1:], q); i >= 0 {
				end = i + 2
			}
		}
		if end < 0 || end > len(s) {
			end = len(s)
		}
		out, s = append(out, s[:end]), s[end:]
	}
	return out
}

func goEnv(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", name)
	cmd.Env = hostEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("workplace: go env %s: %w", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// extractArchive extracts `git archive` of rev into dst: regular files and directories; links are skipped.
func extractArchive(ctx context.Context, repo, rev, dst string) error {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "archive", "--format=tar", rev)
	cmd.Env = hostEnv()
	return extractFrom(cmd, dst)
}

// extractFrom runs cmd, a `git archive --format=tar`, and extracts its output into dst.
func extractFrom(cmd *exec.Cmd, dst string) error {
	var errb limitBuffer
	errb.buf, errb.max = new(bytes.Buffer), 1<<20
	cmd.Stderr = &errb
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
			return fmt.Errorf("workplace: archive: %w", err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name := h.Name
		if path.IsAbs(name) || strings.HasPrefix(name, "/") {
			return fmt.Errorf("workplace: archive: absolute path %q", name)
		}
		for _, c := range strings.Split(name, "/") {
			if c == ".." {
				return fmt.Errorf("workplace: archive: path %q escapes", name)
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
			return fmt.Errorf("workplace: archive: unsupported entry %q (type %c)", name, h.Typeflag)
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
