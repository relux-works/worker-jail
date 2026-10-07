package workplace

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Docker runs the docker CLI (or a fake of it).
type Docker interface {
	// Run executes `docker <args>`; exit is the CLI's exit status. err only if the CLI could not run.
	Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (exit int, err error)
}

// Colima reads the workers VM's /proc/mounts.
type Colima interface {
	ProcMounts(ctx context.Context) (string, error)
}

// DockerCLI is the docker CLI pinned to the workers VM with an empty client config.
type DockerCLI struct{ Env []string }

// Endpoint is the docker endpoint of the workers VM.
func Endpoint(home string) string {
	return "unix://" + filepath.Join(home, ".colima", "workers", "docker.sock")
}

// NewDockerCLI builds a DockerCLI whose environment is exactly PATH, HOME, DOCKER_HOST and DOCKER_CONFIG.
func NewDockerCLI(home, dockerConfig string) DockerCLI {
	return DockerCLI{Env: []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"DOCKER_HOST=" + Endpoint(home),
		"DOCKER_CONFIG=" + dockerConfig,
	}}
}

func (d DockerCLI) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = d.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	return exitOf(cmd.Run())
}

func exitOf(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() >= 0 {
		return ee.ExitCode(), nil
	}
	return -1, err
}

// ColimaCLI reads /proc/mounts over `colima ssh -p workers`.
type ColimaCLI struct{}

func (ColimaCLI) ProcMounts(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "colima", "ssh", "-p", "workers", "--", "cat", "/proc/mounts")
	cmd.Dir = "/" // colima cds to the caller's cwd inside the VM
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", &cmdError{"colima ssh", err, errb.Bytes()}
	}
	return out.String(), nil
}

type cmdError struct {
	what   string
	err    error
	stderr []byte
}

func (e *cmdError) Error() string { return e.what + ": " + e.err.Error() + ": " + tail(e.stderr) }
func (e *cmdError) Unwrap() error { return e.err }

// dockerOut runs a short docker command and returns stdout and stderr (tail) as strings.
func (j *Workplace) dockerOut(ctx context.Context, stdin io.Reader, args ...string) (string, string, int, error) {
	if err := migrationGuard(j.state); err != nil {
		return "", "", -1, err
	}
	if len(args) > 0 && (args[0] == "create" || args[0] == "run" || args[0] == "volume" && len(args) > 1 && args[1] == "rm") {
		var volumes []string
		for i, arg := range args {
			if arg == "--mount" && i+1 < len(args) {
				for _, part := range strings.Split(args[i+1], ",") {
					if strings.HasPrefix(part, "src=") {
						volumes = append(volumes, strings.TrimPrefix(part, "src="))
					}
				}
			}
			if args[0] == "volume" && i > 1 && !strings.HasPrefix(arg, "-") {
				volumes = append(volumes, arg)
			}
		}
		for _, vol := range volumes {
			if _, _, err := j.volumeLabels(ctx, vol); err != nil {
				return "", "", -1, err
			}
		}
	}
	var out, errb bytes.Buffer
	exit, err := j.docker.Run(ctx, args, stdin, &out, &limitBuffer{buf: &errb, max: 1 << 20})
	return out.String(), tail(errb.Bytes()), exit, err
}

type limitBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.buf.Write(p[:room])
	}
	return len(p), nil
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
