package workplace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The egress service of v2.1 (docs/design/v2/egress.md): one container in the workers VM, its network and its
// three volumes. Only `egress up` creates them; a call mounts nothing of them but its own socket's subpath, read-only.
const (
	EgressContainer    = "rwp-egress"
	EgressImage        = "remote-workplace/egress:1"
	EgressNetwork      = "rwp-egress-net"
	EgressSockVolume   = "rwp-egress-sock"
	EgressPolicyVolume = "rwp-egress-policy"
	EgressCacheVolume  = "rwp-egress-cache"
	KindEgress         = "egress"

	egressUser = "10002:10002"
	// egressProject labels the workplace's own calls on the policy volume that belong to no project (egress up).
	egressProject = "rwp-egress"
)

// egressConfirmWait bounds how long policy set waits for the service to report the stored id; egressPoll is the
// interval between two asks. Tests shorten them.
var (
	egressConfirmWait = 30 * time.Second
	egressPoll        = 250 * time.Millisecond
)

// egressPolicyScript runs in a hardened call that mounts only the policy volume at /work. It keeps the volume root
// readable by the service (0755) and writes <P>.<W>.json by atomic rename, or removes it.
const egressPolicyScript = `set -eu
chmod 0755 /work
case "$1" in
put) cat > "/work/.$2.tmp"; chmod 0644 "/work/.$2.tmp"; mv -f "/work/.$2.tmp" "/work/$2.json" ;;
rm) rm -f "/work/$2.json" ;;
init) ;;
*) exit 2 ;;
esac
`

func egressKey(r Ref) string { return r.Project + "." + r.Worker }

var policyIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// egressRunArgs is the `docker run` of the service container: hardened like a call, except that it has its own
// network with a public resolver (the Appendix A exception), runs as uid 10002 and keeps its logs (driver local).
func egressRunArgs() []string {
	return []string{"run", "-d", "--name", EgressContainer,
		"--label", LabelRoot + "=1", "--label", LabelKind + "=" + KindEgress,
		"--network", EgressNetwork, "--dns", "1.1.1.1",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", egressUser,
		"--cpus", "1", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "256",
		"--ulimit", "nofile=8192:8192", "--ulimit", "core=0:0",
		"--log-driver", "local", "--log-opt", "max-size=20m", "--log-opt", "max-file=5",
		"--restart", "unless-stopped",
		"--mount", "type=volume,src=" + EgressSockVolume + ",dst=/egress/sock",
		"--mount", "type=volume,src=" + EgressPolicyVolume + ",dst=/egress/policy,readonly",
		"--mount", "type=volume,src=" + EgressCacheVolume + ",dst=/egress/cache",
		EgressImage, "serve", "--sockroot", "/egress/sock", "--policydir", "/egress/policy", "--cachedir", "/egress/cache"}
}

// EgressUp creates the egress network, the three volumes and the service container, or starts a stopped one.
// It is idempotent. The policy volume is initialised by a hardened call before the service first mounts it.
func (j *Workplace) EgressUp(ctx context.Context) error {
	if err := migrationGuard(j.state); err != nil {
		return err
	}
	// Refuse imported volumes before network creation or any other write.
	for _, vol := range []string{EgressSockVolume, EgressPolicyVolume, EgressCacheVolume} {
		if _, _, err := j.volumeLabels(ctx, vol); err != nil {
			return err
		}
	}
	if _, errb, exit, err := j.dockerOut(ctx, nil, "network", "inspect", "--format", "{{.Name}}", EgressNetwork); err != nil {
		return err
	} else if exit != 0 {
		if !strings.Contains(strings.ToLower(errb), "not found") {
			return fmt.Errorf("workplace: docker network inspect %s: %s", EgressNetwork, errb)
		}
		if _, errb, exit, err := j.dockerOut(ctx, nil, "network", "create", "--driver", "bridge",
			"--label", LabelRoot+"=1", "--label", LabelKind+"="+KindEgress, EgressNetwork); err != nil {
			return err
		} else if exit != 0 {
			return fmt.Errorf("workplace: docker network create %s: %s", EgressNetwork, errb)
		}
	}
	for _, vol := range []string{EgressSockVolume, EgressPolicyVolume, EgressCacheVolume} {
		_, ok, err := j.volumeLabels(ctx, vol)
		if err != nil {
			return err
		}
		if !ok {
			if err := j.volumeCreate(ctx, vol, LabelRoot+"="+"1", LabelKind+"="+KindEgress, LabelCreated+"="+now()); err != nil {
				return err
			}
		}
	}
	if err := j.egressFile(ctx, egressProject, "init", "", nil); err != nil {
		return err
	}
	state, err := j.egressState(ctx)
	if err != nil {
		return err
	}
	args := egressRunArgs()
	switch state {
	case "running":
		return nil
	case "":
	default:
		args = []string{"start", EgressContainer}
	}
	if _, errb, exit, err := j.dockerOut(ctx, nil, args...); err != nil {
		return err
	} else if exit != 0 {
		return fmt.Errorf("workplace: docker %s %s: %s", args[0], EgressContainer, errb)
	}
	return nil
}

// EgressDown removes the service container. Volumes (policies, sockets, caches) and the network stay; without the
// service every socket vanishes and Run of a network-enabled policy fails with ErrEgressUnavailable.
func (j *Workplace) EgressDown(ctx context.Context) error {
	if err := migrationGuard(j.state); err != nil {
		return err
	}
	_, errb, exit, err := j.dockerOut(ctx, nil, "rm", "-f", EgressContainer)
	if err != nil {
		return err
	}
	if exit != 0 && !strings.Contains(strings.ToLower(errb), "no such container") {
		return fmt.Errorf("workplace: docker rm %s: %s", EgressContainer, errb)
	}
	return nil
}

// egressState returns the service container's state ("running", "exited", ...), or "" if it does not exist.
func (j *Workplace) egressState(ctx context.Context) (string, error) {
	out, errb, exit, err := j.dockerOut(ctx, nil, "inspect", "--type", "container", "--format", "{{.State.Status}}", EgressContainer)
	if err != nil {
		return "", err
	}
	if exit != 0 {
		if strings.Contains(strings.ToLower(errb), "no such") {
			return "", nil
		}
		return "", fmt.Errorf("workplace: docker inspect %s: %s", EgressContainer, errb)
	}
	return strings.TrimSpace(out), nil
}

// EgressWorker is one stored policy that needs egress, with the id the service serves for it ("" for none).
type EgressWorker struct {
	Ref
	Mode, Stored, Loaded string
}

// EgressReport is the state of the service and of every stored policy that needs it.
type EgressReport struct {
	State   string // the container's state, "" if it does not exist
	Workers []EgressWorker
}

// EgressStatus reports the service's state and, for each stored policy whose mode is not none, the id it serves.
func (j *Workplace) EgressStatus(ctx context.Context) (EgressReport, error) {
	if err := migrationGuard(j.state); err != nil {
		return EgressReport{}, err
	}
	var rep EgressReport
	state, err := j.egressState(ctx)
	if err != nil {
		return rep, err
	}
	rep.State = state
	for _, p := range j.networkPolicies() {
		w := EgressWorker{Ref: Ref{p.Project, p.Worker}, Mode: p.Network.Mode, Stored: p.ID()}
		if state == "running" {
			w.Loaded, _ = j.EgressLoaded(ctx, w.Ref)
		}
		rep.Workers = append(rep.Workers, w)
	}
	return rep, nil
}

// EgressLogFilter selects egress log lines; empty fields match everything. Since is passed to `docker logs --since`.
type EgressLogFilter struct {
	Project, Worker, Since string
}

// EgressLog copies the service's JSON log lines (`docker logs`) that match f to w.
func (j *Workplace) EgressLog(ctx context.Context, f EgressLogFilter, w io.Writer) error {
	if err := migrationGuard(j.state); err != nil {
		return err
	}
	for _, n := range []string{f.Project, f.Worker} {
		if n != "" {
			if err := ValidName(n); err != nil {
				return err
			}
		}
	}
	args := []string{"logs"}
	if f.Since != "" {
		if strings.HasPrefix(f.Since, "-") || strings.ContainsAny(f.Since, " \t\n") {
			return fmt.Errorf("workplace: invalid --since %q", f.Since)
		}
		args = append(args, "--since", f.Since)
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		var werr error
		for sc.Scan() {
			var l struct{ Project, Worker string }
			if json.Unmarshal(sc.Bytes(), &l) != nil || f.Project != "" && l.Project != f.Project || f.Worker != "" && l.Worker != f.Worker {
				continue
			}
			if werr == nil {
				_, werr = fmt.Fprintf(w, "%s\n", sc.Bytes())
			}
		}
		io.Copy(io.Discard, pr)
		done <- werr
	}()
	var errb bytes.Buffer
	exit, err := j.docker.Run(ctx, append(args, EgressContainer), nil, pw, &limitBuffer{buf: &errb, max: 1 << 20})
	pw.Close()
	werr := <-done
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("workplace: docker logs %s: %s", EgressContainer, tail(errb.Bytes()))
	}
	return werr
}

// imageRelay returns the egress-relay label of j's image ("" when the image has none).
func (j *Workplace) imageRelay(ctx context.Context) (string, error) {
	out, errb, exit, err := j.dockerOut(ctx, nil, "image", "inspect", "--format", "{{json .Config.Labels}}", j.image)
	if err != nil {
		return "", err
	}
	if exit != 0 {
		return "", fmt.Errorf("workplace: image %s missing (run `make image`): %s", j.image, errb)
	}
	labels := map[string]string{}
	if s := strings.TrimSpace(out); s != "" && s != "null" {
		if err := json.Unmarshal([]byte(s), &labels); err != nil {
			return "", fmt.Errorf("workplace: docker image inspect %s: %w", j.image, err)
		}
	}
	return labels[LabelEgressRelay], nil
}

// checkImageRelay fails with ErrImageNoRelay unless j's image carries the egress relay (base image v2), which a call
// under the network mode mode starts. Only a positive answer is cached, per image, for the Workplace's lifetime.
func (j *Workplace) checkImageRelay(ctx context.Context, mode string) error {
	j.relayMu.Lock()
	defer j.relayMu.Unlock()
	if j.relayOK[j.image] {
		return nil
	}
	relay, err := j.imageRelay(ctx)
	if err != nil {
		return err
	}
	if relay != EgressRelaySocat {
		return fmt.Errorf("%w: image %s lacks the label %s=%s that network mode %s needs; rebuild it FROM remote-workplace/base:2",
			ErrImageNoRelay, j.image, LabelEgressRelay, EgressRelaySocat, mode)
	}
	if j.relayOK == nil {
		j.relayOK = map[string]bool{}
	}
	j.relayOK[j.image] = true
	return nil
}

// networkPolicies returns the valid stored policies whose network mode is not none.
func (j *Workplace) networkPolicies() []Policy {
	files, _ := filepath.Glob(filepath.Join(j.state, "policies", "*.json"))
	var out []Policy
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if p, err := ParsePolicy(data); err == nil && p.Network.Mode != NetNone {
			out = append(out, p)
		}
	}
	return out
}

// EgressLoaded asks the running service which policy id it serves for r ("" for none). It fails with
// ErrEgressUnavailable when the service cannot be asked.
func (j *Workplace) EgressLoaded(ctx context.Context, r Ref) (string, error) {
	if err := migrationGuard(j.state); err != nil {
		return "", err
	}
	if err := r.validate(); err != nil {
		return "", err
	}
	out, errb, exit, err := j.dockerOut(ctx, nil, "exec", EgressContainer, "rwp-egress", "status", egressKey(r))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEgressUnavailable, err)
	}
	switch id := strings.TrimSpace(out); {
	case exit == 0 && policyIDRE.MatchString(id):
		return id, nil
	case exit == 3:
		return "", nil
	default:
		return "", fmt.Errorf("%w: the egress service did not answer (exit %d): %s", ErrEgressUnavailable, exit, errb)
	}
}

// checkEgressLoaded fails with ErrEgressUnavailable unless the service serves exactly p for r (Run, egress.md §6),
// so a stale service can neither widen nor silently narrow access.
func (j *Workplace) checkEgressLoaded(ctx context.Context, r Ref, p Policy) error {
	id, err := j.EgressLoaded(ctx, r)
	switch {
	case err != nil:
		return err
	case id == "":
		return fmt.Errorf("%w: the egress service serves no policy for %s (run `remote-workplace policy set` again)", ErrEgressUnavailable, egressKey(r))
	case id != p.ID():
		return fmt.Errorf("%w: the egress service serves %s for %s, the stored policy is %s (run `remote-workplace policy set` again)",
			ErrEgressUnavailable, id, egressKey(r), p.ID())
	}
	return nil
}

// egressFile writes (put), removes (rm) or only prepares (init) a file in the policy volume through a hardened call
// that mounts nothing else. The volume must exist: a missing one means `egress up` never ran.
func (j *Workplace) egressFile(ctx context.Context, project, op, key string, data []byte) error {
	_, ok, err := j.volumeLabels(ctx, EgressPolicyVolume)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: volume %s missing (run `remote-workplace egress up`)", ErrEgressUnavailable, EgressPolicyVolume)
	}
	argv := []string{"sh", "-c", egressPolicyScript, "sh", op}
	if key != "" {
		argv = append(argv, key)
	}
	res, errb, err := j.call(ctx, callSpec{Shape: shapeEgressPolicy, Project: project, Workdir: "/work",
		Timeout: time.Minute, Argv: argv}, bytes.NewReader(data), discard{}, 0)
	if err != nil {
		return err
	}
	if res.Exit != 0 || res.TimedOut {
		return fmt.Errorf("workplace: egress policy %s %s failed (exit %d, timed out %v): %s", op, key, res.Exit, res.TimedOut, tail(errb))
	}
	return nil
}

// egressSignal makes the service re-read the policy volume.
func (j *Workplace) egressSignal(ctx context.Context) error {
	_, errb, exit, err := j.dockerOut(ctx, nil, "kill", "-s", "HUP", EgressContainer)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEgressUnavailable, err)
	}
	if exit != 0 {
		return fmt.Errorf("%w: signalling %s: %s", ErrEgressUnavailable, EgressContainer, errb)
	}
	return nil
}

// deliverEgress writes p's whole file into the policy volume, signals the service and waits (bounded) until it
// reports p's id (egress.md §6).
func (j *Workplace) deliverEgress(ctx context.Context, r Ref, data []byte, p Policy) error {
	if err := j.egressFile(ctx, r.Project, "put", egressKey(r), data); err != nil {
		return err
	}
	if err := j.egressSignal(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(egressConfirmWait)
	for {
		id, err := j.EgressLoaded(ctx, r)
		if err == nil && id == p.ID() {
			return nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = fmt.Errorf("%w: the egress service did not confirm %s for %s within %v (it serves %q)",
					ErrEgressUnavailable, p.ID(), egressKey(r), egressConfirmWait, id)
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(egressPoll):
		}
	}
}

// withdrawEgress removes r's file from the policy volume and signals the service, which closes the listener and drops
// the worker's cache namespace. Without the volume there is nothing to withdraw; a service that is down reads the
// volume when it starts, so a failed signal is not an error.
func (j *Workplace) withdrawEgress(ctx context.Context, r Ref) error {
	if _, ok, err := j.volumeLabels(ctx, EgressPolicyVolume); err != nil || !ok {
		return err
	}
	if err := j.egressFile(ctx, r.Project, "rm", egressKey(r), nil); err != nil {
		return err
	}
	j.egressSignal(ctx)
	return nil
}

// egressContainer is the part of `docker inspect` that doctor checks.
type egressContainer struct {
	State  struct{ Running bool }
	Config struct {
		User, Image string
	}
	HostConfig struct {
		ReadonlyRootfs, Privileged bool
		CapDrop, CapAdd            []string
		SecurityOpt                []string
		Memory                     int64
		PidsLimit                  *int64
		NetworkMode                string
		LogConfig                  struct{ Type string }
		Binds                      []string
	}
	Mounts []struct {
		Type, Name, Destination string
		RW                      bool
	}
}

// checkEgressHardening reports whether the service container runs with its hardening (egress.md §2).
func checkEgressHardening(js string) (bool, string) {
	var c egressContainer
	if err := json.Unmarshal([]byte(js), &c); err != nil {
		return false, "unparsable docker inspect: " + err.Error()
	}
	h := c.HostConfig
	user, _, _ := strings.Cut(c.Config.User, ":")
	var bad []string
	add := func(cond bool, what string) {
		if !cond {
			bad = append(bad, what)
		}
	}
	add(c.State.Running, "not running")
	add(c.Config.Image == EgressImage, "image "+c.Config.Image+", want "+EgressImage)
	add(h.ReadonlyRootfs, "rootfs writable")
	add(slices.ContainsFunc(h.CapDrop, func(s string) bool { return strings.EqualFold(s, "ALL") }), "capabilities not dropped")
	add(len(h.CapAdd) == 0, "capabilities added")
	add(!h.Privileged, "privileged")
	add(slices.ContainsFunc(h.SecurityOpt, func(s string) bool { return s == "no-new-privileges" || s == "no-new-privileges:true" }), "no-new-privileges unset")
	add(user != "" && user != "0" && user != "root", "runs as root")
	add(h.Memory > 0, "no memory limit")
	add(h.PidsLimit != nil && *h.PidsLimit > 0, "no pids limit")
	add(h.LogConfig.Type == "local", "log driver "+h.LogConfig.Type+", want local")
	add(h.NetworkMode == EgressNetwork, "network "+h.NetworkMode+", want "+EgressNetwork)
	add(len(h.Binds) == 0, "bind mounts")
	want := map[string]bool{"/egress/sock": true, "/egress/policy": false, "/egress/cache": true} // destination: rw
	vols := map[string]string{"/egress/sock": EgressSockVolume, "/egress/policy": EgressPolicyVolume, "/egress/cache": EgressCacheVolume}
	for _, m := range c.Mounts {
		rw, ok := want[m.Destination]
		add(ok && m.Type == "volume" && m.Name == vols[m.Destination] && m.RW == rw, "unexpected mount "+m.Type+" "+m.Name+" at "+m.Destination)
		delete(want, m.Destination)
	}
	add(len(want) == 0, "missing mounts")
	if len(bad) > 0 {
		return false, EgressContainer + ": " + strings.Join(bad, "; ")
	}
	return true, EgressContainer + " hardened (read-only, no caps, no-new-privileges, non-root, limits, log driver local)"
}
