package workplace

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

var shareTypes = map[string]bool{"virtiofs": true, "9p": true, "sshfs": true, "nfs": true, "nfs4": true, "cifs": true, "smb3": true}

// checkShares validates the VM's /proc/mounts: the only host share allowed is colima's cache, read-only.
func checkShares(mounts, home string) (bool, string) {
	allowed := filepath.Join(home, "Library", "Caches", "colima")
	var bad []string
	for _, line := range splitLines(mounts) {
		f := strings.Fields(line)
		if len(f) < 4 {
			bad = append(bad, "unparsable: "+line)
			continue
		}
		fstype := f[2]
		if !shareTypes[fstype] && !strings.HasPrefix(fstype, "fuse.") && fstype != "fuse" {
			continue
		}
		ro := false
		for _, o := range strings.Split(f[3], ",") {
			ro = ro || o == "ro"
		}
		if unescapeMount(f[1]) == allowed && ro {
			continue
		}
		bad = append(bad, line)
	}
	if len(bad) > 0 {
		return false, "unexpected host shares: " + strings.Join(bad, "; ")
	}
	return true, "only colima's read-only image cache is shared"
}

// unescapeMount decodes /proc/mounts octal escapes such as \040.
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Doctor runs every check and fails with ErrDoctor if any fails. The relay check reports whether the image
// carries the egress relay and fails only when a stored policy has a network mode other than none; the egress check
// runs only then. This is the operator's view of the whole state dir.
func (j *Workplace) Doctor(ctx context.Context) (DoctorReport, error) {
	if err := migrationGuard(j.state); err != nil {
		return DoctorReport{}, err
	}
	return j.doctor(ctx, len(j.networkPolicies()) > 0)
}

// doctor runs the checks; the relay and egress checks must pass only when needEgress. Provision passes whether the
// worker it provisions needs egress, so one worker's egress policy never blocks an offline worker on an older image
// or while the egress service is down.
func (j *Workplace) doctor(ctx context.Context, needEgress bool) (DoctorReport, error) {
	var rep DoctorReport
	add := func(name string, ok bool, detail string) { rep.Checks = append(rep.Checks, Check{name, ok, detail}) }

	out, errb, exit, err := j.dockerOut(ctx, nil, "info", "--format", "{{.Name}}\t{{.Driver}}\t{{.NCPU}}")
	switch f := strings.Split(strings.TrimSpace(out), "\t"); {
	case err != nil:
		add("endpoint", false, "docker: "+err.Error())
	case exit != 0:
		add("endpoint", false, "docker info: "+errb)
	case len(f) < 2 || f[0] != "colima-workers" || f[1] != "overlay2":
		add("endpoint", false, fmt.Sprintf("want colima-workers/overlay2, got %q", strings.TrimSpace(out)))
	default:
		add("endpoint", true, "colima-workers, overlay2")
	}

	if mounts, err := j.colima.ProcMounts(ctx); err != nil {
		add("vm-shares", false, err.Error())
	} else {
		ok, d := checkShares(mounts, j.home)
		add("vm-shares", ok, d)
	}

	out, errb, exit, err = j.dockerOut(ctx, nil, "image", "inspect", "--format", "{{json .Config.Volumes}}", j.image)
	switch v := strings.TrimSpace(out); {
	case err != nil:
		add("image", false, "docker: "+err.Error())
	case exit != 0:
		add("image", false, fmt.Sprintf("image %s missing (run `make image`): %s", j.image, errb))
	case v != "null" && v != "{}":
		add("image", false, fmt.Sprintf("image %s declares VOLUME %s", j.image, v))
	default:
		add("image", true, j.image)
	}

	switch relay, err := j.imageRelay(ctx); {
	case err != nil:
		add("relay", !needEgress, err.Error())
	case relay != EgressRelaySocat:
		add("relay", !needEgress, fmt.Sprintf("image %s lacks the label %s=%s (offline workers only); rebuild it FROM remote-workplace/base:2 for egress",
			j.image, LabelEgressRelay, EgressRelaySocat))
	default:
		add("relay", true, fmt.Sprintf("image %s carries the egress relay (%s)", j.image, relay))
	}

	if needEgress {
		out, errb, exit, err = j.dockerOut(ctx, nil, "inspect", "--type", "container", "--format", "{{json .}}", EgressContainer)
		switch {
		case err != nil:
			add("egress", false, "docker: "+err.Error())
		case exit != 0:
			add("egress", false, fmt.Sprintf("%s missing (run `remote-workplace egress up`): %s", EgressContainer, errb))
		default:
			ok, d := checkEgressHardening(out)
			add("egress", ok, d)
		}
	}

	for _, c := range rep.Checks {
		if !c.OK {
			return rep, fmt.Errorf("%w: %s: %s", ErrDoctor, c.Name, c.Detail)
		}
	}
	return rep, nil
}
