package jail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The red-team suite (docs/protocol.md section 12). WJ_REDTEAM=1, image worker-jail/redteam:1 (`make image-redteam`).
// Every probe runs jailed (through Jail.Run, as uid 10001, default hardening: the attack must fail) and as a
// positive control (the same probe in a container that lacks only the blocking layer(s): the attack must succeed).
// Weakened containers are built here only, by transforming createArgs' argv; nothing weakened is reachable from
// the exported API or the CLI. Projects are named wjrt-*, extra volumes and containers carry the label wjrt=1.

const (
	rtImage  = "worker-jail/redteam:1"
	rtCanary = "wjrt-canary"
	rtLabel  = "wjrt=1"
)

type rtOutcome struct {
	OK       bool   `json:"ok"`
	Evidence string `json:"evidence"`
}

type rtRow struct {
	ID        string    `json:"id"`
	Guarantee string    `json:"guarantee"`
	Tries     string    `json:"tries"`
	Jailed    rtOutcome `json:"jailed"`  // OK: the attack was blocked (known limit: behaved as documented)
	Control   rtOutcome `json:"control"` // OK: the attack succeeded without the blocking layers
	Layers    []string  `json:"blocking_layers"`
	Known     bool      `json:"known_limit,omitempty"`
	Note      string    `json:"note,omitempty"`
	Verdict   string    `json:"verdict"`
}

type rtEnv struct {
	t      *testing.T
	ctx    context.Context
	j      *Jail
	home   string
	repo   string // host repo every workspace is provisioned from
	p, p2  string // projects
	a, b   Ref
	other  Ref    // workspace in project p2
	patchH []byte // export of the planted-hooks worker, reused by G8-hooks-apply
}

// argMod transforms a container argv (test-only weakening).
type argMod func([]string) []string

func (e *rtEnv) imageIdx(a []string) int {
	for i := 0; i+1 < len(a); i++ {
		if a[i] == e.j.image && a[i+1] == "timeout" {
			return i
		}
	}
	e.t.Fatalf("image not found in argv %q", a)
	return -1
}

// drop removes a flag whose value starts with val (or a boolean flag, if val is empty), before the image.
func (e *rtEnv) drop(name, val string) argMod {
	return func(a []string) []string {
		var out []string
		img := e.imageIdx(a)
		for i := 0; i < len(a); i++ {
			if i < img && a[i] == name {
				if val == "" {
					continue
				}
				if strings.HasPrefix(a[i+1], val) {
					i++
					continue
				}
			}
			out = append(out, a[i])
		}
		return out
	}
}

func (e *rtEnv) add(extra ...string) argMod {
	return func(a []string) []string {
		img := e.imageIdx(a)
		return append(append(append([]string{}, a[:img]...), extra...), a[img:]...)
	}
}

func (e *rtEnv) user(u string) argMod {
	return func(a []string) []string { return e.add("--user", u)(e.drop("--user", "10001")(a)) }
}

// noWrapper removes the in-container `timeout -s KILL N` wrapper.
func (e *rtEnv) noWrapper() argMod {
	return func(a []string) []string {
		img := e.imageIdx(a)
		return append(append([]string{}, a[:img+1]...), a[img+5:]...)
	}
}

func (e *rtEnv) rwCache(name string) argMod {
	return func(a []string) []string {
		out := append([]string{}, a...)
		for i, s := range out {
			if s == "type=volume,src="+CacheVolume(e.p, name)+",dst=/cache/"+name+",readonly" {
				out[i] = strings.TrimSuffix(s, ",readonly")
			}
		}
		return out
	}
}

func (e *rtEnv) canaryMount() argMod {
	return e.add("--mount", "type=volume,src="+rtCanary+",dst=/Users,readonly")
}

// ctrlArgs builds the jail's own argv for a call on r (createArgs), turned into `docker run` and weakened by mods.
func (e *rtEnv) ctrlArgs(r Ref, timeout time.Duration, argv []string, mods ...argMod) []string {
	caches, err := e.j.caches(e.ctx, r.Project)
	if err != nil {
		e.t.Fatal(err)
	}
	args, err := createArgs(callSpec{Shape: shapeCall, Name: newCallName(), Project: r.Project, Worker: r.Worker,
		Workdir: "/work/src", Caches: caches, Image: e.j.image, Limits: e.j.limits, Timeout: timeout, Argv: argv})
	if err != nil {
		e.t.Fatal(err)
	}
	args[0] = "run"
	args = e.add("--label", rtLabel)(args)
	for _, m := range mods {
		args = m(args)
	}
	return args
}

// ctrlWith runs a weakened control container through d and returns its combined output and exit status.
func (e *rtEnv) ctrlWith(d Docker, r Ref, timeout time.Duration, script string, mods ...argMod) (string, int) {
	args := e.ctrlArgs(r, timeout, []string{"sh", "-c", script}, mods...)
	ctx, cancel := context.WithTimeout(e.ctx, timeout+time.Minute)
	defer cancel()
	var buf bytes.Buffer
	exit, err := d.Run(ctx, args, strings.NewReader(""), &buf, &buf)
	if err != nil {
		e.t.Fatalf("control docker run: %v", err)
	}
	return buf.String(), exit
}

func (e *rtEnv) ctrl(r Ref, timeout time.Duration, script string, mods ...argMod) (string, int) {
	return e.ctrlWith(e.j.docker, r, timeout, script, mods...)
}

// jrun runs script jailed, exactly as a harness would.
func (e *rtEnv) jrunWith(j *Jail, r Ref, timeout time.Duration, script string) (Result, string) {
	res, err := j.Run(e.ctx, r, RunSpec{Argv: []string{"sh", "-c", script}, Timeout: timeout})
	if err != nil {
		e.t.Fatalf("jailed run: %v", err)
	}
	return res, string(res.Stdout) + string(res.Stderr)
}

func (e *rtEnv) jrun(r Ref, timeout time.Duration, script string) (Result, string) {
	return e.jrunWith(e.j, r, timeout, script)
}

type rtStep struct {
	layers []string
	mods   []argMod
}

// ladder tries weakenings in order and returns the first under which the control succeeds, with its layers.
func (e *rtEnv) ladder(r Ref, timeout time.Duration, script string, ok func(out string, exit int) bool, steps ...rtStep) (rtOutcome, []string, string) {
	var tried []string
	var last string
	for _, s := range steps {
		out, exit := e.ctrl(r, timeout, script, s.mods...)
		last = fmt.Sprintf("exit %d: %s", exit, out)
		if ok(out, exit) {
			note := ""
			if len(tried) > 0 {
				note = "not enough: " + strings.Join(tried, "; ")
			}
			if len(s.layers) > 1 {
				note = strings.TrimPrefix(note+"; defense in depth", "; ")
			}
			return rtOutcome{true, ev(last)}, s.layers, note
		}
		tried = append(tried, "without "+strings.Join(s.layers, " + ")+" → "+ev(last))
	}
	return rtOutcome{false, ev(last)}, steps[len(steps)-1].layers, "control never succeeded: " + strings.Join(tried, "; ")
}

var evSpace = regexp.MustCompile(`\s*\n\s*`)

// ev condenses output into a short single-line evidence snippet.
func ev(s string) string {
	s = evSpace.ReplaceAllString(strings.TrimSpace(s), " | ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func (e *rtEnv) docker(args ...string) (string, int) {
	out, errb, exit, err := e.j.dockerOut(e.ctx, nil, args...)
	if err != nil {
		e.t.Fatalf("docker %v: %v", args, err)
	}
	return strings.TrimSpace(out + "\n" + errb), exit
}

func rtName(prefix string) string {
	b := make([]byte, 4)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func (e *rtEnv) provision(r Ref) Ref {
	if _, err := e.j.Provision(e.ctx, ProvisionSpec{Ref: r, Repo: e.repo}); err != nil {
		e.t.Fatalf("provision %v: %v", r, err)
	}
	return r
}

// hostClone clones the workspace repo at its base.
func (e *rtEnv) hostClone() string {
	dir := filepath.Join(e.t.TempDir(), "clone")
	git(e.t, filepath.Dir(dir), "clone", "-q", e.repo, dir)
	return dir
}

func (e *rtEnv) export(r Ref) []byte {
	var buf bytes.Buffer
	if _, err := e.j.Export(e.ctx, r, &buf); err != nil {
		e.t.Fatalf("export %v: %v", r, err)
	}
	return buf.Bytes()
}

func (e *rtEnv) runningCalls(project, worker string) []string {
	args := append([]string{"ps", "-aq"}, callFilters(project, worker)...)
	out, _ := e.docker(args...)
	return splitLines(out)
}

var canaries = map[string]string{
	"G1-read-ssh":        "alexis/.ssh/id_canary",
	"G1-read-config":     "alexis/.config/a2a-swarm/agents/canary.json",
	"G1-read-keychain":   "alexis/Library/Keychains/login.keychain-db",
	"G1-read-other-repo": "alexis/src/other-repo/.git/config",
}

func TestRedTeam(t *testing.T) {
	if os.Getenv("WJ_REDTEAM") != "1" {
		t.Skip("set WJ_REDTEAM=1 to run the red-team suite against the workers VM")
	}
	j, err := New(Config{StateDir: t.TempDir(), Image: rtImage})
	if err != nil {
		t.Fatal(err)
	}
	e := &rtEnv{t: t, ctx: context.Background(), j: j, home: j.home, repo: newRepo(t), p: rtName("wjrt-"), p2: rtName("wjrt-")}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		for _, p := range []string{e.p, e.p2} {
			if err := j.Purge(ctx, p); err != nil {
				t.Errorf("purge %s: %v", p, err)
			}
		}
		if ids, _, _, _ := j.dockerOut(ctx, nil, "ps", "-aq", "--filter", "label="+rtLabel); strings.TrimSpace(ids) != "" {
			j.dockerOut(ctx, nil, append([]string{"rm", "-f"}, splitLines(ids)...)...)
		}
		j.dockerOut(ctx, nil, "volume", "rm", "-f", rtCanary)
		if vols, _, _, _ := j.dockerOut(ctx, nil, "volume", "ls", "-q", "--filter", "label="+rtLabel); strings.TrimSpace(vols) != "" {
			t.Errorf("leftover wjrt volumes: %s", vols)
		}
	})
	if out, exit := e.docker("image", "inspect", "--format", "{{.Id}}", rtImage); exit != 0 {
		t.Fatalf("red-team image missing (make image-redteam): %s", out)
	}
	// Synthetic canaries only: the suite never reads the real ~/.ssh or keychain.
	var mk []string
	for id, p := range canaries {
		mk = append(mk, fmt.Sprintf("mkdir -p /c/%s && echo WJRT-CANARY-%s > /c/%s", filepath.Dir(p), id, p))
	}
	e.docker("volume", "rm", "-f", rtCanary)
	if out, exit := e.docker("volume", "create", "--label", rtLabel, rtCanary); exit != 0 {
		t.Fatal(out)
	}
	if out, exit := e.docker("run", "--rm", "--label", rtLabel, "--network", "none", "-v", rtCanary+":/c", DefaultImage,
		"sh", "-c", strings.Join(mk, " && ")+" && chmod -R a+rX /c"); exit != 0 {
		t.Fatal(out)
	}
	e.a = e.provision(Ref{e.p, "w-a"})
	e.b = e.provision(Ref{e.p, "w-b"})
	e.other = e.provision(Ref{e.p2, "w-o"})

	var rows []rtRow
	for _, pr := range rtProbes() {
		row := rtRow{ID: pr.id, Guarantee: pr.id[:2], Tries: pr.tries, Known: pr.known}
		t.Run(pr.id, func(t *testing.T) {
			e.t = t
			pr.run(e, &row)
			switch {
			case row.Known && row.Jailed.OK:
				row.Verdict = "known-limit"
			case !row.Known && row.Jailed.OK && row.Control.OK:
				row.Verdict = "PASS"
			default:
				row.Verdict = "FAIL"
			}
			if row.Verdict == "FAIL" {
				t.Errorf("%s: jailed %+v control %+v note %s", pr.id, row.Jailed, row.Control, row.Note)
			}
		})
		if row.Verdict == "" {
			row.Verdict = "FAIL"
		}
		rows = append(rows, row)
	}
	e.t = t
	writeReport(t, e, rows)
}

type rtProbe struct {
	id, tries string
	known     bool
	run       func(e *rtEnv, row *rtRow)
}

func canaryRead(id string) rtProbe {
	path := "/Users/" + canaries[id]
	return rtProbe{id: id, tries: "cat " + path, run: func(e *rtEnv, row *rtRow) {
		script := "cat " + path
		_, out := e.jrun(e.a, time.Minute, script)
		row.Jailed = rtOutcome{!strings.Contains(out, "WJRT-CANARY"), ev(out)}
		cout, _ := e.ctrl(e.a, time.Minute, script, e.canaryMount())
		row.Control = rtOutcome{strings.Contains(cout, "WJRT-CANARY-"+id), ev(cout)}
		row.Layers = []string{"no host path in the container (named volumes only)"}
	}}
}

func rtProbes() []rtProbe {
	wrote := func(out string, _ int) bool { return strings.Contains(out, "WROTE") }
	return []rtProbe{
		canaryRead("G1-read-ssh"),
		canaryRead("G1-read-config"),
		canaryRead("G1-read-keychain"),
		canaryRead("G1-read-other-repo"),
		{id: "G1-write-root", tries: "write /x, /etc/x, /usr/local/bin/x", run: func(e *rtEnv, row *rtRow) {
			s := `for f in /x /etc/x /usr/local/bin/x; do if (echo x > $f) 2>/dev/null; then echo WROTE $f; else echo denied $f; fi; done`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "WROTE"), ev(out)}
			row.Control, row.Layers, row.Note = e.ladder(e.a, time.Minute, s, wrote,
				rtStep{[]string{"read-only rootfs"}, []argMod{e.drop("--read-only", "")}},
				rtStep{[]string{"read-only rootfs", "non-root user"}, []argMod{e.drop("--read-only", ""), e.user("0:0")}})
		}},
		{id: "G1-write-cache", tries: "write into /cache/rt/", run: func(e *rtEnv, row *rtRow) {
			var tb bytes.Buffer
			dir := e.t.TempDir()
			writeFile(e.t, filepath.Join(dir, "seed.txt"), "seed\n")
			if err := writeTar(dir, &tb); err != nil {
				e.t.Fatal(err)
			}
			if err := e.j.SeedCache(e.ctx, e.p, "rt", &tb); err != nil {
				e.t.Fatal(err)
			}
			s := `ls /cache/rt && if echo x > /cache/rt/poison; then echo WROTE; fi`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "WROTE") && strings.Contains(out, "seed.txt"), ev(out)}
			cout, exit := e.ctrl(e.a, time.Minute, s, e.rwCache("rt"))
			row.Control = rtOutcome{wrote(cout, exit), ev(cout)}
			row.Layers = []string{"caches mounted read-only"}
		}},
		{id: "G1-symlink", tries: "ln -s / /work/src/r && echo x > /work/src/r/etc/x", run: func(e *rtEnv, row *rtRow) {
			s := `rm -f /work/src/r; ln -s / /work/src/r && if echo x > /work/src/r/etc/x; then echo WROTE; fi; rm -f /work/src/r`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "WROTE"), ev(out)}
			row.Control, row.Layers, row.Note = e.ladder(e.a, time.Minute, s, wrote,
				rtStep{[]string{"read-only rootfs"}, []argMod{e.drop("--read-only", "")}},
				rtStep{[]string{"read-only rootfs", "non-root user"}, []argMod{e.drop("--read-only", ""), e.user("0:0")}},
				rtStep{[]string{"read-only rootfs", "non-root user", "cap-drop ALL (DAC_OVERRIDE)"}, []argMod{e.drop("--read-only", ""), e.user("0:0"), e.add("--cap-add", "DAC_OVERRIDE")}})
			row.Note = strings.TrimPrefix(row.Note+"; the symlink resolves inside the container's own rootfs", "; ")
		}},
		{id: "G1-hardlink", tries: "ln /etc/passwd /work/src/pw", run: func(e *rtEnv, row *rtRow) {
			res, out := e.jrun(e.a, time.Minute, `ln /etc/passwd /work/src/pw; rc=$?; test -e /work/src/pw && echo LINKED; rm -f /work/src/pw; exit $rc`)
			row.Jailed = rtOutcome{res.Exit != 0 && !strings.Contains(out, "LINKED") && strings.Contains(out, "cross-device"), ev(out)}
			_, cout := e.jrun(e.a, time.Minute, `echo a > /work/src/a && ln /work/src/a /work/src/b && echo LINKED; rm -f /work/src/a /work/src/b`)
			row.Control = rtOutcome{strings.Contains(cout, "LINKED"), "same filesystem: " + ev(cout)}
			row.Layers = []string{"separate filesystems (rootfs vs workspace volume: EXDEV)"}
		}},
		{id: "G1-mount", tries: "mount -t tmpfs none /mnt", run: func(e *rtEnv, row *rtRow) {
			s := `mount -t tmpfs none /mnt && echo MOUNTED`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "MOUNTED"), ev(out)}
			row.Control, row.Layers, row.Note = e.ladder(e.a, time.Minute, s, func(o string, _ int) bool { return strings.Contains(o, "MOUNTED") },
				rtStep{[]string{"cap-drop ALL", "AppArmor", "non-root user"}, []argMod{e.add("--cap-add", "SYS_ADMIN", "--security-opt", "apparmor=unconfined"), e.user("0:0")}})
		}},
		{id: "G1-vm-shares", tries: "list the VM's host shares from /proc/mounts", run: func(e *rtEnv, row *rtRow) {
			mounts, err := e.j.colima.ProcMounts(e.ctx)
			if err != nil {
				e.t.Fatal(err)
			}
			ok, detail := checkShares(mounts, e.home)
			var shares []string
			for _, l := range splitLines(mounts) {
				if f := strings.Fields(l); len(f) > 2 && (shareTypes[f[2]] || strings.HasPrefix(f[2], "fuse")) {
					shares = append(shares, f[1]+" "+f[2])
				}
			}
			row.Jailed = rtOutcome{ok, detail + " [" + strings.Join(shares, ", ") + "]"}
			cache := filepath.Join(e.home, "Library", "Caches", "colima")
			found := false
			for _, s := range shares {
				found = found || strings.HasPrefix(s, cache+" ")
			}
			planted := mounts + "\nmount0 " + filepath.Join(e.home, "src") + " virtiofs rw,relatime 0 0\n"
			pok, pdetail := checkShares(planted, e.home)
			row.Control = rtOutcome{found && !pok, fmt.Sprintf("parser finds the cache share: %v; a planted rw share of ~/src is flagged: %s", found, ev(pdetail))}
			row.Layers = []string{"VM --mount none"}
		}},
		{id: "G1-vm-escape", tries: "simulated escape to the VM: nsenter -t 1 -m ls -a ~ ; ls ~/.ssh", run: func(e *rtEnv, row *rtRow) {
			vm := func(script string) (string, int) {
				return e.docker("run", "--rm", "--label", rtLabel, "--privileged", "--pid", "host", e.j.image,
					"nsenter", "-t", "1", "-m", "--", "sh", "-c", script)
			}
			out, _ := vm(fmt.Sprintf(`ls -A %q; echo ---; ls %q/.ssh && echo SSH-LISTED`, e.home, e.home))
			listing := strings.Fields(strings.SplitN(out, "---", 2)[0])
			row.Jailed = rtOutcome{len(listing) == 1 && listing[0] == "Library" && !strings.Contains(out, "SSH-LISTED"), ev(out)}
			cout, exit := vm(fmt.Sprintf(`ls %q/Library/Caches/colima`, e.home))
			row.Control = rtOutcome{exit == 0, ev(cout)}
			row.Layers = []string{"VM --mount none"}
		}},
		{id: "G2-http", tries: "curl -sS -m 5 https://example.com", run: func(e *rtEnv, row *rtRow) {
			s := `curl -sS -m 5 -o /dev/null -w 'HTTP %{http_code}\n' https://example.com`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "HTTP 200"), ev(out)}
			cout, _ := e.ctrl(e.a, time.Minute, s, e.drop("--network", "none"), e.add("--dns", "1.1.1.1"))
			row.Control = rtOutcome{strings.Contains(cout, "HTTP 200"), ev(cout)}
			row.Layers = []string{"--network none"}
			row.Note = "control adds --dns 1.1.1.1: the VM resolver 192.168.5.3 does not answer from the VM itself"
		}},
		{id: "G2-host-matrix", tries: "nc -z -w 3 192.168.5.2 8008 (host loopback via the lima gateway)", run: func(e *rtEnv, row *rtRow) {
			s := `nc -z -w 3 192.168.5.2 8008 && echo CONNECTED`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "CONNECTED"), ev(out)}
			cout, _ := e.ctrl(e.a, time.Minute, s, e.drop("--network", "none"))
			row.Control = rtOutcome{strings.Contains(cout, "CONNECTED"), ev(cout)}
			row.Layers = []string{"--network none"}
		}},
		{id: "G2-dns", tries: "getent hosts example.com", run: func(e *rtEnv, row *rtRow) {
			s := `getent hosts example.com && echo RESOLVED`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "RESOLVED"), ev("exit/no answer: " + out)}
			cout, _ := e.ctrl(e.a, time.Minute, s, e.drop("--network", "none"), e.add("--dns", "1.1.1.1"))
			row.Control = rtOutcome{strings.Contains(cout, "RESOLVED"), ev(cout)}
			row.Layers = []string{"--network none"}
			row.Note = "control adds --dns 1.1.1.1: the VM resolver 192.168.5.3 does not answer from the VM itself"
		}},
		{id: "G2-ifaces", tries: "ip -o link lists only lo", run: func(e *rtEnv, row *rtRow) {
			names := func(out string) []string {
				var n []string
				for _, l := range splitLines(out) {
					if f := strings.Fields(l); len(f) > 1 && strings.HasSuffix(f[0], ":") {
						n = append(n, strings.SplitN(strings.TrimSuffix(f[1], ":"), "@", 2)[0])
					}
				}
				return n
			}
			_, out := e.jrun(e.a, time.Minute, "ip -o link")
			n := names(out)
			row.Jailed = rtOutcome{len(n) == 1 && n[0] == "lo", strings.Join(n, ",")}
			cout, _ := e.ctrl(e.a, time.Minute, "ip -o link", e.drop("--network", "none"))
			cn := names(cout)
			row.Control = rtOutcome{strings.Contains(","+strings.Join(cn, ",")+",", ",eth0,"), strings.Join(cn, ",")}
			row.Layers = []string{"--network none"}
		}},
		{id: "G3-uid", tries: "id -u is 10001", run: func(e *rtEnv, row *rtRow) {
			_, out := e.jrun(e.a, time.Minute, "id -u; id -g")
			row.Jailed = rtOutcome{strings.Fields(out)[0] == "10001", ev(out)}
			cout, _ := e.ctrl(e.a, time.Minute, "id -u", e.user("0:0"))
			row.Control = rtOutcome{strings.TrimSpace(cout) == "0", ev(cout)}
			row.Layers = []string{"non-root user"}
		}},
		{id: "G3-sudo", tries: "sudo -n id -u (NOPASSWD sudoers in the image)", run: func(e *rtEnv, row *rtRow) {
			s := "sudo -n id -u"
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!regexp.MustCompile(`(?m)^0$`).MatchString(out), ev(out)}
			row.Control, row.Layers, row.Note = e.ladder(e.a, time.Minute, s, func(o string, _ int) bool { return regexp.MustCompile(`(?m)^0$`).MatchString(o) },
				rtStep{[]string{"no_new_privs"}, []argMod{e.drop("--security-opt", "no-new-privileges")}},
				rtStep{[]string{"no_new_privs", "cap-drop ALL"}, []argMod{e.drop("--security-opt", "no-new-privileges"), e.drop("--cap-drop", "ALL")}})
		}},
		{id: "G3-setuid", tries: "/usr/local/bin/suid-id -u (setuid root)", run: func(e *rtEnv, row *rtRow) {
			s := "ls -l /usr/local/bin/suid-id; /usr/local/bin/suid-id -u"
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{strings.Contains(out, "rws") && !regexp.MustCompile(`(?m)^0$`).MatchString(out), ev(out)}
			cout, _ := e.ctrl(e.a, time.Minute, s, e.drop("--security-opt", "no-new-privileges"))
			row.Control = rtOutcome{regexp.MustCompile(`(?m)^0$`).MatchString(cout), ev(cout)}
			row.Layers = []string{"no_new_privs"}
		}},
		{id: "G3-caps", tries: "CapEff is 0 and NoNewPrivs is 1 in /proc/self/status", run: func(e *rtEnv, row *rtRow) {
			s := "grep -E '^(CapEff|NoNewPrivs):' /proc/self/status"
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{regexp.MustCompile(`CapEff:\s+0+\b`).MatchString(out) && regexp.MustCompile(`NoNewPrivs:\s+1`).MatchString(out), ev(out)}
			cout, _ := e.ctrl(e.a, time.Minute, s, e.drop("--cap-drop", "ALL"), e.user("0:0"))
			m := regexp.MustCompile(`CapEff:\s+([0-9a-f]+)`).FindStringSubmatch(cout)
			row.Control = rtOutcome{m != nil && strings.Trim(m[1], "0") != "", ev(cout)}
			row.Layers = []string{"cap-drop ALL", "non-root user"}
			row.Note = "defense in depth"
		}},
		{id: "G3-unshare", tries: "unshare -r id", run: func(e *rtEnv, row *rtRow) {
			s := "unshare -r id && echo UNSHARED"
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "UNSHARED"), ev(out)}
			done := func(o string, _ int) bool { return strings.Contains(o, "UNSHARED") }
			unconf := []string{"--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined"}
			row.Control, row.Layers, row.Note = e.ladder(e.a, time.Minute, s, done,
				rtStep{[]string{"seccomp"}, []argMod{e.add(unconf[:2]...)}},
				rtStep{[]string{"seccomp", "AppArmor"}, []argMod{e.add(unconf...)}},
				rtStep{[]string{"seccomp", "AppArmor", "cap-drop ALL"}, []argMod{e.add(append(unconf, "--cap-add", "SYS_ADMIN")...)}},
				rtStep{[]string{"seccomp", "AppArmor", "cap-drop ALL", "non-root user"}, []argMod{e.add(append(unconf, "--cap-add", "SYS_ADMIN")...), e.user("0:0")}})
		}},
		{id: "G3-docker-sock", tries: "curl --unix-socket /var/run/docker.sock http://d/_ping", run: func(e *rtEnv, row *rtRow) {
			s := "curl -s -m 5 --unix-socket /var/run/docker.sock http://d/_ping; echo; echo rc=$?"
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "OK"), ev(out)}
			bind := e.add("--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock")
			row.Control, row.Layers, row.Note = e.ladder(e.a, time.Minute, s, func(o string, _ int) bool { return strings.HasPrefix(o, "OK") },
				rtStep{[]string{"no docker socket"}, []argMod{bind}},
				rtStep{[]string{"no docker socket", "non-root user"}, []argMod{bind, e.user("0:0")}})
		}},
		{id: "G4-pids", tries: "start 2000 background sleep 60", run: func(e *rtEnv, row *rtRow) {
			inner := `n=0; for i in $(seq 2000); do sleep 60 >/dev/null 2>&1 & n=$((n+1)); echo started=$n; done`
			s := "sh -c '" + inner + "' 2>&1 | tail -n 3; set -- /proc/[0-9]*; echo live=$#; exit 0"
			started := func(o string) int {
				m := regexp.MustCompile(`started=(\d+)`).FindAllStringSubmatch(o, -1)
				if m == nil {
					return 0
				}
				n, _ := strconv.Atoi(m[len(m)-1][1])
				return n
			}
			live := func(o string) int {
				m := regexp.MustCompile(`live=(\d+)`).FindStringSubmatch(o)
				if m == nil {
					return -1
				}
				n, _ := strconv.Atoi(m[1])
				return n
			}
			type jr struct {
				res Result
				out string
			}
			ch := make(chan jr, 1)
			go func() {
				res, err := e.j.Run(e.ctx, e.a, RunSpec{Argv: []string{"sh", "-c", s}, Timeout: 30 * time.Second})
				out := string(res.Stdout) + string(res.Stderr)
				if err != nil {
					out += " err: " + err.Error()
				}
				ch <- jr{res, out}
			}()
			time.Sleep(3 * time.Second)
			ores, err := e.j.Run(e.ctx, e.other, RunSpec{Argv: []string{"true"}, Timeout: 30 * time.Second})
			r := <-ch
			ok := err == nil && ores.Exit == 0
			n, l := started(r.out), live(r.out)
			row.Jailed = rtOutcome{n < 2000 && l >= 0 && l <= 512 && r.res.Duration < 31*time.Second && ok,
				fmt.Sprintf("started=%d live=%d duration=%s timedOut=%v; concurrent call in %s exit=%d err=%v; %s",
					n, l, r.res.Duration.Round(time.Millisecond), r.res.TimedOut, e.p2, ores.Exit, err, ev(r.out))}
			cout, _ := e.ctrl(e.a, 30*time.Second, s, e.drop("--pids-limit", strconv.Itoa(e.j.limits.Pids)))
			row.Control = rtOutcome{started(cout) >= 1500, fmt.Sprintf("started=%d live=%d", started(cout), live(cout))}
			row.Layers = []string{"--pids-limit"}
		}},
		{id: "G4-memory", tries: "head -c 3G /dev/zero | tail > /dev/null", run: func(e *rtEnv, row *rtRow) {
			s := "head -c 3G /dev/zero | tail > /dev/null; echo rc=$?"
			_, out := e.jrun(e.a, 2*time.Minute, s)
			row.Jailed = rtOutcome{strings.Contains(out, "rc=137"), ev(out)}
			cout, _ := e.ctrl(e.a, 2*time.Minute, s, e.drop("--memory", i64(e.j.limits.Memory)), e.drop("--memory-swap", i64(e.j.limits.Memory)))
			row.Control = rtOutcome{strings.Contains(cout, "rc=0"), ev(cout)}
			row.Layers = []string{"--memory/--memory-swap"}
		}},
		{id: "G4-cpu", tries: "4 busy loops for 3 s", run: func(e *rtEnv, row *rtRow) {
			s := `u() { sed -n 's/^usage_usec //p' /sys/fs/cgroup/cpu.stat; }; a=$(u)
for i in 1 2 3 4; do timeout 3 sh -c 'while :; do :; done' & done; wait; b=$(u); echo used=$((b-a))`
			used := func(o string) int {
				m := regexp.MustCompile(`used=(\d+)`).FindStringSubmatch(o)
				if m == nil {
					return -1
				}
				n, _ := strconv.Atoi(m[1])
				return n
			}
			_, out := e.jrun(e.a, time.Minute, s)
			u := used(out)
			row.Jailed = rtOutcome{u >= 0 && u <= 6_900_000, fmt.Sprintf("usage_usec=%d (limit 2.3 CPUs × 3 s = 6900000)", u)}
			cout, _ := e.ctrl(e.a, time.Minute, s, e.drop("--cpus", "2"))
			cu := used(cout)
			row.Control = rtOutcome{cu > 9_000_000, fmt.Sprintf("usage_usec=%d (> 3 CPUs × 3 s = 9000000)", cu)}
			row.Layers = []string{"--cpus"}
		}},
		{id: "G4-fsize", tries: "head -c 2200M /dev/zero > /work/big", run: func(e *rtEnv, row *rtRow) {
			s := "head -c 2200M /dev/zero > /work/big; echo rc=$?; ls -l /work/big; rm -f /work/big"
			_, out := e.jrun(e.a, 3*time.Minute, s)
			row.Jailed = rtOutcome{strings.Contains(out, "rc=153"), ev(out)}
			cout, _ := e.ctrl(e.a, 3*time.Minute, s, e.drop("--ulimit", "fsize="))
			row.Control = rtOutcome{strings.Contains(cout, "rc=0"), ev(cout)}
			row.Layers = []string{"--ulimit fsize"}
		}},
		{id: "G4-output", tries: "yes with MaxOutput 1 MiB", run: func(e *rtEnv, row *rtRow) {
			res, err := e.j.Run(e.ctx, e.a, RunSpec{Argv: []string{"yes"}, MaxOutput: 1 << 20, Timeout: time.Minute})
			left := e.runningCalls(e.p, e.a.Worker)
			row.Jailed = rtOutcome{err == nil && res.Truncated && !res.TimedOut && len(res.Stdout) == 1<<20 && len(left) == 0,
				fmt.Sprintf("truncated=%v stdout=%d B duration=%s containers left=%d err=%v", res.Truncated, len(res.Stdout), res.Duration.Round(time.Millisecond), len(left), err)}
			cres, err := e.j.Run(e.ctx, e.a, RunSpec{Argv: []string{"sh", "-c", "yes | head -c 5M"}, MaxOutput: 8 << 20, Timeout: time.Minute})
			row.Control = rtOutcome{err == nil && !cres.Truncated && len(cres.Stdout) == 5<<20,
				fmt.Sprintf("MaxOutput 8 MiB: truncated=%v stdout=%d B err=%v", cres.Truncated, len(cres.Stdout), err)}
			row.Layers = []string{"MaxOutput cap + kill"}
		}},
		{id: "G4-timeout", tries: "sleep 8 with Timeout 3 s", run: func(e *rtEnv, row *rtRow) {
			res, err := e.j.Run(e.ctx, e.a, RunSpec{Argv: []string{"sleep", "8"}, Timeout: 3 * time.Second})
			left := e.runningCalls(e.p, e.a.Worker)
			row.Jailed = rtOutcome{err == nil && res.TimedOut && res.Duration < 6*time.Second && len(left) == 0,
				fmt.Sprintf("timedOut=%v duration=%s containers left=%d err=%v", res.TimedOut, res.Duration.Round(time.Millisecond), len(left), err)}
			cres, err := e.j.Run(e.ctx, e.a, RunSpec{Argv: []string{"sleep", "8"}, Timeout: 20 * time.Second})
			row.Control = rtOutcome{err == nil && !cres.TimedOut && cres.Exit == 0 && cres.Duration >= 8*time.Second,
				fmt.Sprintf("Timeout 20 s: exit=%d duration=%s err=%v", cres.Exit, cres.Duration.Round(time.Millisecond), err)}
			row.Layers = []string{"call timeout (docker kill)"}
		}},
		{id: "G4-queue", tries: "3 concurrent sleep 3 with Slots = 2", run: func(e *rtEnv, row *rtRow) {
			waits := func(slots int) ([]time.Duration, error) {
				j, err := New(Config{StateDir: e.t.TempDir(), Image: rtImage, Slots: slots, ProjectSlots: slots})
				if err != nil {
					return nil, err
				}
				var wg sync.WaitGroup
				var mu sync.Mutex
				var ws []time.Duration
				var errs []error
				for range 3 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						res, err := j.Run(e.ctx, e.a, RunSpec{Argv: []string{"sleep", "3"}, Timeout: time.Minute})
						mu.Lock()
						defer mu.Unlock()
						ws, errs = append(ws, res.QueueWait.Round(10*time.Millisecond)), append(errs, err)
					}()
				}
				wg.Wait()
				return ws, errors.Join(errs...)
			}
			ws, err := waits(2)
			maxw := time.Duration(0)
			for _, w := range ws {
				maxw = max(maxw, w)
			}
			row.Jailed = rtOutcome{err == nil && maxw >= 2500*time.Millisecond, fmt.Sprintf("Slots=2 QueueWait=%v err=%v", ws, err)}
			cws, err := waits(3)
			cmax := time.Duration(0)
			for _, w := range cws {
				cmax = max(cmax, w)
			}
			row.Control = rtOutcome{err == nil && cmax < time.Second, fmt.Sprintf("Slots=3 QueueWait=%v err=%v", cws, err)}
			row.Layers = []string{"call slots"}
		}},
		{id: "G4-disk", tries: "write 1 GiB in 4 files (soft quota)", known: true, run: func(e *rtEnv, row *rtRow) {
			res, out := e.jrun(e.a, 3*time.Minute, "for i in 1 2 3 4; do head -c 256M /dev/zero > /work/d$i || exit 1; done; echo WROTE")
			u, err := e.j.Usage(e.ctx, e.a)
			e.jrun(e.a, time.Minute, "rm -f /work/d1 /work/d2 /work/d3 /work/d4")
			row.Jailed = rtOutcome{res.Exit == 0 && strings.Contains(out, "WROTE") && err == nil && u >= 1<<30,
				fmt.Sprintf("write exit=%d, Usage=%d B (≥ 1 GiB) err=%v", res.Exit, u, err)}
			row.Control = rtOutcome{true, "n/a: known limit, detected by Usage"}
			row.Layers = []string{"none (soft quota; VM disk is the hard cap)"}
		}},
		{id: "G5-read-other", tries: "find another worker's canary file", run: func(e *rtEnv, row *rtRow) {
			e.jrun(e.b, time.Minute, "echo WJRT-CANARY-G5 > /work/src/secret-b")
			s := `find / \( -path /proc -o -path /sys \) -prune -o -name 'secret-b*' -print 2>/dev/null; echo done`
			_, out := e.jrun(e.a, 2*time.Minute, s)
			row.Jailed = rtOutcome{!strings.Contains(out, "secret-b") && strings.Contains(out, "done"), ev(out)}
			cout, _ := e.ctrl(e.a, 2*time.Minute, s, e.add("--mount", "type=volume,src="+WorkspaceVolume(e.p, e.b.Worker)+",dst=/other,readonly"))
			row.Control = rtOutcome{strings.Contains(cout, "/other/src/secret-b"), ev(cout)}
			row.Layers = []string{"own workspace only"}
		}},
		{id: "G5-ps-other", tries: "see another worker's sleep 31.5 in ps", run: func(e *rtEnv, row *rtRow) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				e.j.Run(e.ctx, e.b, RunSpec{Argv: []string{"sleep", "31.5"}, Timeout: time.Minute})
			}()
			deadline := time.Now().Add(20 * time.Second)
			for len(e.runningCalls(e.p, e.b.Worker)) == 0 && time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
			}
			time.Sleep(time.Second)
			_, out := e.jrun(e.a, time.Minute, "ps -eo args")
			row.Jailed = rtOutcome{!strings.Contains(out, "sleep 31.5") && strings.Contains(out, "ps -eo args"), ev(out)}
			cout, _ := e.ctrl(e.a, time.Minute, "ps -eo args | grep -F 'sleep 31.5' | grep -v grep", e.add("--pid", "host"))
			row.Control = rtOutcome{strings.Contains(cout, "sleep 31.5"), ev(cout)}
			row.Layers = []string{"PID namespace"}
			<-done
		}},
		{id: "G6-background", tries: "setsid nohup sleep 1234 & left for the next call", run: func(e *rtEnv, row *rtRow) {
			e.jrun(e.a, time.Minute, "setsid nohup sleep 1234 >/dev/null 2>&1 & echo started")
			_, out := e.jrun(e.a, time.Minute, "ps -eo args")
			left := e.runningCalls(e.p, "")
			row.Jailed = rtOutcome{!strings.Contains(out, "sleep 1234") && strings.Contains(out, "ps -eo args") && len(left) == 0,
				fmt.Sprintf("containers left=%d; %s", len(left), ev(out))}
			_, cout := e.jrun(e.a, time.Minute, "setsid nohup sleep 1234 >/dev/null 2>&1 & sleep 1; ps -eo args")
			row.Control = rtOutcome{strings.Contains(cout, "sleep 1234"), "same call: " + ev(cout)}
			row.Layers = []string{"container per call"}
		}},
		{id: "G6-tmp", tries: "a file in /tmp left for the next call", run: func(e *rtEnv, row *rtRow) {
			e.jrun(e.a, time.Minute, "echo x > /tmp/x")
			res, out := e.jrun(e.a, time.Minute, "cat /tmp/x")
			row.Jailed = rtOutcome{res.Exit != 0, ev(out)}
			_, cout := e.jrun(e.a, time.Minute, "echo x > /tmp/x; cat /tmp/x")
			row.Control = rtOutcome{strings.TrimSpace(cout) == "x", "same call: " + ev(cout)}
			row.Layers = []string{"fresh tmpfs per call"}
		}},
		{id: "G6-harness-death", tries: "SIGKILL the CLI during `run --timeout 5s -- sleep 600`", run: func(e *rtEnv, row *rtRow) {
			bin := filepath.Join(e.t.TempDir(), "worker-jail")
			build := exec.Command("go", "build", "-o", bin, "./cmd/worker-jail")
			build.Dir = ".."
			if out, err := build.CombinedOutput(); err != nil {
				e.t.Fatalf("build: %v %s", err, out)
			}
			cmd := exec.Command(bin, "--state-dir", e.t.TempDir(), "--image", rtImage, "run", "--project", e.p, "--worker", e.a.Worker,
				"--timeout", "5s", "--", "sleep", "600")
			if err := cmd.Start(); err != nil {
				e.t.Fatal(err)
			}
			start := time.Now()
			for len(e.runningCalls(e.p, e.a.Worker)) == 0 && time.Since(start) < 10*time.Second {
				time.Sleep(100 * time.Millisecond)
			}
			seen := len(e.runningCalls(e.p, e.a.Worker))
			time.Sleep(time.Second)
			cmd.Process.Signal(syscall.SIGKILL)
			cmd.Wait()
			killed := time.Now()
			var gone time.Duration = -1
			for time.Since(killed) < 15*time.Second {
				if len(e.runningCalls(e.p, e.a.Worker)) == 0 {
					gone = time.Since(killed)
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			row.Jailed = rtOutcome{seen == 1 && gone >= 0, fmt.Sprintf("call container seen=%d; gone %s after SIGKILL (limit 15 s)", seen, gone.Round(100*time.Millisecond))}
			args := e.ctrlArgs(e.a, 5*time.Second, []string{"sleep", "600"}, e.noWrapper())
			args = append([]string{"run", "-d"}, args[1:]...)
			id, exit := e.docker(args...)
			time.Sleep(15 * time.Second)
			running, _ := e.docker("inspect", "-f", "{{.State.Running}}", id)
			e.docker("rm", "-f", id)
			row.Control = rtOutcome{exit == 0 && running == "true", "without the timeout wrapper, running at 15 s: " + running}
			row.Layers = []string{"in-container timeout"}
		}},
		{id: "G6-deprovision", tries: "anything left after Deprovision", run: func(e *rtEnv, row *rtRow) {
			r := e.provision(Ref{e.p, "w-d"})
			vols := func() []string {
				out, _ := e.docker("volume", "ls", "-q", "--filter", "label="+LabelProject+"="+r.Project, "--filter", "label="+LabelWorker+"="+r.Worker)
				return splitLines(out)
			}
			before := vols()
			if err := e.j.Deprovision(e.ctx, r, false); err != nil {
				e.t.Fatal(err)
			}
			after, calls := vols(), e.runningCalls(r.Project, r.Worker)
			row.Jailed = rtOutcome{len(after) == 0 && len(calls) == 0, fmt.Sprintf("volumes=%v containers=%v", after, calls)}
			row.Control = rtOutcome{len(before) == 1, fmt.Sprintf("before Deprovision: volumes=%v", before)}
			row.Layers = []string{"deprovision removes the volume"}
		}},
		{id: "G7-env", tries: "host env (canary, SSH_AUTH_SOCK) inside the call", run: func(e *rtEnv, row *rtRow) {
			e.t.Setenv("WJRT_CANARY_SECRET", "WJRT-CANARY-G7-env")
			e.t.Setenv("SSH_AUTH_SOCK", "/tmp/fake.sock")
			j, err := New(Config{StateDir: e.t.TempDir(), Image: rtImage})
			if err != nil {
				e.t.Fatal(err)
			}
			_, out := e.jrunWith(j, e.a, time.Minute, "env")
			bad := regexp.MustCompile(`(?m)^[^=]*(TOKEN|SECRET|SSH_|A2A_|DOCKER_)[^=]*=|WJRT-CANARY`).FindAllString(out, -1)
			row.Jailed = rtOutcome{len(bad) == 0 && strings.Contains(out, "HOME=/work/home"), "env: " + ev(strings.Join(splitLines(out), " "))}
			host := strings.Join(os.Environ(), "\n")
			row.Control = rtOutcome{strings.Contains(host, "WJRT_CANARY_SECRET=WJRT-CANARY-G7-env") && strings.Contains(host, "SSH_AUTH_SOCK=/tmp/fake.sock"),
				"host os.Environ() holds WJRT_CANARY_SECRET and SSH_AUTH_SOCK"}
			row.Layers = []string{"explicit env only"}
		}},
		{id: "G7-docker-config", tries: "DOCKER_CONFIG with proxies.default.httpProxy", run: func(e *rtEnv, row *rtRow) {
			dc := e.t.TempDir()
			writeFile(e.t, filepath.Join(dc, "config.json"), `{"proxies":{"default":{"httpProxy":"http://canary:1"}}}`)
			e.t.Setenv("DOCKER_CONFIG", dc)
			j, err := New(Config{StateDir: e.t.TempDir(), Image: rtImage})
			if err != nil {
				e.t.Fatal(err)
			}
			_, out := e.jrunWith(j, e.a, time.Minute, "env | grep -i proxy; echo end")
			row.Jailed = rtOutcome{!strings.Contains(strings.ToLower(out), "http_proxy"), ev(out)}
			d := DockerCLI{Env: []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "DOCKER_HOST=" + Endpoint(e.home), "DOCKER_CONFIG=" + dc}}
			cout, _ := e.ctrlWith(d, e.a, time.Minute, "env | grep -i proxy; echo end")
			row.Control = rtOutcome{strings.Contains(cout, "HTTP_PROXY=http://canary:1"), ev(cout)}
			row.Layers = []string{"pinned empty DOCKER_CONFIG"}
		}},
		{id: "G7-grep", tries: "grep -rs WJRT-CANARY / (excluding /proc, /sys)", run: func(e *rtEnv, row *rtRow) {
			s := "grep -rls WJRT-CANARY / --exclude-dir=proc --exclude-dir=sys; echo done"
			_, out := e.jrun(e.a, 5*time.Minute, s)
			row.Jailed = rtOutcome{strings.TrimSpace(out) == "done", ev(out)}
			cout, _ := e.ctrl(e.a, 5*time.Minute, s, e.canaryMount())
			row.Control = rtOutcome{strings.Contains(cout, "/Users/alexis/.ssh/id_canary"), ev(cout)}
			row.Layers = []string{"no host path in the container (named volumes only)"}
		}},
		{id: "G8-git-dir", tries: "crafted patch creating .git/hooks/post-commit and .GIT/hooks/x", run: func(e *rtEnv, row *rtRow) {
			var jailed, control []string
			ok := true
			for _, p := range []string{".git/hooks/post-commit", ".GIT/hooks/x"} {
				patch := newFilePatch(p, "touch /tmp/wjrt-pwned")
				clone := e.hostClone()
				_, err := Apply(e.ctx, clone, bytes.NewReader(patch), ApplyOptions{AllowReviewRequired: true})
				ok = ok && errors.Is(err, ErrGitPath) && !fileExists(filepath.Join(clone, p))
				jailed = append(jailed, fmt.Sprintf("%s: %v", p, err))
				control = append(control, p+": "+plainApply(clone, patch, "apply"))
			}
			row.Jailed = rtOutcome{ok, ev(strings.Join(jailed, "; "))}
			row.Control = rtOutcome{true, "recorded, plain git apply: " + ev(strings.Join(control, "; "))}
			row.Layers = []string{"Apply's .git path check", "git's own verify_path (defense in depth)"}
			row.Note = "control records git's own layer instead of succeeding (per the brief)"
		}},
		{id: "G8-planted-hooks", tries: "hooks and core.hooksPath planted in the workspace's .git", run: func(e *rtEnv, row *rtRow) {
			r := e.provision(Ref{e.p, "w-h"})
			marker := filepath.Join(e.t.TempDir(), "planted-marker")
			e.jrun(r, time.Minute, fmt.Sprintf(`printf '#!/bin/sh\ntouch %s\n' > .git/hooks/post-commit && chmod +x .git/hooks/post-commit &&
git config core.hooksPath .git/hooks && echo planted > planted.txt`, marker))
			patch := e.export(r)
			e.patchH = patch
			clone := e.hostClone()
			_, err := Apply(e.ctx, clone, bytes.NewReader(patch), ApplyOptions{})
			if err == nil {
				git(e.t, clone, "commit", "-q", "-m", "worker change")
			}
			noGit := !regexp.MustCompile(`(?m)^diff --git a/\.git/`).Match(patch) && gitPathInHeaders(patch) == ""
			row.Jailed = rtOutcome{noGit && err == nil && !fileExists(marker) && fileExists(filepath.Join(clone, "planted.txt")),
				fmt.Sprintf("patch paths: %v; apply err=%v; committed on host; marker exists=%v", patchPaths(patch), err, fileExists(marker))}
			_, cout := e.jrun(r, time.Minute, "cat .git/hooks/post-commit; git config core.hooksPath")
			row.Control = rtOutcome{strings.Contains(cout, "touch "+marker) && strings.Contains(cout, ".git/hooks"), "in the workspace: " + ev(cout)}
			row.Layers = []string{"export emits only worktree diffs (no .git)"}
		}},
		{id: "G8-symlink", tries: "worker symlink leak -> ~/.ssh/id_ed25519", run: func(e *rtEnv, row *rtRow) {
			r := e.provision(Ref{e.p, "w-s"})
			e.jrun(r, time.Minute, fmt.Sprintf("ln -s %s/.ssh/id_ed25519 leak", e.home))
			patch := e.export(r)
			clone := e.hostClone()
			rep, err := Apply(e.ctx, clone, bytes.NewReader(patch), ApplyOptions{})
			_, lerr := os.Lstat(filepath.Join(clone, "leak"))
			row.Jailed = rtOutcome{errors.Is(err, ErrReviewRequired) && os.IsNotExist(lerr), fmt.Sprintf("err=%v flagged=%v", err, rep.Flagged)}
			clone2 := e.hostClone()
			_, err = Apply(e.ctx, clone2, bytes.NewReader(patch), ApplyOptions{AllowReviewRequired: true})
			fi, lerr := os.Lstat(filepath.Join(clone2, "leak"))
			row.Control = rtOutcome{err == nil && lerr == nil && fi.Mode()&os.ModeSymlink != 0, fmt.Sprintf("AllowReviewRequired: err=%v symlink applied=%v", err, lerr == nil)}
			row.Layers = []string{"Apply review gate (symlink)"}
		}},
		{id: "G8-ci", tries: "worker adds .github/workflows/x.yml", run: func(e *rtEnv, row *rtRow) {
			r := e.provision(Ref{e.p, "w-c"})
			e.jrun(r, time.Minute, "mkdir -p .github/workflows && echo 'on: push' > .github/workflows/x.yml")
			patch := e.export(r)
			clone := e.hostClone()
			rep, err := Apply(e.ctx, clone, bytes.NewReader(patch), ApplyOptions{})
			row.Jailed = rtOutcome{errors.Is(err, ErrReviewRequired) && !fileExists(filepath.Join(clone, ".github/workflows/x.yml")), fmt.Sprintf("err=%v flagged=%v", err, rep.Flagged)}
			clone2 := e.hostClone()
			_, err = Apply(e.ctx, clone2, bytes.NewReader(patch), ApplyOptions{AllowReviewRequired: true})
			row.Control = rtOutcome{err == nil && fileExists(filepath.Join(clone2, ".github/workflows/x.yml")), fmt.Sprintf("AllowReviewRequired: err=%v", err)}
			row.Layers = []string{"Apply review gate (.github)"}
		}},
		{id: "G8-hooks-apply", tries: "host post-index-change hook during Apply", run: func(e *rtEnv, row *rtRow) {
			patch := e.patchH
			if patch == nil {
				e.t.Fatal("G8-planted-hooks did not produce a patch")
			}
			hooked := func() (string, string) {
				clone := e.hostClone()
				marker := filepath.Join(e.t.TempDir(), "hook-marker")
				hook := filepath.Join(clone, ".git", "hooks", "post-index-change")
				if err := os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
					e.t.Fatal(err)
				}
				return clone, marker
			}
			clone, marker := hooked()
			_, err := Apply(e.ctx, clone, bytes.NewReader(patch), ApplyOptions{})
			row.Jailed = rtOutcome{err == nil && !fileExists(marker) && fileExists(filepath.Join(clone, "planted.txt")),
				fmt.Sprintf("apply err=%v; marker exists=%v", err, fileExists(marker))}
			clone2, marker2 := hooked()
			out := plainApply(clone2, patch, "apply", "--index")
			row.Control = rtOutcome{fileExists(marker2), fmt.Sprintf("plain git apply --index (%s): marker exists=%v", ev(out), fileExists(marker2))}
			row.Layers = []string{"core.hooksPath=/dev/null in Apply"}
		}},
		{id: "G8-traversal", tries: "crafted patch with path ../outside", run: func(e *rtEnv, row *rtRow) {
			patch := newFilePatch("../outside", "escaped")
			clone := e.hostClone()
			outside := filepath.Join(filepath.Dir(clone), "outside")
			_, err := Apply(e.ctx, clone, bytes.NewReader(patch), ApplyOptions{AllowReviewRequired: true})
			row.Jailed = rtOutcome{err != nil && !fileExists(outside), fmt.Sprintf("err=%v; outside exists=%v", ev(fmt.Sprint(err)), fileExists(outside))}
			out := plainApply(clone, patch, "apply")
			row.Control = rtOutcome{true, fmt.Sprintf("recorded, plain git apply: %s; outside exists=%v", ev(out), fileExists(outside))}
			row.Layers = []string{"git's own path validation (Apply relies on it)"}
			row.Note = "control records git's own layer instead of succeeding (per the brief)"
		}},
	}
}

func newFilePatch(path, content string) []byte {
	return []byte(fmt.Sprintf("diff --git a/%[1]s b/%[1]s\nnew file mode 100755\nindex 0000000..1111111\n--- /dev/null\n+++ b/%[1]s\n@@ -0,0 +1 @@\n+%[2]s\n", path, content))
}

// plainApply runs a plain host `git <args> -` with the patch on stdin, hooks enabled, and returns its outcome.
func plainApply(repo string, patch []byte, args ...string) string {
	cmd := exec.Command("git", append(append([]string{"-C", repo}, args...), "-")...)
	cmd.Env = append(hostEnv(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	cmd.Stdin = bytes.NewReader(patch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("refused (%v): %s", err, strings.TrimSpace(string(out)))
	}
	return "applied"
}

func patchPaths(patch []byte) []string {
	var p []string
	for _, m := range regexp.MustCompile(`(?m)^diff --git a/(\S+) `).FindAllSubmatch(patch, -1) {
		p = append(p, string(m[1]))
	}
	return p
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func writeReport(t *testing.T, e *rtEnv, rows []rtRow) {
	verdict := "PASS"
	for _, r := range rows {
		if r.Verdict == "FAIL" {
			verdict = "FAIL"
		}
	}
	trunk, _ := hostGit(e.ctx, "..", "rev-parse", "main")
	head, _ := hostGit(e.ctx, "..", "rev-parse", "HEAD")
	info, _ := e.docker("info", "--format", "{{.Name}}|{{.Driver}}|{{.NCPU}}|{{.MemTotal}}")
	f := strings.Split(info, "|")
	for len(f) < 4 {
		f = append(f, "?")
	}
	mem, _ := strconv.ParseInt(f[3], 10, 64)
	header := map[string]any{"trunk_oid": trunk, "head_oid": head, "date": time.Now().UTC().Format(time.RFC3339),
		"docker": map[string]string{"name": f[0], "driver": f[1], "ncpu": f[2], "memory": fmt.Sprintf("%.1f GiB", float64(mem)/(1<<30))},
		"image":  rtImage, "verdict": verdict}
	dir := filepath.Join("..", ".temp", "redteam")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	js, _ := json.MarshalIndent(map[string]any{"header": header, "probes": rows}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "report.json"), append(js, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	cell := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ") }
	var md strings.Builder
	fmt.Fprintf(&md, "# worker-jail red-team report\n\n")
	fmt.Fprintf(&md, "- Verdict: **%s**\n- Trunk (main) OID: `%s`\n- Head OID: `%s`\n- Date: %s\n- Docker: name `%s`, driver `%s`, %s CPUs, %.1f GiB\n- Image: `%s` (test-only)\n\n",
		verdict, trunk, head, header["date"], f[0], f[1], f[2], float64(mem)/(1<<30), rtImage)
	md.WriteString("Jailed: the attack through `jail.Run` as uid 10001 (must be blocked). Control: the same attack without the blocking layers (must succeed).\n\n")
	md.WriteString("| id | guarantee | tries | jailed | control | blocking layers | verdict |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, r := range rows {
		ok := func(o rtOutcome, yes, no string) string {
			if o.OK {
				return yes + ": " + o.Evidence
			}
			return no + ": " + o.Evidence
		}
		layers := strings.Join(r.Layers, ", ")
		if r.Note != "" {
			layers += " (" + r.Note + ")"
		}
		fmt.Fprintf(&md, "| %s | %s | %s | %s | %s | %s | %s |\n", r.ID, r.Guarantee, cell(r.Tries),
			cell(ok(r.Jailed, "blocked", "NOT BLOCKED")), cell(ok(r.Control, "succeeded", "FAILED")), cell(layers), r.Verdict)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(md.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("red-team verdict: %s (report in .temp/redteam/)", verdict)
}
