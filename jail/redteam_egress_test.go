package jail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The egress red-team probes of v2.1 (docs/design/v2/egress.md §8: E1, E2, E2-generic, E5, E8, E10; E3, E4, E6, E7 and
// E9, and E5 in depth, are unit tests in egress/). WJ_REDTEAM=1, the images of `make image image-redteam` and a running
// service (`worker-jail egress up`). The same style as TestRedTeam: every probe runs jailed and has a positive control;
// weakened containers exist only here. Workers are modules or allowlist policies of a wjrt-* project, withdrawn from the
// service and purged at the end.

// rtModules is the probes' modules policy: golang.org/x/sync only.
func rtModules(t *testing.T, r Ref) []byte {
	return modulesPolicy(t, r.Project, r.Worker, `golang\.org/x/sync`)
}

// rtAllowlist is the probes' generic policy: an allowlist of proxy.golang.org on port 443 only (HIGH, with its note).
func rtAllowlist(t *testing.T, r Ref) []byte {
	return mut(t, string(testPolicy(r.Project, r.Worker)), set("note", "red-team E5 and E2-generic"),
		set("network", map[string]any{"mode": NetAllowlist, "hosts": []string{`proxy\.golang\.org`}, "ports": []any{443},
			"rate": map[string]any{"requests_per_min": 600, "max_conns": 8, "bytes_per_day": 1 << 30}}))
}

func (e *rtEnv) provisionModules(j *Jail, r Ref, repo string) Ref {
	if _, err := j.SetPolicy(e.ctx, r, rtModules(e.t, r), SetPolicyOptions{}); err != nil {
		e.t.Fatalf("policy %v: %v", r, err)
	}
	if _, err := j.Provision(e.ctx, ProvisionSpec{Ref: r, Repo: repo}); err != nil {
		e.t.Fatalf("provision %v: %v", r, err)
	}
	return r
}

// ctrlEgress is ctrlArgs for a modules call: the jail's own argv with the socket, env and relay, run with `docker run`
// and weakened by mods.
func (e *rtEnv) ctrlEgress(r Ref, script string, mods ...argMod) (string, int) {
	args, err := createArgs(callSpec{Shape: shapeCall, Name: newCallName(), Project: r.Project, Worker: r.Worker, Egress: NetModules,
		Workdir: "/work/src", Image: e.j.image, Limits: e.j.limits, Timeout: time.Minute, Argv: []string{"sh", "-c", script}})
	if err != nil {
		e.t.Fatal(err)
	}
	args[0] = "run"
	args = e.add("--label", rtLabel)(args)
	for _, m := range mods {
		args = m(args)
	}
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	out, errb, exit, err := e.j.dockerOut(ctx, nil, args...)
	if err != nil {
		e.t.Fatalf("control docker run: %v", err)
	}
	return out + errb, exit
}

// replaceArg swaps one argument before the image.
func (e *rtEnv) replaceArg(old, repl string) argMod {
	return func(a []string) []string {
		out := append([]string{}, a...)
		for i := 0; i < e.imageIdx(out); i++ {
			if out[i] == old {
				out[i] = repl
			}
		}
		return out
	}
}

// waitLoaded polls the service until it serves id for r ("" for none).
func (e *rtEnv) waitLoaded(r Ref, id string) error {
	deadline := time.Now().Add(time.Minute)
	for {
		got, err := e.j.EgressLoaded(e.ctx, r)
		if err == nil && got == id {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("egress serves %q (%v), want %q", got, err, id)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestRedTeamEgress(t *testing.T) {
	if os.Getenv("WJ_REDTEAM") != "1" {
		t.Skip("set WJ_REDTEAM=1 to run the red-team suite against the workers VM")
	}
	j, err := New(Config{StateDir: t.TempDir(), Image: rtImage})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if state, err := j.egressState(ctx); err != nil || state != "running" {
		t.Fatalf("the egress service is not running (worker-jail egress up): %q %v", state, err)
	}
	e := &rtEnv{t: t, ctx: ctx, j: j, home: j.home, repo: newRepo(t), p: rtName("wjrt-")}
	var refs []Ref
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if state, _ := j.egressState(cctx); state != "running" {
			j.dockerOut(cctx, nil, "start", EgressContainer)
		}
		for _, r := range refs {
			if err := j.RemovePolicy(r); err != nil && !errors.Is(err, ErrNoPolicy) {
				t.Errorf("withdraw %v: %v", r, err)
			}
		}
		if err := j.Purge(cctx, e.p); err != nil {
			t.Errorf("purge %s: %v", e.p, err)
		}
		if ids, _, _, _ := j.dockerOut(cctx, nil, "ps", "-aq", "--filter", "label="+rtLabel); strings.TrimSpace(ids) != "" {
			j.dockerOut(cctx, nil, append([]string{"rm", "-f"}, splitLines(ids)...)...)
		}
	})
	e.a, e.b = Ref{e.p, "w-a"}, Ref{e.p, "w-b"}
	refs = append(refs, e.a, e.b)
	e.provisionModules(j, e.a, e.repo)
	e.provisionModules(j, e.b, e.repo)

	var rows []rtRow
	for _, pr := range rtEgressProbes(&refs) {
		row := rtRow{ID: pr.id, Guarantee: "G2", Tries: pr.tries}
		t.Run(pr.id, func(t *testing.T) {
			e.t = t
			pr.run(e, &row)
			row.Verdict = "FAIL"
			if row.Jailed.OK && row.Control.OK {
				row.Verdict = "PASS"
			}
			if row.Verdict == "FAIL" {
				t.Errorf("%s: jailed %+v control %+v note %s", pr.id, row.Jailed, row.Control, row.Note)
			}
		})
		rows = append(rows, row)
	}
	e.t = t
	js, _ := json.MarshalIndent(rows, "", "  ")
	dir := filepath.Join("..", ".temp", "redteam")
	if err := os.MkdirAll(dir, 0o755); err == nil {
		os.WriteFile(filepath.Join(dir, "egress-report.json"), append(js, '\n'), 0o644)
	}
	t.Logf("egress probes:\n%s", js)
}

// askScript sends raw requests to the worker's socket with socat and prints, per request, the status and the denial code.
const askScript = `ask() { printf "$2" | socat -t 10 - UNIX-CONNECT:/run/wj/egress.sock | tr -d '\r' |
  sed -n -e '1s/^HTTP\/1.1 \([0-9]*\).*/\1/p' -e 's/^X-Worker-Jail-Denied: //p' | tr '\n' ' ' | sed "s/^/$1=/"; echo; }
`

func rtEgressProbes(refs *[]Ref) []rtProbe {
	// gen provisions the allowlist worker on first use; it is withdrawn and purged with the others.
	var g Ref
	gen := func(e *rtEnv) Ref {
		if g.Worker == "" {
			g = Ref{e.p, "w-gen"}
			*refs = append(*refs, g)
			if _, err := e.j.SetPolicy(e.ctx, g, rtAllowlist(e.t, g), SetPolicyOptions{}); err != nil {
				e.t.Fatalf("policy %v: %v", g, err)
			}
			if _, err := e.j.Provision(e.ctx, ProvisionSpec{Ref: g, Repo: e.repo}); err != nil {
				e.t.Fatalf("provision %v: %v", g, err)
			}
		}
		return g
	}
	return []rtProbe{
		{id: "E1-socket-scope", tries: "list /run/wj for other workers' sockets, write into it, list interfaces", run: func(e *rtEnv, row *rtRow) {
			s := `ls -A /run/wj; echo ---; touch /run/wj/x 2>/dev/null && echo WROTE; mkdir /run/wj/d 2>/dev/null && echo WROTE
echo ---; ip -o link | awk -F': ' '{print $2}'; echo ---
curl -s -o /dev/null -w 'OWN=%{http_code}\n' --unix-socket /run/wj/egress.sock http://wj/gomod/sumdb/sum.golang.org/supported`
			_, out := e.jrun(e.a, time.Minute, s)
			parts := strings.Split(out, "---")
			row.Jailed = rtOutcome{len(parts) == 4 && strings.TrimSpace(parts[0]) == probeSocketName &&
				!strings.Contains(out, "WROTE") && strings.TrimSpace(parts[2]) == "lo" && strings.Contains(parts[3], "OWN=200"), ev(out)}
			// Control: the whole socket volume, read-write, as the service's uid: the other worker's socket and a write.
			other := e.b.Project + "." + e.b.Worker
			cs := `ls -A /run/wj; touch /run/wj/x && echo WROTE; rm -f /run/wj/x`
			sub := "type=volume,src=" + EgressSockVolume + ",dst=/run/wj,volume-subpath=" + e.a.Project + "." + e.a.Worker + ",readonly"
			cout, _ := e.ctrlEgress(e.a, cs, e.replaceArg(sub, "type=volume,src="+EgressSockVolume+",dst=/run/wj"), e.user("10002:10002"))
			row.Control = rtOutcome{strings.Contains(cout, other) && strings.Contains(cout, "WROTE"), ev(cout)}
			row.Layers = []string{"volume-subpath of the worker's own directory", "readonly mount", "--network none"}
			row.Note = "control mounts the whole wj-egress-sock volume read-write as uid 10002 (the socket directories' owner)"
		}},
		{id: "E2-mode-confusion", tries: "CONNECT, absolute-URI GET and POST on a modules socket", run: func(e *rtEnv, row *rtRow) {
			s := askScript + `ask connect 'CONNECT proxy.golang.org:443 HTTP/1.1\r\nHost: proxy.golang.org:443\r\n\r\n'
ask absolute 'GET http://proxy.golang.org/golang.org/x/sync/@v/list HTTP/1.1\r\nHost: proxy.golang.org\r\n\r\n'
ask post 'POST /gomod/golang.org/x/sync/@v/list HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n'
ask unlisted 'GET /gomod/golang.org/x/text/@v/list HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n'`
			_, out := e.jrun(e.a, time.Minute, s)
			row.Jailed = rtOutcome{strings.Contains(out, "connect=403 mode") && strings.Contains(out, "absolute=403 mode") &&
				strings.Contains(out, "post=403 method") && strings.Contains(out, "unlisted=403 module"), ev(out)}
			// Control: the permitted form, an origin-form GET of a listed module, is served.
			_, cout := e.jrun(e.a, time.Minute, askScript+`ask origin 'GET /gomod/golang.org/x/sync/@v/list HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n'`)
			row.Control = rtOutcome{strings.Contains(cout, "origin=200"), ev(cout)}
			row.Layers = []string{"egress routing table (modules: origin-form GET/HEAD only)", "module masks"}
		}},
		{id: "E2-generic-mode-confusion", tries: "origin-form module GET, absolute-URI POST, https absolute URI and a Host mismatch on an allowlist socket",
			run: func(e *rtEnv, row *rtRow) {
				r := gen(e)
				s := askScript + `ask origin 'GET /gomod/golang.org/x/sync/@v/list HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n'
ask post 'POST http://proxy.golang.org/ HTTP/1.1\r\nHost: proxy.golang.org\r\nContent-Length: 0\r\n\r\n'
ask https 'GET https://proxy.golang.org/ HTTP/1.1\r\nHost: proxy.golang.org\r\n\r\n'
ask fronted 'GET http://proxy.golang.org:443/ HTTP/1.1\r\nHost: example.com\r\n\r\n'`
				_, out := e.jrun(r, time.Minute, s)
				row.Jailed = rtOutcome{strings.Contains(out, "origin=403 mode") && strings.Contains(out, "post=403 method") &&
					strings.Contains(out, "https=403 grammar") && strings.Contains(out, "fronted=403 host"), ev(out)}
				// Control: the permitted form, CONNECT to the listed host and port through the relay (HTTPS_PROXY).
				res, cout := e.jrun(r, time.Minute, `curl -sS -o /dev/null -w 'CODE=%{http_code}\n' https://proxy.golang.org/`)
				row.Control = rtOutcome{res.Exit == 0 && strings.Contains(cout, "CODE=") && !strings.Contains(cout, "CODE=000"),
					fmt.Sprintf("exit %d: %s", res.Exit, ev(cout))}
				row.Layers = []string{"egress routing table (generic: CONNECT and absolute-URI GET/HEAD only)", "Host checked against the authority"}
			}},
		{id: "E5-allowlist-anchoring", tries: "CONNECT to a suffix, a prefix, an IP literal, an unlisted port and an IDN of the allowlisted host",
			run: func(e *rtEnv, row *rtRow) {
				r := gen(e)
				c := func(name, authority string) string {
					return "ask " + name + " 'CONNECT " + authority + " HTTP/1.1\\r\\nHost: " + authority + "\\r\\n\\r\\n'\n"
				}
				// printf "$2" in ask: a literal % is written %%.
				s := askScript + c("suffix", "proxy.golang.org.evil.io:443") + c("prefix", "evilproxy.golang.org:443") +
					c("literal", "142.250.74.110:443") + c("port", "proxy.golang.org:80") + c("idn", "pr%%C3%%B6xy.golang.org:443")
				_, out := e.jrun(r, 2*time.Minute, s)
				row.Jailed = rtOutcome{strings.Contains(out, "suffix=403 host") && strings.Contains(out, "prefix=403 host") &&
					strings.Contains(out, "literal=403 host") && strings.Contains(out, "port=403 port") && strings.Contains(out, "idn=403 host"), ev(out)}
				// Control: the exact host, and its uppercase form with a trailing dot (the same canonical host), tunnel.
				_, cout := e.jrun(r, 2*time.Minute, askScript+c("exact", "proxy.golang.org:443")+c("canonical", "PROXY.Golang.ORG.:443"))
				row.Control = rtOutcome{strings.Contains(cout, "exact=200") && strings.Contains(cout, "canonical=200"), ev(cout)}
				row.Layers = []string{"host masks anchored as ^(?:mask)$ on the canonical host", "ports listed explicitly", "IDNs refused"}
			}},
		{id: "E8-fail-closed", tries: "Run with a corrupt policy file, a stale loaded id, and the service stopped", run: func(e *rtEnv, row *rtRow) {
			r, key := e.a, egressKey(e.a)
			stored := rtModules(e.t, r)
			run := func() error {
				_, err := e.j.Run(e.ctx, r, RunSpec{Argv: []string{"true"}, Timeout: time.Minute})
				return err
			}
			var got []string
			ok := true
			check := func(what string, err error) {
				got = append(got, fmt.Sprintf("%s: %v", what, err))
				ok = ok && errors.Is(err, ErrEgressUnavailable)
			}
			// A corrupt file: the listener closes, Run refuses.
			e.j.egressFile(e.ctx, r.Project, "put", key, []byte(`{"version":1,`))
			e.j.egressSignal(e.ctx)
			if err := e.waitLoaded(r, ""); err != nil {
				e.t.Fatal(err)
			}
			check("corrupt", run())
			// A stale id: the service serves another valid policy for the worker.
			other := modulesPolicy(e.t, r.Project, r.Worker, `golang\.org/x/.*`)
			e.j.egressFile(e.ctx, r.Project, "put", key, other)
			e.j.egressSignal(e.ctx)
			if err := e.waitLoaded(r, policyID(e.t, other)); err != nil {
				e.t.Fatal(err)
			}
			check("stale", run())
			if _, err := e.j.SetPolicy(e.ctx, r, stored, SetPolicyOptions{}); err != nil {
				e.t.Fatal(err)
			}
			// The service stopped.
			e.docker("stop", EgressContainer)
			check("stopped", run())
			if out, exit := e.docker("start", EgressContainer); exit != 0 {
				e.t.Fatalf("restart the service: %s", out)
			}
			if err := e.waitLoaded(r, policyID(e.t, stored)); err != nil {
				e.t.Fatal(err)
			}
			row.Jailed = rtOutcome{ok, strings.Join(got, "; ")}
			// Control: service up and on the stored id: the call runs and reaches the service.
			res, out := e.jrun(r, time.Minute, `curl -s -o /dev/null -w 'CODE=%{http_code}' -x '' http://127.0.0.1:3128/gomod/sumdb/sum.golang.org/supported`)
			row.Control = rtOutcome{res.Exit == 0 && strings.Contains(out, "CODE=200"), fmt.Sprintf("exit %d: %s", res.Exit, out)}
			row.Layers = []string{"Run compares the loaded id with the stored one", "invalid files close the listener"}
		}},
		{id: "E10-offline", tries: "go build of a module from the seeded cache with the relay killed inside the call", run: func(e *rtEnv, row *rtRow) {
			gj, err := New(Config{StateDir: e.j.state, Image: "worker-jail/go:1"})
			if err != nil {
				e.t.Fatal(err)
			}
			repo := newRepo(e.t)
			writeFile(e.t, filepath.Join(repo, "go.mod"), "module example.com/m\n\ngo 1.25\n")
			writeFile(e.t, filepath.Join(repo, "main.go"), "package main\n\nimport \"golang.org/x/sync/errgroup\"\n\nfunc main() { var g errgroup.Group; _ = g.Wait() }\n")
			get := exec.Command("go", "get", "golang.org/x/sync@v0.10.0")
			get.Dir, get.Env = repo, append(os.Environ(), "GOTOOLCHAIN=local")
			if out, err := get.CombinedOutput(); err != nil {
				e.t.Fatalf("host go get: %v %s", err, out)
			}
			git(e.t, repo, "add", "-A")
			git(e.t, repo, "commit", "-q", "-m", "module")
			seeded := Ref{e.p, "w-off"}
			bare := Ref{rtName("wjrt-"), "w-off"}
			*refs = append(*refs, seeded, bare)
			e.t.Cleanup(func() { gj.Purge(context.Background(), bare.Project) })
			e.provisionModules(gj, seeded, repo)
			e.provisionModules(gj, bare, repo)
			if err := gj.SeedGoMod(e.ctx, seeded.Project, repo, "HEAD"); err != nil {
				e.t.Fatal(err)
			}
			s := `pkill -x socat; sleep 0.3; go build ./... && echo BUILT`
			_, out := e.jrunWith(gj, seeded, 5*time.Minute, s)
			row.Jailed = rtOutcome{strings.Contains(out, "BUILT"), ev(out)}
			// Control: the same build without a seeded cache fails, so the probe sees a missing route.
			_, cout := e.jrunWith(gj, bare, 5*time.Minute, s)
			row.Control = rtOutcome{!strings.Contains(cout, "BUILT"), ev(cout)}
			row.Layers = []string{"GOPROXY lists the seeded cache (file://) before the egress relay"}
			row.Note = "the call kills its own relay: the service cannot be stopped without Run refusing the call (E8)"
		}},
	}
}

// probeSocketName is the one entry a worker sees under /run/wj (egress.SocketName; the jail does not import egress).
const probeSocketName = "egress.sock"
