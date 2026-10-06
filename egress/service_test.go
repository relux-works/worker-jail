package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/worker-jail/jail"
)

// modulesPolicy is a valid modules policy for p.w with the given masks and rate.
func modulesPolicy(p, w string, masks []string, rpm, conns, bytesPerDay int64) []byte {
	m, _ := json.Marshal(masks)
	return []byte(fmt.Sprintf(`{"version":1,"project":%q,"worker":%q,"tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},
 "network":{"mode":"modules","go_modules":%s,"rate":{"requests_per_min":%d,"max_conns":%d,"bytes_per_day":%d}},
 "limits":{"cpus":2,"memory_mib":2048,"pids":512,"call_timeout_s":600,"max_output_bytes":4194304,"disk_soft_mib":4096}}`,
		p, w, m, rpm, conns, bytesPerDay))
}

func defaultPolicy(p, w string) []byte {
	return modulesPolicy(p, w, []string{`golang\.org/x/.*`}, 600, 8, 1<<30)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// upstream is a fake proxy.golang.org (under /proxy) and sum.golang.org (under /sum) that records what it was asked.
type upstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	hits    map[string]int
	headers []http.Header
	routes  map[string]func(w http.ResponseWriter)
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{hits: map[string]int{}, routes: map[string]func(http.ResponseWriter){
		"/proxy/golang.org/x/text/@v/list":         text(200, "v0.13.0\nv0.14.0\n"),
		"/proxy/golang.org/x/text/@v/v0.14.0.info": text(200, `{"Version":"v0.14.0","Time":"2023-10-11T00:00:00Z"}`),
		"/proxy/golang.org/x/text/@v/v0.14.0.mod":  text(200, "module golang.org/x/text\n\ngo 1.18\n"),
		"/proxy/golang.org/x/text/@v/v0.14.0.zip":  text(200, strings.Repeat("Z", 4096)),
		"/proxy/golang.org/x/text/@latest":         text(200, `{"Version":"v0.14.0"}`),
		"/proxy/golang.org/x/gone/@v/v1.0.0.info":  text(410, "gone"),
		"/sum/latest":                                text(200, "go.sum database tree\n1\nhash\n"),
		"/sum/lookup/golang.org/x/text@v0.14.0":      text(200, "123\ngolang.org/x/text v0.14.0 h1:x\n"),
		"/sum/tile/8/0/000":                          text(200, "tile"),
		"/proxy/golang.org/x/redirect/@v/v1.0.0.zip": redirect("https://storage.example/zip"),
	}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits[r.URL.Path]++
		u.headers = append(u.headers, r.Header.Clone())
		h := u.routes[r.URL.Path]
		u.mu.Unlock()
		if h == nil {
			text(404, "not found: "+r.URL.Path)(w)
			return
		}
		h(w)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func text(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func redirect(to string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Location", to)
		w.WriteHeader(302)
	}
}

func (u *upstream) hit(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[path]
}

type env struct {
	t                   *testing.T
	s                   *Service
	sock, policy, cache string
	log                 *syncBuf
	up                  *upstream
	clock               *clock
}

// newEnv starts a service on short temporary directories (Unix socket paths are limited) against a fake upstream,
// with the real upstream client minus the dial guard (the upstream is on loopback); the guard has its own tests.
func newEnv(t *testing.T) *env {
	t.Helper()
	root, err := os.MkdirTemp("", "wje")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	e := &env{t: t, sock: filepath.Join(root, "s"), policy: filepath.Join(root, "p"), cache: filepath.Join(root, "c"),
		log: &syncBuf{}, up: newUpstream(t), clock: &clock{t: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}}
	for _, d := range []string{e.sock, e.policy, e.cache} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.s, err = New(Config{SockRoot: e.sock, PolicyDir: e.policy, CacheDir: e.cache, Log: e.log})
	if err != nil {
		t.Fatal(err)
	}
	e.s.now = e.clock.now
	e.s.proxyURL, e.s.sumURL = e.up.srv.URL+"/proxy", e.up.srv.URL+"/sum"
	e.s.client = newUpstreamClient((&net.Dialer{Timeout: time.Second}).DialContext)
	if err := e.s.listenControl(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.s.Close)
	return e
}

func (e *env) put(key string, data []byte) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.policy, key+".json"), data, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) sockPath(key string) string { return filepath.Join(e.sock, key, SocketName) }

type reply struct {
	status int
	denied string
	body   string
	header http.Header
	close  bool
}

// do sends raw on a fresh connection to key's socket and reads one response.
func (e *env) do(key, raw string) reply {
	e.t.Helper()
	c, err := net.Dial("unix", e.sockPath(key))
	if err != nil {
		e.t.Fatalf("dial %s: %v", key, err)
	}
	defer c.Close()
	return e.roundTrip(c, raw)
}

func (e *env) roundTrip(c net.Conn, raw string) reply {
	e.t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		e.t.Fatal(err)
	}
	method, _, _ := strings.Cut(raw, " ")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		e.t.Fatalf("read response to %q: %v", raw, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return reply{resp.StatusCode, resp.Header.Get("X-Worker-Jail-Denied"), string(b), resp.Header, resp.Close}
}

func get(path string) string { return "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\r\n" }

// The modules handler end to end on the worker's socket (E2, E3): every permitted kind is served from the fixed
// upstream; every refused form gets 403 with its code and a one-line body that names the denied thing and never
// the policy; the client's headers are not forwarded.
func TestServiceModules(t *testing.T) {
	e := newEnv(t)
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	allowed := []struct{ path, body string }{
		{"/gomod/golang.org/x/text/@v/list", "v0.13.0\nv0.14.0\n"},
		{"/gomod/golang.org/x/text/@v/v0.14.0.info", `{"Version":"v0.14.0","Time":"2023-10-11T00:00:00Z"}`},
		{"/gomod/golang.org/x/text/@v/v0.14.0.mod", "module golang.org/x/text\n\ngo 1.18\n"},
		{"/gomod/golang.org/x/text/@v/v0.14.0.zip", strings.Repeat("Z", 4096)},
		{"/gomod/golang.org/x/text/@latest", `{"Version":"v0.14.0"}`},
		{"/gomod/sumdb/sum.golang.org/supported", ""},
		{"/gomod/sumdb/sum.golang.org/latest", "go.sum database tree\n1\nhash\n"},
		{"/gomod/sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0", "123\ngolang.org/x/text v0.14.0 h1:x\n"},
		{"/gomod/sumdb/sum.golang.org/tile/8/0/000", "tile"},
	}
	for _, a := range allowed {
		r := e.do("p.w", "GET "+a.path+" HTTP/1.1\r\nHost: 127.0.0.1:3128\r\nAuthorization: Bearer WJ-CANARY-AUTH\r\nX-Canary: WJ-CANARY-HDR\r\n\r\n")
		if r.status != 200 || r.body != a.body || r.denied != "" {
			t.Errorf("%s: %d %q %q", a.path, r.status, r.denied, r.body)
		}
	}
	if e.up.hit("/sum/supported") != 0 {
		t.Error("supported went upstream; the service answers it")
	}
	for _, h := range e.up.headers {
		for k := range h {
			if k != "User-Agent" {
				t.Errorf("client header forwarded upstream: %s: %v", k, h[k])
			}
		}
	}
	// Not found passes through so that go falls back or reports it; a HEAD has no body.
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/v9.9.9.info")); r.status != 404 || !strings.Contains(r.body, "not found") {
		t.Errorf("404: %+v", r)
	}
	if r := e.do("p.w", get("/gomod/golang.org/x/gone/@v/v1.0.0.info")); r.status != 410 {
		t.Errorf("410: %+v", r)
	}
	if r := e.do("p.w", "HEAD /gomod/golang.org/x/text/@v/list HTTP/1.1\r\nHost: h\r\n\r\n"); r.status != 200 || r.body != "" {
		t.Errorf("HEAD: %+v", r)
	}
	denied := []struct{ raw, code, name string }{
		{get("/gomod/github.com/evil/x/@v/v1.0.0.zip"), CodeModule, "github.com/evil/x"},
		{get("/gomod/github.com/evil/x/@latest"), CodeModule, "github.com/evil/x"},
		{get("/gomod/github.com/evil/x/@v/list"), CodeModule, "github.com/evil/x"},
		{get("/gomod/sumdb/sum.golang.org/lookup/github.com/evil/x@v1.0.0"), CodeModule, "github.com/evil/x"},
		{get("/gomod/golang.org/x/text/@v/../../../etc/passwd"), CodeGrammar, ""},
		{get("/gomod/golang.org%2fx%2ftext/@v/list"), CodeGrammar, ""},
		{get("/gomod/sumdb/sum.example.com/latest"), CodeGrammar, ""},
		{get("/gomod/" + strings.Repeat("a", 2000)), CodeGrammar, ""},
		{get("/elsewhere"), CodeGrammar, ""},
		{"CONNECT proxy.golang.org:443 HTTP/1.1\r\nHost: proxy.golang.org:443\r\n\r\n", CodeMode, "CONNECT proxy.golang.org:443"},
		{"GET http://proxy.golang.org/golang.org/x/text/@v/list HTTP/1.1\r\nHost: proxy.golang.org\r\n\r\n", CodeMode, "GET http://"},
		{"POST /gomod/golang.org/x/text/@v/list HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", CodeMethod, "POST"},
		{"GET /gomod/golang.org/x/text/@v/list HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc", CodeGrammar, "request body"},
		{"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", CodeGrammar, "transfer-encoding"},
		{"GET / HTTP/1.1\r\nHost: h\r\nX: " + strings.Repeat("a", MaxHeaderBytes) + "\r\n\r\n", CodeSize, "header block"},
	}
	for _, d := range denied {
		r := e.do("p.w", d.raw)
		if r.status != 403 || r.denied != d.code || !strings.HasPrefix(r.body, "worker-jail egress: denied ("+d.code+")") ||
			!strings.Contains(r.body, d.name) || strings.Count(r.body, "\n") != 1 || strings.Contains(r.body, `golang\.org`) {
			t.Errorf("%.60q: %d %q %q", d.raw, r.status, r.denied, r.body)
		}
	}
	if e.up.hit("/proxy/github.com/evil/x/@v/v1.0.0.zip")+e.up.hit("/proxy/github.com/evil/x/@latest") != 0 {
		t.Error("a denied request reached the upstream")
	}
}

// Keep-alive: several requests on one connection are served in order (the go command reuses connections);
// a denial closes the connection.
func TestServiceKeepAlive(t *testing.T) {
	e := newEnv(t)
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	c, err := net.Dial("unix", e.sockPath("p.w"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		if r := e.roundTrip(c, get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if r := e.roundTrip(c, get("/gomod/github.com/evil/x/@v/list")); r.denied != CodeModule || !r.close {
		t.Fatalf("denial: %+v", r)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection open after a denial")
	}
}

// Sockets: <sockroot>/<P>.<W>/egress.sock, the directory 0755 and the socket 0666; only modules workers get one.
func TestServiceSockets(t *testing.T) {
	e := newEnv(t)
	e.put("p.w", defaultPolicy("p", "w"))
	e.put("p.none", []byte(strings.Replace(string(defaultPolicy("p", "none")), `"network":{"mode":"modules","go_modules":["golang\\.org/x/.*"],"rate":{"requests_per_min":600,"max_conns":8,"bytes_per_day":1073741824}}`, `"network":{"mode":"none"}`, 1)))
	e.s.Reload()
	di, err := os.Stat(filepath.Join(e.sock, "p.w"))
	if err != nil || di.Mode().Perm() != 0o755 {
		t.Fatalf("dir %v %v", di, err)
	}
	si, err := os.Stat(e.sockPath("p.w"))
	if err != nil || si.Mode().Perm() != 0o666 || si.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket %v %v", si, err)
	}
	if _, err := os.Stat(filepath.Join(e.sock, "p.none")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a none policy got a socket directory: %v", err)
	}
	if id, err := Status(e.cache, "p.w"); err != nil || id != policyIDOf(t, defaultPolicy("p", "w")) {
		t.Fatalf("status %q %v", id, err)
	}
	if _, err := Status(e.cache, "p.none"); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("status of none: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(e.cache, controlName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("control socket %v %v", fi, err)
	}
}

func policyIDOf(t *testing.T, data []byte) string {
	t.Helper()
	p, err := jail.ParsePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID()
}

// E7: a redirect from the modules upstream is not followed: 502 upstream, and the redirect target is never asked.
// Control: the same kind of object without a redirect is served.
func TestRedirectRefused(t *testing.T) {
	e := newEnv(t)
	other := newUpstream(t)
	e.up.routes["/proxy/golang.org/x/redirect/@v/v1.0.0.zip"] = redirect(other.srv.URL + "/stolen")
	e.up.routes["/sum/latest"] = func(w http.ResponseWriter) { w.Header().Set("Location", other.srv.URL+"/x"); w.WriteHeader(307) }
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	for _, path := range []string{"/gomod/golang.org/x/redirect/@v/v1.0.0.zip", "/gomod/sumdb/sum.golang.org/latest"} {
		if r := e.do("p.w", get(path)); r.status != 502 || r.denied != CodeUpstream {
			t.Errorf("%s: %+v", path, r)
		}
	}
	if other.hit("/stolen")+other.hit("/x") != 0 {
		t.Fatal("redirect target was asked")
	}
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/v0.14.0.zip")); r.status != 200 {
		t.Fatalf("control: %+v", r)
	}
}

// Upstream failures fail closed with 502 upstream, never a fallback: an unreachable upstream and a 500.
func TestUpstreamFailures(t *testing.T) {
	e := newEnv(t)
	e.up.routes["/proxy/golang.org/x/err/@v/list"] = text(500, "boom")
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	if r := e.do("p.w", get("/gomod/golang.org/x/err/@v/list")); r.status != 502 || r.denied != CodeUpstream {
		t.Errorf("500: %+v", r)
	}
	e.s.proxyURL = "http://127.0.0.1:1"
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 502 || r.denied != CodeUpstream {
		t.Errorf("unreachable: %+v", r)
	}
}

// The dial guard behind the service (E4): an upstream name resolving to a forbidden address is 403 guard, a resolver
// failure is 502 upstream; control: a public answer reaches the dial.
func TestServiceGuard(t *testing.T) {
	e := newEnv(t)
	res := &fakeResolver{answers: map[string][][]netip.Addr{
		"proxy.golang.org": {addrs("169.254.169.254")},
		"sum.golang.org":   {addrs("142.250.74.110")},
	}}
	var dialed []string
	e.s.client = newUpstreamClient((&guard{resolver: res, timeout: time.Second, dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errDialed
	}}).DialContext)
	e.s.proxyURL, e.s.sumURL = "http://proxy.golang.org", "http://sum.golang.org"
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 403 || r.denied != CodeGuard {
		t.Errorf("forbidden answer: %+v", r)
	}
	delete(res.answers, "proxy.golang.org")
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 502 || r.denied != CodeUpstream {
		t.Errorf("resolver failure: %+v", r)
	}
	if r := e.do("p.w", get("/gomod/sumdb/sum.golang.org/latest")); r.status != 502 || len(dialed) != 1 || dialed[0] != "142.250.74.110:80" {
		t.Errorf("control: %+v dialed %v", r, dialed)
	}
}

// E6: requests per minute, max_conns and bytes_per_day each engage with 403 rate for every request form, and lift
// when the bucket refills, the connection closes or the UTC day changes.
func TestRateLimits(t *testing.T) {
	t.Run("requests per minute", func(t *testing.T) {
		e := newEnv(t)
		e.put("p.w", modulesPolicy("p", "w", []string{`golang\.org/x/.*`}, 2, 8, 1<<30))
		e.s.Reload()
		for i := 0; i < 2; i++ {
			if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
				t.Fatalf("request %d: %+v", i, r)
			}
		}
		for _, raw := range []string{get("/gomod/golang.org/x/text/@v/list"), "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
			"POST /x HTTP/1.1\r\nHost: h\r\n\r\n", get("/gomod/github.com/evil/x/@v/list")} {
			if r := e.do("p.w", raw); r.status != 403 || r.denied != CodeRate {
				t.Errorf("%.40q over the limit: %+v", raw, r)
			}
		}
		e.clock.add(30 * time.Second) // one token back
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
			t.Fatalf("after refill: %+v", r)
		}
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.denied != CodeRate {
			t.Fatalf("one token only: %+v", r)
		}
		// Control: a reload with a higher limit lifts it without resetting what was spent.
		e.put("p.w", modulesPolicy("p", "w", []string{`golang\.org/x/.*`}, 600, 8, 1<<30))
		e.s.Reload()
		e.clock.add(time.Second)
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
			t.Fatalf("control: %+v", r)
		}
	})
	t.Run("max conns", func(t *testing.T) {
		e := newEnv(t)
		e.put("p.w", modulesPolicy("p", "w", []string{`golang\.org/x/.*`}, 600, 1, 1<<30))
		e.s.Reload()
		hold, err := net.Dial("unix", e.sockPath("p.w"))
		if err != nil {
			t.Fatal(err)
		}
		if r := e.roundTrip(hold, get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
			t.Fatalf("first connection: %+v", r)
		}
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 403 || r.denied != CodeRate {
			t.Fatalf("second connection: %+v", r)
		}
		hold.Close()
		deadline := time.Now().Add(5 * time.Second)
		for {
			r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list"))
			if r.status == 200 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("slot not released: %+v", r)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	t.Run("bytes per day", func(t *testing.T) {
		e := newEnv(t)
		e.put("p.w", modulesPolicy("p", "w", []string{`golang\.org/x/.*`}, 600, 8, 120))
		e.s.Reload()
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
			t.Fatalf("first: %+v", r)
		}
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 403 || r.denied != CodeRate {
			t.Fatalf("over the day's bytes: %+v", r)
		}
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/v0.14.0.zip")); r.denied != CodeRate {
			t.Fatalf("a body larger than what is left: %+v", r)
		}
		e.clock.add(12 * time.Hour) // 00:00 UTC
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
			t.Fatalf("next UTC day: %+v", r)
		}
	})
}

// E6 and G5: the cache is per worker. A hit for one worker is a miss for another (the upstream is asked again), and
// the mask is checked before the cache: a narrowed policy cannot read what it cached before.
func TestCachePerWorker(t *testing.T) {
	e := newEnv(t)
	e.put("p.a", defaultPolicy("p", "a"))
	e.put("p.b", defaultPolicy("p", "b"))
	e.s.Reload()
	const path = "/proxy/golang.org/x/text/@v/v0.14.0.zip"
	if r := e.do("p.a", get("/gomod/golang.org/x/text/@v/v0.14.0.zip")); r.status != 200 || e.up.hit(path) != 1 {
		t.Fatalf("a, first: %+v hits %d", r, e.up.hit(path))
	}
	if r := e.do("p.a", get("/gomod/golang.org/x/text/@v/v0.14.0.zip")); r.status != 200 || e.up.hit(path) != 1 {
		t.Fatalf("a, cache hit: %+v hits %d", r, e.up.hit(path))
	}
	if r := e.do("p.b", get("/gomod/golang.org/x/text/@v/v0.14.0.zip")); r.status != 200 || e.up.hit(path) != 2 {
		t.Fatalf("b sees a's cache: %+v hits %d", r, e.up.hit(path))
	}
	// Mutable answers are never cached.
	e.do("p.a", get("/gomod/golang.org/x/text/@v/list"))
	e.do("p.a", get("/gomod/golang.org/x/text/@v/list"))
	if n := e.up.hit("/proxy/golang.org/x/text/@v/list"); n != 2 {
		t.Fatalf("list cached: %d upstream hits", n)
	}
	e.put("p.a", modulesPolicy("p", "a", []string{`golang\.org/x/net`}, 600, 8, 1<<30))
	e.s.Reload()
	if r := e.do("p.a", get("/gomod/golang.org/x/text/@v/v0.14.0.zip")); r.denied != CodeModule {
		t.Fatalf("narrowed policy read its cache: %+v", r)
	}
	logs := e.log.String()
	if !strings.Contains(logs, `"cache":"hit"`) || !strings.Contains(logs, `"cache":"miss"`) {
		t.Fatalf("cache field not logged: %s", logs)
	}
}

// Caps: a response over the per-object cap is 403 size and not cached; once the worker's total cap is reached,
// responses are still served but no longer cached.
func TestCacheCaps(t *testing.T) {
	e := newEnv(t)
	e.s.objectCap, e.s.workerCap = 1024, 40
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/v0.14.0.zip")); r.status != 403 || r.denied != CodeSize {
		t.Fatalf("over the object cap: %+v", r)
	}
	for i := 0; i < 2; i++ {
		if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/v0.14.0.mod")); r.status != 200 {
			t.Fatalf("mod: %+v", r)
		}
	}
	if n := e.up.hit("/proxy/golang.org/x/text/@v/v0.14.0.mod"); n != 1 {
		t.Fatalf("mod under the total cap not cached: %d hits", n)
	}
	for i := 0; i < 2; i++ {
		e.do("p.w", get("/gomod/golang.org/x/text/@v/v0.14.0.info"))
	}
	if n := e.up.hit("/proxy/golang.org/x/text/@v/v0.14.0.info"); n != 2 {
		t.Fatalf("info over the total cap was cached: %d hits", n)
	}
	if ents, _ := os.ReadDir(filepath.Join(e.cache, "p.w", "tmp")); len(ents) != 0 {
		t.Fatalf("spool files left: %v", ents)
	}
}

// E8, fail closed: an invalid file closes only its worker's listener; a fixed file reopens it; a changed file is
// served only after a reload (a stale id until then); a removed file, a none or generic mode, a file for another
// target, a symlink and an unreadable policy directory all leave no listener.
func TestFailClosed(t *testing.T) {
	e := newEnv(t)
	e.put("p.a", defaultPolicy("p", "a"))
	e.put("p.b", defaultPolicy("p", "b"))
	e.s.Reload()
	listening := func(key string) bool {
		c, err := net.Dial("unix", e.sockPath(key))
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	if !listening("p.a") || !listening("p.b") {
		t.Fatal("control: both workers listen")
	}
	e.do("p.a", get("/gomod/golang.org/x/text/@v/v0.14.0.info")) // fills a's cache

	e.put("p.a", []byte(`{"version":1,`))
	e.s.Reload()
	if listening("p.a") || e.s.Loaded("p.a") != "" {
		t.Fatal("invalid file: listener still open")
	}
	if !listening("p.b") || e.do("p.b", get("/gomod/golang.org/x/text/@v/list")).status != 200 {
		t.Fatal("invalid file of a closed another worker")
	}
	if _, err := os.Stat(filepath.Join(e.cache, "p.a")); err != nil {
		t.Fatalf("invalid file dropped the cache: %v", err)
	}
	if !strings.Contains(e.log.String(), `"event":"policy-invalid"`) {
		t.Fatal("invalid file not logged")
	}

	narrow := modulesPolicy("p", "a", []string{`golang\.org/x/text`}, 600, 8, 1<<30)
	e.put("p.a", narrow)
	e.s.Reload()
	if !listening("p.a") || e.s.Loaded("p.a") != policyIDOf(t, narrow) {
		t.Fatal("fixed file: listener not reopened")
	}

	// A file changed without a reload is not served yet: Status still reports the old id, which Run compares.
	old := e.s.Loaded("p.b")
	wide := modulesPolicy("p", "b", []string{`.*`}, 600, 8, 1<<30)
	e.put("p.b", wide)
	if id, _ := Status(e.cache, "p.b"); id != old {
		t.Fatalf("stale id: %s", id)
	}
	if r := e.do("p.b", get("/gomod/github.com/evil/x/@v/list")); r.denied != CodeModule {
		t.Fatalf("unreloaded file served: %+v", r)
	}
	e.s.Reload()
	if id, _ := Status(e.cache, "p.b"); id != policyIDOf(t, wide) {
		t.Fatalf("reloaded id: %s", id)
	}

	os.Remove(filepath.Join(e.policy, "p.b.json"))
	e.s.Reload()
	if listening("p.b") {
		t.Fatal("removed file: listener still open")
	}
	for _, p := range []string{filepath.Join(e.sock, "p.b"), filepath.Join(e.cache, "p.b")} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("removed file left %s: %v", p, err)
		}
	}

	rate := `"rate":{"requests_per_min":600,"max_conns":8,"bytes_per_day":1073741824}`
	modules := `"mode":"modules","go_modules":["golang\\.org/x/.*"],` + rate
	for _, c := range []struct {
		key  string
		data string
	}{
		{"p.none", strings.Replace(string(defaultPolicy("p", "none")), modules, `"mode":"none"`, 1)},
		{"p.all", strings.Replace(string(defaultPolicy("p", "all")), modules, `"mode":"all","ports":["*"],`+rate, 1)},
		{"p.other", string(defaultPolicy("p", "elsewhere"))},
		{"p.v2", strings.Replace(string(defaultPolicy("p", "v2")), `"version":1`, `"version":2`, 1)},
	} {
		if _, err := jail.ParsePolicy([]byte(c.data)); err != nil && c.key != "p.v2" && c.key != "p.other" {
			t.Fatalf("%s fixture: %v", c.key, err)
		}
		e.put(c.key, []byte(c.data))
	}
	os.Symlink(filepath.Join(e.policy, "p.a.json"), filepath.Join(e.policy, "p.link.json"))
	e.s.Reload()
	for _, key := range []string{"p.none", "p.all", "p.other", "p.v2", "p.link"} {
		if listening(key) || e.s.Loaded(key) != "" {
			t.Errorf("%s: listener open", key)
		}
	}
	if !strings.Contains(e.log.String(), `"event":"policy-not-served","project":"p","worker":"all"`) {
		t.Error("generic mode not logged")
	}

	os.RemoveAll(e.policy)
	e.s.Reload()
	if listening("p.a") {
		t.Fatal("unreadable policy dir: listener still open")
	}
	if _, err := os.Stat(filepath.Join(e.cache, "p.a")); err != nil {
		t.Fatalf("unreadable policy dir dropped a cache: %v", err)
	}
	e.s.Close()
	if _, err := Status(e.cache, "p.a"); err == nil || errors.Is(err, ErrNotLoaded) {
		t.Fatalf("status of a stopped service: %v", err)
	}
}

// A connection that sends no complete head within the header timeout is closed without an answer.
func TestHeaderTimeout(t *testing.T) {
	e := newEnv(t)
	e.s.headerTimeout = 100 * time.Millisecond
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	c, err := net.Dial("unix", e.sockPath("p.w"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /gomod/golang.org/x/text/@v/list HTTP/1.1\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 64))
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read %d %v, want the service to close", n, err)
	}
}

type panicTransport struct{ next http.RoundTripper }

func (p panicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "/panic") {
		panic("handler bug")
	}
	return p.next.RoundTrip(r)
}

// A panic in a handler closes that connection only; the worker's listener keeps serving.
func TestPanicKeepsListener(t *testing.T) {
	e := newEnv(t)
	e.s.client.Transport = panicTransport{e.s.client.Transport}
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	c, err := net.Dial("unix", e.sockPath("p.w"))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, get("/gomod/golang.org/x/panic/@v/list"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _ := c.Read(make([]byte, 64)); n != 0 {
		t.Fatal("panicking request got an answer")
	}
	c.Close()
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
		t.Fatalf("listener after a panic: %+v", r)
	}
	if !strings.Contains(e.log.String(), `"event":"panic"`) {
		t.Fatal("panic not logged")
	}
}

// Every request logs exactly the fields of egress.md §5 as one JSON line, and never a header or a body.
func TestLogFields(t *testing.T) {
	e := newEnv(t)
	e.up.routes["/proxy/golang.org/x/text/@v/v0.14.0.info"] = text(200, "WJ-CANARY-BODY")
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	e.do("p.w", "GET /gomod/golang.org/x/text/@v/v0.14.0.info HTTP/1.1\r\nHost: h\r\nX-Canary: WJ-CANARY-HDR\r\n\r\n")
	e.do("p.w", get("/gomod/github.com/evil/x/@v/list"))
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(e.log.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a JSON line: %q", l)
		}
		if _, ok := m["event"]; !ok {
			lines = append(lines, m)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("request lines: %v", lines)
	}
	want := []string{"ts", "project", "worker", "policy_id", "mode", "handler", "method", "host", "port", "path", "decision",
		"code", "status", "bytes_in", "bytes_out", "dur_ms", "cache", "ip"}
	for _, l := range lines {
		if len(l) != len(want) {
			t.Errorf("fields %v", l)
		}
		for _, k := range want {
			if _, ok := l[k]; !ok {
				t.Errorf("field %s missing: %v", k, l)
			}
		}
	}
	a, d := lines[0], lines[1]
	if a["project"] != "p" || a["worker"] != "w" || a["policy_id"] != policyIDOf(t, defaultPolicy("p", "w")) || a["mode"] != "modules" ||
		a["handler"] != "modules" || a["method"] != "GET" || a["host"] != proxyHost || a["port"] != 443.0 ||
		a["path"] != "/gomod/golang.org/x/text/@v/v0.14.0.info" || a["decision"] != "allow" || a["status"] != 200.0 ||
		a["bytes_out"] != float64(len("WJ-CANARY-BODY")) || a["cache"] != "miss" || a["ip"] != "127.0.0.1" {
		t.Errorf("allowed line %v", a)
	}
	if d["decision"] != "deny" || d["code"] != CodeModule || d["status"] != 403.0 {
		t.Errorf("denied line %v", d)
	}
	if strings.Contains(e.log.String(), "WJ-CANARY") {
		t.Fatal("a header or body reached the log")
	}
}

type gateWriter struct {
	gate chan struct{}
	buf  syncBuf
}

func (g *gateWriter) Write(p []byte) (int, error) {
	<-g.gate
	return g.buf.Write(p)
}

// A log sink blocked for 5 s makes the service refuse new connections until the sink recovers.
func TestLogSinkStall(t *testing.T) {
	e := newEnv(t)
	e.put("p.w", defaultPolicy("p", "w"))
	e.s.Reload()
	g := &gateWriter{gate: make(chan struct{})}
	e.s.log.mu.Lock()
	e.s.log.w = g
	e.s.log.mu.Unlock()
	go e.do("p.w", get("/gomod/golang.org/x/text/@v/list")) // its log line blocks
	for e.s.log.busySince.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if e.s.log.stalled() {
		t.Fatal("stalled before 5 s")
	}
	e.clock.add(sinkStall)
	c, err := net.Dial("unix", e.sockPath("p.w"))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, get("/gomod/golang.org/x/text/@v/list"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _ := c.Read(make([]byte, 64)); n != 0 {
		t.Fatal("connection served while the sink is blocked")
	}
	c.Close()
	close(g.gate)
	if r := e.do("p.w", get("/gomod/golang.org/x/text/@v/list")); r.status != 200 {
		t.Fatalf("after recovery: %+v", r)
	}
}
