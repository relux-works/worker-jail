package egress

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// genericPolicy is a valid generic policy for p.w: mode allowlist, denylist or all, host masks (nil for all), ports
// (a list of ints, or "*"), and the rate.
func genericPolicy(p, w, mode string, hosts []string, ports any, rpm, conns, bytesPerDay int64) []byte {
	if ports == "*" {
		ports = []string{"*"}
	}
	pj, _ := json.Marshal(ports)
	hj := ""
	if hosts != nil {
		h, _ := json.Marshal(hosts)
		hj = `"hosts":` + string(h) + `,`
	}
	return []byte(fmt.Sprintf(`{"version":1,"project":%q,"worker":%q,"tools":{"mode":"yolo"},
 "workspace":{"access":"read-write","write_scope":["*"]},
 "network":{"mode":%q,%s"ports":%s,"rate":{"requests_per_min":%d,"max_conns":%d,"bytes_per_day":%d}},
 "limits":{"cpus":2,"memory_mib":2048,"pids":512,"call_timeout_s":600,"max_output_bytes":4194304,"disk_soft_mib":4096}}`,
		p, w, mode, hj, pj, rpm, conns, bytesPerDay))
}

func allowlist(p, w string, hosts []string, ports ...int) []byte {
	return genericPolicy(p, w, jail.NetAllowlist, hosts, ports, 600, 64, 1<<30)
}

// genericEnv is env with the generic handlers' dial guard over a fake resolver. Every dial the guard lets through
// reaches target (a loopback server), whatever checked public address it was given; dialed records those addresses.
type genericEnv struct {
	*env
	res    *fakeResolver
	mu     sync.Mutex
	dialed []string
	target string
}

func newGenericEnv(t *testing.T) *genericEnv {
	g := &genericEnv{env: newEnv(t), res: &fakeResolver{answers: map[string][][]netip.Addr{}}}
	g.target = echoServer(t)
	g.s.dial = (&guard{resolver: g.res, timeout: time.Second, dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
		g.mu.Lock()
		g.dialed = append(g.dialed, addr)
		to := g.target
		g.mu.Unlock()
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", to)
	}}).DialContext
	return g
}

// public makes each name resolve to a public address.
func (g *genericEnv) public(names ...string) {
	g.res.mu.Lock()
	defer g.res.mu.Unlock()
	for _, n := range names {
		g.res.answers[n] = [][]netip.Addr{addrs("93.184.216.34")}
	}
}

func (g *genericEnv) lastDialed() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.dialed) == 0 {
		return ""
	}
	return g.dialed[len(g.dialed)-1]
}

func (g *genericEnv) dialCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.dialed)
}

func (g *genericEnv) setTarget(addr string) {
	g.mu.Lock()
	g.target = addr
	g.mu.Unlock()
}

func (g *genericEnv) lookups() int {
	g.res.mu.Lock()
	defer g.res.mu.Unlock()
	return g.res.lookups
}

// echoServer echoes every connection until the client half-closes.
func echoServer(t *testing.T) string {
	return tcpServer(t, func(c net.Conn) { io.Copy(c, c) })
}

func tcpServer(t *testing.T, serve func(net.Conn)) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				serve(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// open sends raw on a fresh connection and reads the response head; a 200 to CONNECT leaves the tunnel open on the
// returned connection and reader, any other answer is read whole, and then open waits until the service closes the
// connection (every other generic answer ends it), so its max_conns slot is free again.
func (g *genericEnv) open(key, raw string) (net.Conn, *bufio.Reader, reply) {
	g.t.Helper()
	c, err := net.Dial("unix", g.sockPath(key))
	if err != nil {
		g.t.Fatalf("dial %s: %v", key, err)
	}
	g.t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		g.t.Fatal(err)
	}
	method, _, _ := strings.Cut(raw, " ")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		g.t.Fatalf("read response to %.60q: %v", raw, err)
	}
	r := reply{status: resp.StatusCode, denied: resp.Header.Get("X-Worker-Jail-Denied"), header: resp.Header}
	if method != "CONNECT" || resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		r.body = string(b)
		io.Copy(io.Discard, br)
	}
	return c, br, r
}

func connectReq(authority string) string {
	return "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
}

// tunnelEcho writes msg into an open tunnel and reports whether the echo comes back.
func tunnelEcho(c net.Conn, br *bufio.Reader, msg string) bool {
	if _, err := io.WriteString(c, msg); err != nil {
		return false
	}
	buf := make([]byte, len(msg))
	_, err := io.ReadFull(br, buf)
	return err == nil && string(buf) == msg
}

// requestLines returns the request lines of the log (no events).
func requestLines(t *testing.T, log string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(log), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a JSON line: %q", l)
		}
		if _, ok := m["event"]; !ok {
			out = append(out, m)
		}
	}
	return out
}

// waitLog polls until the log has n request lines (a tunnel's line is written when it ends).
func waitLog(t *testing.T, e *env, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l := requestLines(t, e.log.String()); len(l) >= n || time.Now().After(deadline) {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// E2 for the generic modes, end to end on the worker's socket: CONNECT and absolute-URI GET and HEAD reach the generic
// handlers on an allowlist listener; the origin form (the modules path) is mode, other methods are method, an https
// absolute URI and a non-authority CONNECT target are grammar. Control: the same CONNECT and absolute URI on a modules
// listener stay mode, and an origin-form module request there is served.
func TestGenericForms(t *testing.T) {
	g := newGenericEnv(t)
	httpUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "page") }))
	defer httpUp.Close()
	g.public("example.com")
	g.put("p.g", allowlist("p", "g", []string{`example\.com`}, 443, 80))
	g.put("p.m", defaultPolicy("p", "m"))
	g.s.Reload()

	c, br, r := g.open("p.g", connectReq("example.com:443"))
	if r.status != 200 || !tunnelEcho(c, br, "hello through the tunnel") {
		t.Fatalf("CONNECT: %+v", r)
	}
	g.setTarget(strings.TrimPrefix(httpUp.URL, "http://"))
	if _, _, r := g.open("p.g", "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n"); r.status != 200 || r.body != "page" {
		t.Fatalf("absolute GET: %+v", r)
	}
	if _, _, r := g.open("p.g", "HEAD http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n"); r.status != 200 || r.body != "" {
		t.Fatalf("absolute HEAD: %+v", r)
	}
	for _, d := range []struct{ raw, code string }{
		{get("/gomod/golang.org/x/text/@v/list"), CodeMode},
		{get("/"), CodeMode},
		{"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n", CodeMethod},
		{"PUT http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", CodeMethod},
		{"POST /gomod/x HTTP/1.1\r\nHost: h\r\n\r\n", CodeMethod},
		{"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", CodeGrammar},
		{"GET ftp://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", CodeGrammar},
		{"GET http://example.com/#frag HTTP/1.1\r\nHost: example.com\r\n\r\n", CodeGrammar},
		{"GET http://user@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", CodeGrammar},
		{connectReq("/gomod/x"), CodeGrammar},
		{"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 2\r\n\r\nab", CodeGrammar},
	} {
		if _, _, r := g.open("p.g", d.raw); r.status != 403 || r.denied != d.code {
			t.Errorf("%.50q: %+v, want %s", d.raw, r, d.code)
		}
	}
	for _, raw := range []string{connectReq("example.com:443"), "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n"} {
		if _, _, r := g.open("p.m", raw); r.status != 403 || r.denied != CodeMode {
			t.Errorf("modules listener %.40q: %+v", raw, r)
		}
	}
	if _, _, r := g.open("p.m", "GET /gomod/golang.org/x/text/@v/list HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"); r.status != 200 {
		t.Fatalf("control: modules origin form: %+v", r)
	}
}

// The authority parser and the host canonicalisation (E5, policy.md §2): lowercase, no trailing dot, IPv6 unbracketed
// and canonical, IPv4-mapped as IPv4, percent-escapes decoded; refused: IDNs (non-ASCII), numeric non-dotted-quad
// hosts, bad labels, userinfo, unbracketed IPv6, missing or non-canonical ports. Positive controls in the same table.
func TestParseAuthority(t *testing.T) {
	cases := []struct {
		in      string
		defPort int
		host    string
		port    int
		code    string // "" when accepted
	}{
		{"example.com:443", 0, "example.com", 443, ""},
		{"EXAMPLE.Com:443", 0, "example.com", 443, ""},
		{"example.com.:443", 0, "example.com", 443, ""},
		{"xn--bcher-kva.example:443", 0, "xn--bcher-kva.example", 443, ""},
		{"a-b.c0.example:8443", 0, "a-b.c0.example", 8443, ""},
		{"example.com", 80, "example.com", 80, ""},
		{"example.com:8080", 80, "example.com", 8080, ""},
		{"140.82.112.3:443", 0, "140.82.112.3", 443, ""},
		{"[2001:DB8::1]:443", 0, "2001:db8::1", 443, ""},
		{"[2001:0db8:0:0::1]:443", 0, "2001:db8::1", 443, ""},
		{"[::ffff:140.82.112.3]:443", 0, "140.82.112.3", 443, ""},
		{"[::1]:443", 0, "::1", 443, ""}, // canonical; the dial guard refuses it
		{"exa%6Dple.com:443", 0, "example.com", 443, ""},
		{"example.com:65535", 0, "example.com", 65535, ""},

		{"example.com", 0, "", 0, CodeGrammar},       // CONNECT needs a port
		{"example.com:", 0, "", 0, CodeGrammar},      // empty port
		{"example.com:0", 0, "", 0, CodeGrammar},     // port 0
		{"example.com:0443", 0, "", 0, CodeGrammar},  // leading zero
		{"example.com:65536", 0, "", 0, CodeGrammar}, // out of range
		{"example.com:+443", 0, "", 0, CodeGrammar},
		{"example.com:443:1", 0, "", 0, CodeGrammar},
		{"user@example.com:443", 0, "", 0, CodeGrammar},
		{"example.com/x:443", 0, "", 0, CodeGrammar},
		{"::1:443", 0, "", 0, CodeGrammar},
		{"[::1:443", 0, "", 0, CodeGrammar},
		{"[::1]x:443", 0, "", 0, CodeGrammar},
		{"", 0, "", 0, CodeGrammar},
		{"exa%zzmple.com:443", 0, "", 0, CodeGrammar},
		{"[fe80::1%25eth0]:443", 0, "", 0, CodeHost}, // zone
		{"[1.2.3.4]:443", 0, "", 0, CodeHost},
		{"b%C3%BCcher.example:443", 0, "", 0, CodeHost}, // an IDN, percent-encoded
		{"bücher.example:443", 0, "", 0, CodeHost},      // an IDN, raw (the parser refuses it earlier)
		{"127.1:443", 0, "", 0, CodeHost},
		{"2130706433:443", 0, "", 0, CodeHost},
		{"0177.0.0.1:443", 0, "", 0, CodeHost},
		{"%3A%3A1:443", 0, "", 0, CodeHost}, // ::1 smuggled through escapes
		{"a..b:443", 0, "", 0, CodeHost},
		{"example.com..:443", 0, "", 0, CodeHost},
		{".:443", 0, "", 0, CodeHost},
		{"-a.example:443", 0, "", 0, CodeHost},
		{"a-.example:443", 0, "", 0, CodeHost},
		{"a_b.example:443", 0, "", 0, CodeHost},
		{"a%00b.example:443", 0, "", 0, CodeHost},
		{strings.Repeat("a", 64) + ".example:443", 0, "", 0, CodeHost},
		{strings.Repeat("abcdefg.", 32) + "com:443", 0, "", 0, CodeHost}, // 259 bytes
	}
	for _, c := range cases {
		host, port, err := parseAuthority(c.in, c.defPort)
		code := ""
		if err != nil {
			code = err.(*authError).code
		}
		if code != c.code || host != c.host || port != c.port {
			t.Errorf("%q: %q %d %v, want %q %d %q", c.in, host, port, err, c.host, c.port, c.code)
		}
	}
}

// E5 against the service: host masks are anchored and match the canonical host only. github\.com admits github.com in
// any case and with a trailing dot (positive controls), and refuses github.com.evil.io, evilgithub.com, an IP literal of
// the same host, a percent-encoded IDN (host) and a raw one (the strict parser: grammar). A punycode mask admits the
// punycode host; an IP mask admits the literal as text. Nothing refused is ever resolved or dialed.
func TestHostMaskAnchoring(t *testing.T) {
	g := newGenericEnv(t)
	g.public("github.com", "github.com.evil.io", "evilgithub.com", "xn--bcher-kva.example")
	g.put("p.w", allowlist("p", "w", []string{`github\.com`, `xn--bcher-kva\.example`, `140\.82\.112\.4`}, 443))
	g.s.Reload()
	for _, c := range []struct {
		authority, code string
	}{
		{"github.com:443", ""},
		{"GITHUB.COM:443", ""},
		{"GitHub.Com.:443", ""},
		{"xn--bcher-kva.example:443", ""},
		{"XN--BCHER-KVA.example:443", ""},
		{"140.82.112.4:443", ""},
		{"github.com.evil.io:443", CodeHost},
		{"evilgithub.com:443", CodeHost},
		{"github.com.:80", CodePort},
		{"140.82.112.3:443", CodeHost},
		{"[::ffff:140.82.112.3]:443", CodeHost},
		{"b%C3%BCcher.example:443", CodeHost},
		{"bücher.example:443", CodeGrammar},
	} {
		before := g.dialCount()
		_, _, r := g.open("p.w", connectReq(c.authority))
		switch {
		case c.code == "" && r.status != 200:
			t.Errorf("%s: %+v, want 200", c.authority, r)
		case c.code != "" && (r.status != 403 || r.denied != c.code):
			t.Errorf("%s: %+v, want %s", c.authority, r, c.code)
		case c.code != "" && g.dialCount() != before:
			t.Errorf("%s: refused, but dialed %s", c.authority, g.lastDialed())
		}
	}
}

// Ports are never implied (allowlist lists them; 80 and 443 included), ["*"] admits any port where the policy allows
// it (denylist and all), and an explicit list in all is exact. Each refusal is next to an admitted control.
func TestGenericPorts(t *testing.T) {
	g := newGenericEnv(t)
	g.public("example.com")
	g.put("p.allow", allowlist("p", "allow", []string{`example\.com`}, 8443))
	g.put("p.deny", genericPolicy("p", "deny", jail.NetDenylist, []string{`evil\.io`}, "*", 600, 64, 1<<30))
	g.put("p.all", genericPolicy("p", "all", jail.NetAll, nil, []int{443, 22}, 600, 64, 1<<30))
	g.put("p.any", genericPolicy("p", "any", jail.NetAll, nil, "*", 600, 64, 1<<30))
	g.s.Reload()
	for _, c := range []struct {
		key, authority string
		ok             bool
	}{
		{"p.allow", "example.com:8443", true},
		{"p.allow", "example.com:443", false},
		{"p.allow", "example.com:80", false},
		{"p.deny", "example.com:1", true},
		{"p.deny", "example.com:65535", true},
		{"p.all", "example.com:443", true},
		{"p.all", "example.com:22", true},
		{"p.all", "example.com:80", false},
		{"p.all", "example.com:4443", false},
		{"p.any", "example.com:25", true},
	} {
		_, _, r := g.open(c.key, connectReq(c.authority))
		if c.ok && r.status != 200 || !c.ok && (r.status != 403 || r.denied != CodePort) {
			t.Errorf("%s %s: %+v", c.key, c.authority, r)
		}
	}
	// The absolute form's port defaults to 80, which must be listed too.
	if _, _, r := g.open("p.allow", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"); r.denied != CodePort {
		t.Errorf("absolute without a port under allowlist 8443: %+v", r)
	}
}

// Deny wins in denylist: a host that any mask matches is refused on every port and in both forms, even when another
// mask does not match it; hosts no mask matches pass (controls), IP literals included (a name denylist does not
// cover them, as the threat model states).
func TestDenylistDenyWins(t *testing.T) {
	g := newGenericEnv(t)
	g.public("api.evil.io", "evil.io", "github.com", "example.com", "notevil.io", "github.com.example.com")
	g.put("p.w", genericPolicy("p", "w", jail.NetDenylist, []string{`(.*\.)?evil\.io`, `github\.com`, `nomatch\.example`}, "*", 600, 64, 1<<30))
	g.s.Reload()
	for _, c := range []struct {
		raw  string
		deny bool
	}{
		{connectReq("api.evil.io:443"), true},
		{connectReq("EVIL.IO.:8443"), true},
		{connectReq("github.com:22"), true},
		{"GET http://evil.io/ HTTP/1.1\r\nHost: evil.io\r\n\r\n", true},
		{connectReq("example.com:443"), false},
		{connectReq("notevil.io:443"), false},
		{connectReq("github.com.example.com:443"), false},
		{connectReq("93.184.216.34:443"), false},
	} {
		_, _, r := g.open("p.w", c.raw)
		if c.deny && (r.status != 403 || r.denied != CodeHost) || !c.deny && r.status != 200 {
			t.Errorf("%.50q: %+v", c.raw, r)
		}
	}
}

// E4 through CONNECT and the absolute form: an answer in a forbidden range, a mixed answer, an IPv4-mapped, NAT64 or
// 6to4 form, and IP literals of loopback and metadata are 403 guard and never dialed; a rebinding resolver is asked
// once per connection and the checked address is what gets dialed, so the second lookup's loopback answer only
// refuses the next connection. Control: a public answer is dialed.
func TestGenericGuard(t *testing.T) {
	g := newGenericEnv(t)
	set := func(name string, answers ...[]netip.Addr) {
		g.res.mu.Lock()
		g.res.answers[name] = answers
		g.res.mu.Unlock()
	}
	set("loop.example", addrs("127.0.0.1"))
	set("meta.example", addrs("169.254.169.254"))
	set("lima.example", addrs("192.168.5.2"))
	set("mixed.example", addrs("93.184.216.34", "10.0.0.1"))
	set("mapped.example", addrs("::ffff:127.0.0.1"))
	set("nat64.example", addrs("64:ff9b::a9fe:a9fe"))
	set("sixtofour.example", addrs("2002:c0a8:502::1"))
	set("ula.example", addrs("fd00::1"))
	set("public.example", addrs("93.184.216.34"))
	g.put("p.w", genericPolicy("p", "w", jail.NetAll, nil, "*", 600, 64, 1<<30))
	g.s.Reload()
	for _, raw := range []string{
		connectReq("loop.example:443"), connectReq("meta.example:80"), connectReq("lima.example:443"),
		connectReq("mixed.example:443"), connectReq("mapped.example:443"), connectReq("nat64.example:443"),
		connectReq("sixtofour.example:443"), connectReq("ula.example:443"),
		connectReq("127.0.0.1:443"), connectReq("[::1]:443"), connectReq("169.254.169.254:80"), connectReq("[::ffff:10.0.0.1]:443"),
		"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
		"GET http://meta.example/ HTTP/1.1\r\nHost: meta.example\r\n\r\n",
	} {
		if _, _, r := g.open("p.w", raw); r.status != 403 || r.denied != CodeGuard {
			t.Errorf("%.50q: %+v", raw, r)
		}
	}
	if n := g.dialCount(); n != 0 {
		t.Fatalf("forbidden destinations dialed: %d", n)
	}
	if _, _, r := g.open("p.w", connectReq("unknown.example:443")); r.status != 502 || r.denied != CodeUpstream {
		t.Errorf("resolver failure: %+v", r)
	}

	set("rebind.example", addrs("93.184.216.34"), addrs("127.0.0.1"))
	before := g.lookups()
	c, br, r := g.open("p.w", connectReq("rebind.example:443"))
	if r.status != 200 || !tunnelEcho(c, br, "x") || g.lastDialed() != "93.184.216.34:443" || g.lookups() != before+1 {
		t.Fatalf("rebinding, first connection: %+v dialed %s lookups %d", r, g.lastDialed(), g.lookups()-before)
	}
	if _, _, r := g.open("p.w", connectReq("rebind.example:443")); r.status != 403 || r.denied != CodeGuard || g.dialCount() != 1 {
		t.Fatalf("rebinding, second connection: %+v dialed %d", r, g.dialCount())
	}
	if _, _, r := g.open("p.w", connectReq("public.example:8443")); r.status != 200 || g.lastDialed() != "93.184.216.34:8443" {
		t.Fatalf("control: %+v dialed %s", r, g.lastDialed())
	}
}

// Plain HTTP forwarding: the request goes upstream in origin form with the query, Host is the checked authority,
// hop-by-hop, Proxy-* and Connection-named headers are dropped and end-to-end ones kept; the response (a redirect
// here) passes back unchanged and is not followed. A Host header naming another authority is refused before any dial.
func TestPlainHTTPForwarding(t *testing.T) {
	g := newGenericEnv(t)
	type seen struct {
		uri, host string
		header    http.Header
	}
	got := make(chan seen, 4)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.RequestURI, r.Host, r.Header.Clone()}
		w.Header().Set("Location", "http://elsewhere.example/")
		w.WriteHeader(302)
		io.WriteString(w, "moved")
	}))
	defer up.Close()
	g.setTarget(strings.TrimPrefix(up.URL, "http://"))
	g.public("example.com", "other.example")
	g.put("p.w", allowlist("p", "w", []string{`example\.com`, `other\.example`}, 80, 8080))
	g.s.Reload()
	raw := "GET http://Example.COM:8080/a/b?q=1&r=2 HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: test\r\nAccept: */*\r\n" +
		"X-Keep: yes\r\nProxy-Authorization: Basic WJ-CANARY\r\nProxy-Connection: keep-alive\r\nProxy-Foo: x\r\n" +
		"Connection: keep-alive, X-Drop\r\nX-Drop: x\r\nKeep-Alive: 300\r\nTE: trailers\r\nUpgrade: websocket\r\nTrailer: X\r\n\r\n"
	_, _, r := g.open("p.w", raw)
	if r.status != 302 || r.header.Get("Location") != "http://elsewhere.example/" || r.body != "moved" {
		t.Fatalf("response: %+v", r)
	}
	s := <-got
	if s.uri != "/a/b?q=1&r=2" || s.host != "example.com:8080" || s.header.Get("X-Keep") != "yes" ||
		s.header.Get("User-Agent") != "test" || s.header.Get("Accept") != "*/*" {
		t.Fatalf("upstream saw %+v", s)
	}
	for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "Proxy-Foo", "X-Drop", "Keep-Alive", "Te", "Upgrade", "Trailer"} {
		if v := s.header.Values(h); len(v) != 0 {
			t.Errorf("forwarded %s: %v", h, v)
		}
	}
	if c := s.header.Get("Connection"); c != "close" && c != "" {
		t.Errorf("Connection %q", c)
	}
	// No path in the URI: origin form "/"; the default port is 80 and Host has no port.
	g.open("p.w", "GET http://example.com HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
	if s := <-got; s.uri != "/" || s.host != "example.com" {
		t.Fatalf("no path: %+v", s)
	}
	n := g.dialCount()
	for _, host := range []string{"other.example", "example.com:8080", "example.com.evil.io", "", "example.com:81"} {
		if _, _, r := g.open("p.w", "GET http://example.com/ HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); r.status != 403 || r.denied != CodeHost {
			t.Errorf("Host %q: %+v", host, r)
		}
	}
	if g.dialCount() != n || len(got) != 0 {
		t.Fatalf("a Host mismatch reached the upstream: %d dials", g.dialCount()-n)
	}
	// Control: the case and the trailing dot of Host do not matter.
	if _, _, r := g.open("p.w", "GET http://example.com/ HTTP/1.1\r\nHost: EXAMPLE.com.\r\n\r\n"); r.status != 302 {
		t.Fatalf("control: %+v", r)
	}
	<-got
}

// Upstream failures in the absolute form are 502 upstream: a refused connection and a response that is not HTTP.
func TestPlainHTTPUpstreamFailures(t *testing.T) {
	g := newGenericEnv(t)
	g.public("example.com")
	g.put("p.w", allowlist("p", "w", []string{`example\.com`}, 80))
	g.s.Reload()
	g.setTarget(tcpServer(t, func(c net.Conn) { io.WriteString(c, "SSH-2.0-OpenSSH\r\n") }))
	if _, _, r := g.open("p.w", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"); r.status != 502 || r.denied != CodeUpstream {
		t.Errorf("not HTTP: %+v", r)
	}
	g.setTarget("127.0.0.1:1")
	if _, _, r := g.open("p.w", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"); r.status != 502 || r.denied != CodeUpstream {
		t.Errorf("refused: %+v", r)
	}
}

// The per-connection byte cap is the worker's remaining daily bytes, spent as bytes pass in either direction: a tunnel
// that would exceed it is cut (the chunk that does not fit is not forwarded) and logged with code rate and end bytes,
// and the next request is 403 rate. Control: the same exchange under a large budget passes whole.
func TestTunnelByteCap(t *testing.T) {
	for _, c := range []struct {
		name   string
		budget int64
		cut    bool
	}{{"capped", 2048, true}, {"control", 1 << 30, false}} {
		t.Run(c.name, func(t *testing.T) {
			g := newGenericEnv(t)
			g.public("example.com")
			g.put("p.w", genericPolicy("p", "w", jail.NetAllowlist, []string{`example\.com`}, []int{443}, 600, 64, c.budget))
			g.s.Reload()
			conn, br, r := g.open("p.w", connectReq("example.com:443"))
			if r.status != 200 || !tunnelEcho(conn, br, strings.Repeat("a", 512)) {
				t.Fatalf("first exchange: %+v", r)
			}
			big := strings.Repeat("b", 1500)
			io.WriteString(conn, big)
			n, _ := io.Copy(io.Discard, io.LimitReader(br, int64(len(big))))
			if c.cut != (n < int64(len(big))) {
				t.Fatalf("echoed %d of %d", n, len(big))
			}
			if c.cut {
				if _, err := br.ReadByte(); err == nil {
					t.Fatal("tunnel open after the cap")
				}
				l := waitLog(t, g.env, 1)
				if len(l) != 1 || l[0]["code"] != CodeRate || l[0]["end"] != endBytes || l[0]["decision"] != "allow" {
					t.Fatalf("log %v", l)
				}
			}
		})
	}
}

// The tunnel caps with shortened durations, one case per upstream: no byte in either direction for the idle timeout
// closes the tunnel (end idle); bytes in one direction only keep it open past the idle timeout (control, end eof); the
// lifetime cap closes a busy tunnel (end lifetime), and the absolute form's response stream has the same bound.
func TestTunnelTimeouts(t *testing.T) {
	g := newGenericEnv(t)
	g.s.idleTimeout = 600 * time.Millisecond
	g.public("example.com")
	g.put("p.w", genericPolicy("p", "w", jail.NetAll, nil, "*", 600, 64, 1<<30))
	g.s.Reload()
	stream := func(c net.Conn) { // streams until the tunnel is cut
		for {
			time.Sleep(20 * time.Millisecond)
			if _, err := c.Write([]byte("stream")); err != nil {
				return
			}
		}
	}
	connect := connectReq("example.com:443")
	cases := []struct {
		name     string
		serve    func(net.Conn)
		raw      string
		min, max time.Duration // how long the client reads before the service ends the exchange
		bytes    int64         // exact bytes the client receives, or -1
		end      string
		lifetime time.Duration
	}{
		{"idle", func(c net.Conn) { io.Copy(c, c) }, connect, 500 * time.Millisecond, 3 * time.Second, 0, endIdle, time.Minute},
		{"one-way traffic is not idle", func(c net.Conn) { // one byte every 50 ms for 1.5 s, then close
			for i := 0; i < 30; i++ {
				time.Sleep(50 * time.Millisecond)
				c.Write([]byte{'t'})
			}
		}, connect, 0, 3 * time.Second, 30, endEOF, time.Minute},
		{"lifetime", stream, connect, 900 * time.Millisecond, 3 * time.Second, -1, endLifetime, time.Second},
		{"lifetime of a response stream", func(c net.Conn) {
			bufio.NewReader(c).ReadString('\n')
			io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
			stream(c)
		}, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", 900 * time.Millisecond, 3 * time.Second, -1, endLifetime, time.Second},
	}
	for i, c := range cases {
		g.setTarget(tcpServer(t, c.serve))
		g.s.tunnelLifetime = c.lifetime
		start := time.Now()
		conn, br, r := g.open("p.w", c.raw)
		n, _ := io.Copy(io.Discard, br)
		n += int64(len(r.body))
		d := time.Since(start)
		conn.Close()
		if r.status != 200 || d < c.min || d > c.max || c.bytes >= 0 && n != c.bytes {
			t.Errorf("%s: status %d, %d bytes after %v", c.name, r.status, n, d)
		}
		if l := waitLog(t, g.env, i+1); len(l) != i+1 || l[i]["end"] != c.end {
			t.Errorf("%s: log %v, want end %s", c.name, l[len(l)-1], c.end)
		}
	}
}

// Generic log lines: host, port, handler, method, decision, code, status, ip and end; a CONNECT has no path; a plain
// HTTP path is its first 256 bytes with the query stripped, plus the full path's length and sha256. Neither the query
// nor a header ever reaches the log. Denied lines name the code.
func TestGenericLogFields(t *testing.T) {
	g := newGenericEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer up.Close()
	g.public("example.com")
	g.put("p.w", allowlist("p", "w", []string{`example\.com`}, 443, 80))
	g.s.Reload()
	conn, br, _ := g.open("p.w", connectReq("example.com:443"))
	tunnelEcho(conn, br, "abc")
	conn.(*net.UnixConn).CloseWrite()
	io.Copy(io.Discard, br)
	// The tunnel's line is written after the client has seen its EOF: wait for each line, so that the order is fixed.
	waitLog(t, g.env, 1)
	g.open("p.w", connectReq("evil.example:443"))
	waitLog(t, g.env, 2)
	g.setTarget(strings.TrimPrefix(up.URL, "http://"))
	long := "/" + strings.Repeat("p", 300)
	g.open("p.w", "GET http://example.com"+long+"?token=WJ-CANARY-QUERY HTTP/1.1\r\nHost: example.com\r\nX-Canary: WJ-CANARY-HDR\r\n\r\n")
	l := waitLog(t, g.env, 3)
	if len(l) != 3 {
		t.Fatalf("lines %v", l)
	}
	c, d, h := l[0], l[1], l[2]
	if c["handler"] != handlerConnect || c["method"] != "CONNECT" || c["host"] != "example.com" || c["port"] != 443.0 ||
		c["decision"] != "allow" || c["code"] != "" || c["status"] != 200.0 || c["path"] != "" || c["ip"] != "127.0.0.1" ||
		c["end"] != endEOF || c["bytes_out"] != 3.0 || c["mode"] != jail.NetAllowlist {
		t.Errorf("CONNECT line %v", c)
	}
	if _, ok := c["path_len"]; ok {
		t.Errorf("CONNECT line has path fields: %v", c)
	}
	if d["decision"] != "deny" || d["code"] != CodeHost || d["status"] != 403.0 || d["host"] != "evil.example" || d["port"] != 443.0 {
		t.Errorf("denied line %v", d)
	}
	sum := sha256.Sum256([]byte(long))
	if h["handler"] != handlerHTTP || h["path"] != long[:256] || h["path_len"] != float64(len(long)) ||
		h["path_sha256"] != hex.EncodeToString(sum[:]) || h["status"] != 200.0 || h["host"] != "example.com" || h["port"] != 80.0 {
		t.Errorf("http line %v", h)
	}
	if strings.Contains(g.log.String(), "WJ-CANARY") || strings.Contains(g.log.String(), "token") {
		t.Fatal("a query or header reached the log")
	}
}

// A reload that changes a worker's policy closes its open tunnels, so a narrowed policy decides every exchange from
// then on; a change of mode replaces the listener (modules to allowlist drops the cache namespace). Control: a reload
// with the same policy keeps the tunnel.
func TestGenericReload(t *testing.T) {
	g := newGenericEnv(t)
	g.public("example.com")
	g.put("p.w", allowlist("p", "w", []string{`example\.com`}, 443))
	g.s.Reload()
	conn, br, _ := g.open("p.w", connectReq("example.com:443"))
	g.s.Reload()
	if !tunnelEcho(conn, br, "same policy") {
		t.Fatal("control: a reload with the same policy cut the tunnel")
	}
	g.put("p.w", allowlist("p", "w", []string{`other\.example`}, 443))
	g.s.Reload()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if tunnelEcho(conn, br, "narrowed") {
		t.Fatal("tunnel survived a narrowed policy")
	}
	if _, _, r := g.open("p.w", connectReq("example.com:443")); r.denied != CodeHost {
		t.Fatalf("narrowed policy: %+v", r)
	}

	g.put("p.m", defaultPolicy("p", "m"))
	g.s.Reload()
	g.open("p.m", "GET /gomod/golang.org/x/text/@v/v0.14.0.info HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
	g.put("p.m", allowlist("p", "m", []string{`example\.com`}, 443))
	g.s.Reload()
	if _, _, r := g.open("p.m", connectReq("example.com:443")); r.status != 200 {
		t.Fatalf("modules to allowlist: %+v", r)
	}
	if fi, err := os.Stat(filepath.Join(g.cache, "p.m")); err == nil {
		t.Fatalf("modules cache kept after the mode change: %v", fi)
	}
}

// max_conns covers tunnels: an open tunnel holds a slot, and a second connection is 403 rate until it closes.
func TestGenericMaxConns(t *testing.T) {
	g := newGenericEnv(t)
	g.public("example.com")
	g.put("p.w", genericPolicy("p", "w", jail.NetAllowlist, []string{`example\.com`}, []int{443}, 600, 1, 1<<30))
	g.s.Reload()
	conn, _, r := g.open("p.w", connectReq("example.com:443"))
	if r.status != 200 {
		t.Fatal(r)
	}
	if _, _, r := g.open("p.w", connectReq("example.com:443")); r.denied != CodeRate {
		t.Fatalf("second connection: %+v", r)
	}
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, r := g.open("p.w", connectReq("example.com:443")); r.status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not released")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
