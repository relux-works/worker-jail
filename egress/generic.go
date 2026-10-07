package egress

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/relux-works/remote-workplace/workplace"
)

// Limits of a generic exchange (egress.md §4): a tunnel or a response stream ends after IdleTimeout without a byte in
// either direction, and at the latest after TunnelLifetime. Its bytes count against the worker's bytes_per_day as they
// pass, so the per-connection cap is whatever the worker has left today.
const (
	IdleTimeout    = 60 * time.Second
	TunnelLifetime = time.Hour
	logPathBytes   = 256
	maxHostBytes   = 253
)

// Why a generic exchange ended (the log's end field).
const (
	endEOF      = "eof"
	endIdle     = "idle"
	endLifetime = "lifetime"
	endBytes    = "bytes"
	endClient   = "client" // plain HTTP: the client closed or sent more while the response streamed
	endError    = "error"
)

// hostRule is the generic part of a served policy: the mode, the anchored host masks and the ports.
type hostRule struct {
	mode  string
	hosts masks
	ports workplace.PortSet
}

func compileHostRule(n workplace.NetworkPolicy) (hostRule, error) {
	r := hostRule{mode: n.Mode}
	if n.Ports != nil {
		r.ports = *n.Ports
	}
	var err error
	r.hosts, err = compileMasks(n.Hosts)
	return r, err
}

// check applies the mode to a canonical host and a port and returns "" or the denial code (host before port):
// allowlist needs a matching mask, denylist no matching mask (any match denies), and every mode needs an allowed port.
// Ports are never implied: 80 and 443 pass only when listed, or under ["*"] where the policy allows it.
func (r hostRule) check(host string, port int) string {
	matched := slices.ContainsFunc(r.hosts, func(re *regexp.Regexp) bool { return re.MatchString(host) })
	switch r.mode {
	case workplace.NetAllowlist:
		if !matched {
			return CodeHost
		}
	case workplace.NetDenylist:
		if matched {
			return CodeHost
		}
	case workplace.NetAll:
	default:
		return CodeMode
	}
	if !r.ports.Any && !slices.Contains(r.ports.Ports, port) {
		return CodePort
	}
	return ""
}

// authError is a refused authority: grammar for its syntax, host for a host that has no canonical form.
type authError struct{ code, why string }

func (e *authError) Error() string { return e.why }

// parseAuthority parses host[:port] as in a CONNECT target or an http URI. defPort is the port when none is given;
// 0 makes the port required (CONNECT). It returns the canonical host (canonicalHost) and the port.
// Refused as grammar: userinfo, a path, query or fragment, an unbracketed IPv6 address, an empty or non-canonical port
// (leading zeros, outside 1..65535).
func parseAuthority(a string, defPort int) (string, int, error) {
	if a == "" {
		return "", 0, &authError{CodeGrammar, "empty authority"}
	}
	if strings.Contains(a, "@") {
		return "", 0, &authError{CodeGrammar, "userinfo in the authority"}
	}
	if strings.ContainsAny(a, "/?#\\") {
		return "", 0, &authError{CodeGrammar, "authority with a path, query or fragment"}
	}
	rawHost, rawPort, hasPort := a, "", false
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return "", 0, &authError{CodeGrammar, "unclosed ["}
		}
		rawHost = a[:end+1]
		if rest := a[end+1:]; rest != "" {
			if rest[0] != ':' {
				return "", 0, &authError{CodeGrammar, "junk after ]"}
			}
			rawPort, hasPort = rest[1:], true
		}
	} else {
		if strings.Count(a, ":") > 1 {
			return "", 0, &authError{CodeGrammar, "IPv6 address without brackets"}
		}
		rawHost, rawPort, hasPort = strings.Cut(a, ":")
	}
	port := defPort
	switch {
	case hasPort:
		if port = parsePort(rawPort); port == 0 {
			return "", 0, &authError{CodeGrammar, "port"}
		}
	case defPort == 0:
		return "", 0, &authError{CodeGrammar, "port required"}
	}
	host, err := canonicalHost(rawHost)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// parsePort returns a canonical decimal port in 1..65535, or 0.
func parsePort(s string) int {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return 0
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
	}
	n, _ := strconv.Atoi(s)
	if n > 65535 {
		return 0
	}
	return n
}

// canonicalHost returns the form host masks match (policy.md §2): percent-escapes decoded, lowercase, no trailing dot,
// IPv6 without brackets in its canonical text, IPv4-mapped IPv6 as IPv4, IPv4 as a dotted quad. A hostname is LDH
// labels of 1..63 bytes, at most 253 bytes, whose last label is not numeric (so 127.1, 2130706433 and 0177.0.0.1 are
// refused, never resolved). Non-ASCII hosts (IDNs) are refused: the standard library has no IDNA (UTS #46) mapping, so
// the service cannot canonicalise them; a client sends the punycode form (xn--...), which is accepted.
func canonicalHost(raw string) (string, error) {
	h, err := url.PathUnescape(raw)
	if err != nil {
		return "", &authError{CodeGrammar, "host escaping"}
	}
	if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return "", &authError{CodeGrammar, "unclosed ["}
		}
		ip, err := netip.ParseAddr(h[1 : len(h)-1])
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return "", &authError{CodeHost, "not an IPv6 address"}
		}
		return ip.Unmap().String(), nil
	}
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			return "", &authError{CodeHost, "non-ASCII host (an IDN): send its punycode (xn--) form"}
		}
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > maxHostBytes {
		return "", &authError{CodeHost, "host length"}
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Is4() {
			return ip.String(), nil
		}
		return "", &authError{CodeHost, "IPv6 address without brackets"}
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", &authError{CodeHost, "host label"}
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", &authError{CodeHost, "host character"}
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", &authError{CodeHost, "numeric host that is not a dotted-quad IPv4 address"}
	}
	return h, nil
}

// hostPort joins a canonical host and a port, bracketing IPv6.
func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// parseAbsolute splits an absolute-form target into its authority and the origin form (path and query; "/" when the
// URI has no path). Only http:// is proxied in this form; https goes through CONNECT. A fragment is refused.
func parseAbsolute(target string) (authority, origin string, err error) {
	scheme, rest, ok := strings.Cut(target, "://")
	if !ok || !strings.EqualFold(scheme, "http") {
		return "", "", &authError{CodeGrammar, "only http:// is proxied in absolute form (use CONNECT for https)"}
	}
	if strings.Contains(rest, "#") {
		return "", "", &authError{CodeGrammar, "fragment"}
	}
	i := strings.IndexAny(rest, "/?")
	switch {
	case i < 0:
		return rest, "/", nil
	case rest[i] == '?':
		return rest[:i], "/" + rest[i:], nil
	}
	return rest[:i], rest[i:], nil
}

// setHTTPPath logs a plain-HTTP path (egress.md §5): query stripped, its first 256 bytes, and the length and sha256 of
// the whole stripped path.
func setHTTPPath(e *Entry, origin string) {
	p, _, _ := strings.Cut(origin, "?")
	sum := sha256.Sum256([]byte(p))
	e.PathLen, e.PathSHA256 = len(p), hex.EncodeToString(sum[:])
	if len(p) > logPathBytes {
		p = p[:logPathBytes]
	}
	e.Path = p
}

// logTarget fills the entry's path fields for any request form, before routing: nothing for CONNECT (host and port are
// logged), the plain-HTTP form for absolute URIs, the modules form otherwise.
func logTarget(e *Entry, req *Request) {
	switch {
	case req.Method == "CONNECT":
	case absoluteForm(req.Target):
		_, origin, err := parseAbsolute(req.Target)
		if err != nil {
			origin = req.Target
		}
		setHTTPPath(e, origin)
	default:
		e.Path = logPath(req.Target)
	}
}

// denyAuth denies a refused authority with its code.
func (s *Service) denyAuth(c net.Conn, e *Entry, err error, name string) bool {
	code := CodeGrammar
	var ae *authError
	if errors.As(err, &ae) {
		code = ae.code
		name += ": " + ae.why
	}
	return s.deny(c, e, code, name)
}

// dialUpstream dials host:port through the dial guard (§5) and logs the peer address.
func (s *Service) dialUpstream(host string, port int, e *Entry) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ConnectTimeout)
	defer cancel()
	up, err := s.dial(ctx, "tcp", hostPort(host, port))
	if err != nil {
		return nil, err
	}
	if a, ok := up.RemoteAddr().(*net.TCPAddr); ok {
		e.IP = a.IP.String()
	}
	return up, nil
}

func (s *Service) denyDial(c net.Conn, e *Entry, err error, name string) bool {
	if errors.Is(err, errGuard) {
		return s.deny(c, e, CodeGuard, name)
	}
	return s.deny(c, e, CodeUpstream, name)
}

// connect serves CONNECT host:port on a generic listener: canonicalise and check the authority, dial it through the
// guard, answer 200 and splice bytes in both directions until either side ends, the idle timeout, the lifetime cap or
// the worker's daily bytes. The tunnel content is invisible: there is no TLS interception. The connection ends with it.
func (s *Service) connect(w *worker, sv *served, c net.Conn, br *bufio.Reader, req *Request, e *Entry) bool {
	host, port, err := parseAuthority(req.Target, 0)
	if err != nil {
		e.Host = printable(req.Target, logPathBytes)
		return s.denyAuth(c, e, err, req.Target)
	}
	e.Host, e.Port = host, port
	if code := sv.rule.check(host, port); code != "" {
		return s.deny(c, e, code, hostPort(host, port))
	}
	up, err := s.dialUpstream(host, port, e)
	if err != nil {
		return s.denyDial(c, e, err, hostPort(host, port))
	}
	defer up.Close()
	c.SetWriteDeadline(time.Now().Add(HeaderTimeout))
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		e.Decision, e.End = "error", endError
		return false
	}
	e.Decision, e.Status = "allow", 200
	t := s.newTunnel(w.lim)
	in, out := t.splice(c, br, up)
	e.BytesIn += in
	e.BytesOut, e.End = out, t.end()
	if t.capped.Load() {
		e.Code = CodeRate
	}
	return false
}

// hopByHop are the request headers never forwarded (RFC 9110 §7.6.1, plus the framing headers: no body is forwarded,
// and Host is set from the checked authority). Every Proxy-* header and every header named in Connection go too.
var hopByHop = map[string]bool{"connection": true, "keep-alive": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true, "host": true, "content-length": true}

// forwardHead is the request head sent upstream: origin form, Host from the checked authority, the client's headers
// minus hop-by-hop and Proxy-* ones, and Connection: close (one exchange per connection).
func forwardHead(req *Request, origin, host string, port int) string {
	named := map[string]bool{}
	for _, f := range req.Header {
		if strings.EqualFold(f.Name, "connection") {
			for _, t := range strings.Split(f.Value, ",") {
				named[strings.ToLower(strings.TrimSpace(t))] = true
			}
		}
	}
	hh := host
	if strings.Contains(host, ":") {
		hh = "[" + host + "]"
	}
	if port != 80 {
		hh += ":" + strconv.Itoa(port)
	}
	var b strings.Builder
	b.WriteString(req.Method + " " + origin + " HTTP/1.1\r\nHost: " + hh + "\r\n")
	for _, f := range req.Header {
		n := strings.ToLower(f.Name)
		if hopByHop[n] || named[n] || strings.HasPrefix(n, "proxy-") {
			continue
		}
		b.WriteString(f.Name + ": " + f.Value + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	return b.String()
}

var statusLineRE = regexp.MustCompile(`^HTTP/1\.[01] ([1-9][0-9]{2})(?: [^\r\n]*)?\r?\n$`)

// plainHTTP serves an absolute-URI GET or HEAD on a generic listener: the same checks as CONNECT on the URI's
// authority (port 80 when the URI names none), a Host header that names the same authority, then one exchange in
// origin form. The response passes back as received, redirects included (the client asks again and is checked again).
// The connection ends with the response.
func (s *Service) plainHTTP(w *worker, sv *served, c net.Conn, br *bufio.Reader, req *Request, e *Entry) bool {
	authority, origin, err := parseAbsolute(req.Target)
	if err != nil {
		return s.denyAuth(c, e, err, req.Method+" "+req.Target)
	}
	host, port, err := parseAuthority(authority, 80)
	if err != nil {
		e.Host = printable(authority, logPathBytes)
		return s.denyAuth(c, e, err, authority)
	}
	e.Host, e.Port = host, port
	if hh, hp, err := parseAuthority(req.Host, 80); err != nil || hh != host || hp != port {
		return s.deny(c, e, CodeHost, "Host header "+req.Host+" does not name "+authority)
	}
	if code := sv.rule.check(host, port); code != "" {
		return s.deny(c, e, code, hostPort(host, port))
	}
	up, err := s.dialUpstream(host, port, e)
	if err != nil {
		return s.denyDial(c, e, err, hostPort(host, port))
	}
	defer up.Close()
	up.SetWriteDeadline(time.Now().Add(ConnectTimeout))
	if _, err := io.WriteString(up, forwardHead(req, origin, host, port)); err != nil {
		return s.deny(c, e, CodeUpstream, hostPort(host, port))
	}
	ubr := bufio.NewReaderSize(up, 4096)
	up.SetReadDeadline(time.Now().Add(FirstByte))
	line, err := ubr.ReadSlice('\n')
	m := statusLineRE.FindSubmatch(line)
	if err != nil || m == nil {
		return s.deny(c, e, CodeUpstream, hostPort(host, port))
	}
	if !w.lim.spend(int64(len(line)), s.now()) {
		return s.deny(c, e, CodeRate, "bytes per day")
	}
	e.Decision, e.Status = "allow", atoi(string(m[1]))
	c.SetWriteDeadline(time.Now().Add(HeaderTimeout))
	if _, err := c.Write(line); err != nil {
		e.End = endError
		return false
	}
	t := s.newTunnel(w.lim)
	// The client may only wait or close: any byte from it (a body, a pipelined request) or its EOF ends the exchange,
	// so nothing but the checked head ever reaches the upstream.
	done := make(chan struct{})
	c.SetReadDeadline(time.Time{})
	go func() {
		defer close(done)
		var b [1]byte
		br.Read(b[:])
		t.stop(endClient)
		up.Close()
	}()
	var out int64
	r := t.copy(c, up, ubr, &out)
	t.stop(r)
	c.SetReadDeadline(time.Now())
	<-done
	e.BytesOut, e.End = int64(len(line))+out, t.end()
	if t.capped.Load() {
		e.Code = CodeRate
	}
	return false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// tunnel bounds one generic exchange: the idle timeout across both directions, the lifetime cap, and the worker's
// daily bytes, spent as they pass. Deadlines use the wall clock; the byte budget uses the service's clock. The logged
// end is the first thing that ended (a direction's EOF included); capped records that the byte budget cut it.
type tunnel struct {
	lim      *limiter
	now      func() time.Time
	idle     time.Duration
	deadline time.Time // start + lifetime
	last     atomic.Int64
	capped   atomic.Bool

	once   sync.Once
	reason string
}

func (s *Service) newTunnel(lim *limiter) *tunnel {
	start := time.Now()
	t := &tunnel{lim: lim, now: s.now, idle: s.idleTimeout, deadline: start.Add(s.tunnelLifetime)}
	t.last.Store(start.UnixNano())
	return t
}

// stop records the first reason the exchange ended.
func (t *tunnel) stop(reason string) { t.once.Do(func() { t.reason = reason }) }

func (t *tunnel) end() string {
	t.stop(endEOF)
	return t.reason
}

// until is the deadline for the next read or write: idle after the last byte, but never past the lifetime.
func (t *tunnel) until(from time.Time) time.Time {
	if d := from.Add(t.idle); d.Before(t.deadline) {
		return d
	}
	return t.deadline
}

// copy forwards src (read through r, which may hold buffered bytes) to dst and adds what it forwarded to n. It returns
// why it stopped: eof, idle (no byte in either direction for the idle timeout), lifetime, bytes (the day's budget is
// spent; the chunk that did not fit is not forwarded) or error.
func (t *tunnel) copy(dst, src net.Conn, r io.Reader, n *int64) string {
	buf := make([]byte, 32<<10)
	for {
		src.SetReadDeadline(t.until(time.Unix(0, t.last.Load())))
		k, err := r.Read(buf)
		if k > 0 {
			if !t.lim.spend(int64(k), t.now()) {
				t.capped.Store(true)
				return endBytes
			}
			now := time.Now()
			t.last.Store(now.UnixNano())
			dst.SetWriteDeadline(t.until(now))
			if _, werr := dst.Write(buf[:k]); werr != nil {
				return t.why(werr)
			}
			*n += int64(k)
		}
		if err != nil {
			// A read that timed out while the other direction was busy is not idle.
			if errors.Is(err, os.ErrDeadlineExceeded) && time.Now().Before(t.deadline) &&
				time.Since(time.Unix(0, t.last.Load())) < t.idle {
				continue
			}
			return t.why(err)
		}
	}
}

func (t *tunnel) why(err error) string {
	switch {
	case errors.Is(err, io.EOF):
		return endEOF
	case errors.Is(err, os.ErrDeadlineExceeded) && !time.Now().Before(t.deadline):
		return endLifetime
	case errors.Is(err, os.ErrDeadlineExceeded):
		return endIdle
	}
	return endError
}

// splice runs both directions of a CONNECT tunnel. An EOF half-closes the other side; any other end closes both.
func (t *tunnel) splice(c net.Conn, cr io.Reader, up net.Conn) (in, out int64) {
	finish := func(r string, to net.Conn) {
		t.stop(r)
		if r == endEOF {
			closeWrite(to)
			return
		}
		c.Close()
		up.Close()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		finish(t.copy(up, c, cr, &in), up)
	}()
	finish(t.copy(c, up, up, &out), c)
	<-done
	return in, out
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
