// Package egress is the wj-egress service of worker-jail v2.1 (docs/design/v2/egress.md): one Unix-socket listener per
// worker whose policy has a network mode other than none, a strict HTTP/1.1 parser, and one handler family per mode.
// modules: the Go module proxy and sumdb grammar with the policy's module masks, fixed upstreams and a per-worker cache.
// allowlist, denylist and all (generic.go): CONNECT and absolute-URI http with host masks and ports, without TLS
// interception. Always on: a dial guard, in-band denials, JSON logs, rate limits, and fail-closed policy loading.
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/relux-works/worker-jail/jail"
)

// Timeouts (egress.md §3 and §5).
const (
	HeaderTimeout   = 5 * time.Second
	ConnectTimeout  = 10 * time.Second
	FirstByte       = 30 * time.Second
	exchangeTimeout = 10 * time.Minute
	writeTimeout    = 10 * time.Minute
	errorBodyCap    = 64 << 10
)

// SocketName is the socket in each worker's directory <sockroot>/<P>.<W>/.
const SocketName = "egress.sock"

// controlName is the status socket in the cache root. Its leading dot keeps it apart from every <P>.<W> namespace,
// and the cache volume is never mounted in a call.
const controlName = ".control.sock"

var policyFileRE = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,31})\.([a-z0-9][a-z0-9-]{0,31})\.json$`)
var keyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}\.[a-z0-9][a-z0-9-]{0,31}$`)

// Config names the service's three directories.
type Config struct {
	SockRoot  string    // one <P>.<W>/egress.sock per served worker; the volume wj-egress-sock
	PolicyDir string    // <P>.<W>.json, whole policy files; the volume wj-egress-policy, read-only
	CacheDir  string    // <P>.<W>/ cache namespaces and the control socket; the volume wj-egress-cache
	Log       io.Writer // JSON lines; default os.Stdout
}

// Service serves every worker's listener.
type Service struct {
	cfg Config
	log *logger
	now func() time.Time

	// Fixed in code. Tests replace them through the unexported fields only.
	proxyURL, sumURL string
	client           *http.Client
	objectCap        int64
	workerCap        int64
	headerTimeout    time.Duration
	idleTimeout      time.Duration // generic exchanges
	tunnelLifetime   time.Duration
	// dial is the generic handlers' dial guard (the modules client has its own over the same guard).
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	mu       sync.Mutex
	workers  map[string]*worker
	limiters map[string]*limiter
	ctl      net.Listener
	wg       sync.WaitGroup
}

// served is a loaded policy with its compiled masks: module masks for modules, the host rule for the generic modes.
type served struct {
	pol   jail.Policy
	masks masks
	rule  hostRule
}

type worker struct {
	key, project, name string
	cur                atomic.Pointer[served]
	ln                 net.Listener
	cache              *cache // modules only; nil for the generic modes
	lim                *limiter

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// New builds a service with the fixed upstreams and the dial guard over the system resolver. It touches nothing.
func New(cfg Config) (*Service, error) {
	for _, d := range []string{cfg.SockRoot, cfg.PolicyDir, cfg.CacheDir} {
		if !filepath.IsAbs(d) {
			return nil, fmt.Errorf("egress: directory %q is not absolute", d)
		}
	}
	if cfg.Log == nil {
		cfg.Log = os.Stdout
	}
	s := &Service{cfg: cfg, now: time.Now, proxyURL: "https://" + proxyHost, sumURL: "https://" + sumHost,
		objectCap: DefaultObjectCap, workerCap: DefaultWorkerCap, headerTimeout: HeaderTimeout,
		idleTimeout: IdleTimeout, tunnelLifetime: TunnelLifetime,
		workers: map[string]*worker{}, limiters: map[string]*limiter{}}
	s.log = &logger{w: cfg.Log, now: func() time.Time { return s.now() }}
	g := &guard{resolver: net.DefaultResolver, timeout: ConnectTimeout}
	s.client = newUpstreamClient(g.DialContext)
	s.dial = g.DialContext
	return s, nil
}

// newUpstreamClient is the only HTTP client of the service: no proxy from the environment, no compression,
// no redirects (a 3xx is returned as is and becomes 502 upstream), connect and first-byte timeouts.
func newUpstreamClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   ConnectTimeout,
		ResponseHeaderTimeout: FirstByte,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Serve loads the policies, opens the control socket and reloads on every value from hup until ctx ends.
func (s *Service) Serve(ctx context.Context, hup <-chan os.Signal) error {
	if err := s.listenControl(); err != nil {
		return err
	}
	s.Reload()
	for {
		select {
		case <-ctx.Done():
			s.Close()
			return nil
		case <-hup:
			s.Reload()
		}
	}
}

// Close closes the control socket and every listener and connection; caches stay.
func (s *Service) Close() {
	s.mu.Lock()
	if s.ctl != nil {
		s.ctl.Close()
	}
	for key, w := range s.workers {
		s.closeWorker(w, false)
		delete(s.workers, key)
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Reload re-reads every policy file and opens or closes listeners (egress.md §5, §6). A file that is unreadable,
// invalid, of another target or of an unknown version closes only its worker's listener. A worker whose file is gone,
// or whose valid policy is none, loses its listener and its cache namespace. A worker whose mode changes gets a new
// listener; one whose policy id changes keeps its listener, and its open connections (tunnels included) are closed,
// so that the new policy decides every exchange from then on.
func (s *Service) Reload() {
	want := map[string]*served{}
	keep := map[string]bool{} // workers whose cache survives: invalid files and an unreadable policy dir
	ents, err := os.ReadDir(s.cfg.PolicyDir)
	if err != nil {
		s.log.event(event{Event: "policy-dir-unreadable", File: s.cfg.PolicyDir, Error: err.Error()})
	}
	for _, e := range ents {
		m := policyFileRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		key := m[1] + "." + m[2]
		sv, err := s.loadFile(filepath.Join(s.cfg.PolicyDir, e.Name()), m[1], m[2])
		if err != nil {
			keep[key] = true
			s.log.event(event{Event: "policy-invalid", Project: m[1], Worker: m[2], File: e.Name(), Error: err.Error()})
			continue
		}
		if sv.pol.Network.Mode == jail.NetNone {
			continue
		}
		want[key] = sv
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, w := range s.workers {
		if sv, ok := want[key]; !ok || sv.pol.Network.Mode != w.cur.Load().pol.Network.Mode {
			s.closeWorker(w, !keep[key] && err == nil)
			delete(s.workers, key)
			s.log.event(event{Event: "listener-closed", Project: w.project, Worker: w.name})
		}
	}
	for key, sv := range want {
		if w := s.workers[key]; w != nil {
			if old := w.cur.Swap(sv); old.pol.ID() != sv.pol.ID() {
				w.closeConns()
				s.log.event(event{Event: "policy-loaded", Project: w.project, Worker: w.name, PolicyID: sv.pol.ID(), Mode: sv.pol.Network.Mode})
			}
			w.lim.setRate(*sv.pol.Network.Rate)
			continue
		}
		w, oerr := s.openWorker(key, sv)
		if oerr != nil {
			s.log.event(event{Event: "listener-failed", Project: sv.pol.Project, Worker: sv.pol.Worker, PolicyID: sv.pol.ID(), Error: oerr.Error()})
			continue
		}
		s.workers[key] = w
		s.log.event(event{Event: "policy-loaded", Project: w.project, Worker: w.name, PolicyID: sv.pol.ID(), Mode: sv.pol.Network.Mode})
	}
	if err == nil {
		s.sweep(keep)
	}
}

// sweep removes socket directories and cache namespaces that no served worker owns (left by a crash or a removal
// while the service was down), except the caches of workers whose file is invalid.
func (s *Service) sweep(keep map[string]bool) {
	for _, root := range []string{s.cfg.SockRoot, s.cfg.CacheDir} {
		ents, _ := os.ReadDir(root)
		for _, e := range ents {
			if !e.IsDir() || !keyRE.MatchString(e.Name()) || s.workers[e.Name()] != nil {
				continue
			}
			if root == s.cfg.SockRoot {
				os.Remove(filepath.Join(root, e.Name(), SocketName))
				os.Remove(filepath.Join(root, e.Name()))
			} else if !keep[e.Name()] {
				removeCache(filepath.Join(root, e.Name()))
			}
		}
	}
}

// loadFile reads one policy file and validates it with the jail's own validator, so the loaded id is the host's.
func (s *Service) loadFile(path, project, name string) (*served, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, jail.PolicyMaxBytes+1))
	if err != nil {
		return nil, err
	}
	pol, err := jail.ParsePolicy(data)
	if err != nil {
		return nil, err
	}
	if pol.Project != project || pol.Worker != name {
		return nil, fmt.Errorf("file names %s.%s, policy is for %s.%s", project, name, pol.Project, pol.Worker)
	}
	sv := &served{pol: pol}
	switch pol.Network.Mode {
	case jail.NetModules:
		if sv.masks, err = compileMasks(pol.Network.GoModules); err != nil {
			return nil, err
		}
	case jail.NetAllowlist, jail.NetDenylist, jail.NetAll:
		if sv.rule, err = compileHostRule(pol.Network); err != nil {
			return nil, err
		}
	}
	return sv, nil
}

func (s *Service) openWorker(key string, sv *served) (*worker, error) {
	dir := filepath.Join(s.cfg.SockRoot, key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, SocketName)
	if err := os.Remove(sock); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var c *cache
	if sv.pol.Network.Mode == jail.NetModules {
		var err error
		if c, err = openCache(filepath.Join(s.cfg.CacheDir, key), s.workerCap); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	lim := s.limiters[key]
	if lim == nil {
		lim = newLimiter(*sv.pol.Network.Rate, s.now())
		s.limiters[key] = lim
	} else {
		lim.setRate(*sv.pol.Network.Rate)
	}
	w := &worker{key: key, project: sv.pol.Project, name: sv.pol.Worker, ln: ln, cache: c, lim: lim, conns: map[net.Conn]struct{}{}}
	w.cur.Store(sv)
	s.wg.Add(1)
	go s.accept(w)
	return w, nil
}

// closeWorker closes the listener (which unlinks the socket) and every open connection, removes the socket
// directory, and with dropCache the worker's cache namespace. s.mu is held.
func (s *Service) closeWorker(w *worker, dropCache bool) {
	w.ln.Close()
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	w.closeConns()
	os.Remove(filepath.Join(s.cfg.SockRoot, w.key, SocketName))
	os.Remove(filepath.Join(s.cfg.SockRoot, w.key))
	if dropCache && w.cache != nil {
		removeCache(w.cache.dir)
	}
}

// closeConns closes every open connection of the worker.
func (w *worker) closeConns() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for c := range w.conns {
		c.Close()
	}
}

func (s *Service) accept(w *worker) {
	defer s.wg.Done()
	for {
		c, err := w.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if s.log.stalled() {
			c.Close()
			continue
		}
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			c.Close()
			return
		}
		w.conns[c] = struct{}{}
		w.mu.Unlock()
		s.wg.Add(1)
		go s.serveConn(w, c)
	}
}

// serveConn reads requests until a denial, an error, Connection: close or the header timeout. A panic closes the
// connection only; the listener stays.
func (s *Service) serveConn(w *worker, c net.Conn) {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.log.event(event{Event: "panic", Project: w.project, Worker: w.name, Error: fmt.Sprint(r)})
		}
		c.Close()
		w.mu.Lock()
		delete(w.conns, c)
		w.mu.Unlock()
	}()
	over := !w.lim.conn()
	if !over {
		defer w.lim.release()
	}
	br := bufio.NewReaderSize(c, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(s.headerTimeout))
		req, err := readRequest(br)
		start := s.now()
		sv := w.cur.Load()
		e := &Entry{Project: w.project, Worker: w.name, PolicyID: sv.pol.ID(), Mode: sv.pol.Network.Mode}
		if err != nil {
			switch {
			case errors.Is(err, errHeaderTooLarge):
				s.deny(c, e, CodeSize, "header block")
			case errors.Is(err, errMalformed):
				s.deny(c, e, CodeGrammar, err.Error())
			default:
				return // EOF or the header timeout: nothing to answer
			}
			s.finish(e, start)
			return
		}
		c.SetReadDeadline(time.Time{})
		keep := s.handle(w, sv, c, br, req, e, over)
		s.finish(e, start)
		if !keep || req.Close {
			return
		}
	}
}

func (s *Service) finish(e *Entry, start time.Time) {
	now := s.now()
	e.TS = now.UTC().Format(time.RFC3339Nano)
	e.DurMS = now.Sub(start).Milliseconds()
	s.log.write(e)
}

// handle answers one request and reports whether the connection may serve another.
func (s *Service) handle(w *worker, sv *served, c net.Conn, br *bufio.Reader, req *Request, e *Entry, overConns bool) bool {
	e.Method, e.BytesIn = req.Method, int64(req.HeadBytes)
	logTarget(e, req)
	now := s.now()
	if overConns || !w.lim.request(now) || !w.lim.spend(int64(req.HeadBytes), now) {
		return s.deny(c, e, CodeRate, "rate limit")
	}
	h, code := route(sv.pol.Network.Mode, req)
	e.Handler = h
	if code != "" {
		name := req.Method
		if code == CodeMode {
			name = req.Method + " " + req.Target
		}
		return s.deny(c, e, code, name)
	}
	if req.ContentLength > 0 {
		return s.deny(c, e, CodeGrammar, "request body")
	}
	switch h {
	case handlerConnect:
		return s.connect(w, sv, c, br, req, e)
	case handlerHTTP:
		return s.plainHTTP(w, sv, c, br, req, e)
	}
	p, err := parseModulesPath(req.Target)
	if err != nil {
		return s.deny(c, e, CodeGrammar, err.Error())
	}
	if !sv.masks.allows(p) {
		return s.deny(c, e, CodeModule, p.Module)
	}
	return s.modules(w, c, req, p, e)
}

// modules serves a request that passed the grammar and the masks: locally (sumdb supported), from the worker's
// cache (immutable objects, GET), or from the fixed upstream.
func (s *Service) modules(w *worker, c net.Conn, req *Request, p modPath, e *Entry) bool {
	head := req.Method == "HEAD"
	if p.Kind == kindSupported {
		return s.respond(c, e, 200, nil, 0, head)
	}
	e.Host, e.Port = p.Upstream, 443
	key := p.Upstream + p.Rest
	if p.Immutable() && !head {
		e.Cache = "miss"
		if f, size := w.cache.open(key); f != nil {
			defer f.Close()
			e.Cache = "hit"
			if !w.lim.spend(size, s.now()) {
				return s.deny(c, e, CodeRate, "bytes per day")
			}
			return s.respond(c, e, 200, f, size, false)
		}
	}
	base := s.proxyURL
	if p.Upstream == sumHost {
		base = s.sumURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if a, ok := i.Conn.RemoteAddr().(*net.TCPAddr); ok {
			e.IP = a.IP.String()
		}
	}})
	hreq, err := http.NewRequestWithContext(ctx, req.Method, base+p.Rest, nil)
	if err != nil {
		return s.deny(c, e, CodeUpstream, p.Upstream)
	}
	hreq.Header = http.Header{"User-Agent": {"wj-egress"}} // no client header is forwarded
	resp, err := s.client.Do(hreq)
	if err != nil {
		if errors.Is(err, errGuard) {
			return s.deny(c, e, CodeGuard, p.Upstream)
		}
		return s.deny(c, e, CodeUpstream, p.Upstream)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 404, 410:
		body, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyCap))
		if err != nil {
			return s.deny(c, e, CodeUpstream, p.Upstream)
		}
		if head {
			body = nil
		}
		if !w.lim.spend(int64(len(body)), s.now()) {
			return s.deny(c, e, CodeRate, "bytes per day")
		}
		return s.respond(c, e, resp.StatusCode, strings.NewReader(string(body)), int64(len(body)), head)
	default:
		// Redirects are not followed (E7), and no other status is passed through.
		return s.deny(c, e, CodeUpstream, fmt.Sprintf("%s answered %d", p.Upstream, resp.StatusCode))
	}
	if resp.ContentLength > s.objectCap {
		return s.deny(c, e, CodeSize, p.Upstream+p.Rest)
	}
	if head {
		return s.respond(c, e, 200, nil, max(resp.ContentLength, 0), true)
	}
	tmp, err := w.cache.temp()
	if err != nil {
		return s.deny(c, e, CodeUpstream, "spool")
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, s.objectCap+1))
	switch {
	case n > s.objectCap:
		return s.deny(c, e, CodeSize, p.Upstream+p.Rest)
	case err != nil, resp.ContentLength >= 0 && n != resp.ContentLength:
		return s.deny(c, e, CodeUpstream, p.Upstream)
	}
	if !w.lim.spend(n, s.now()) {
		return s.deny(c, e, CodeRate, "bytes per day")
	}
	if p.Immutable() {
		w.cache.store(key, tmp.Name(), n)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return s.deny(c, e, CodeUpstream, "spool")
	}
	return s.respond(c, e, 200, tmp, n, false)
}

// respond writes a response with n bytes of body (none for HEAD) and reports whether the connection may continue.
func (s *Service) respond(c net.Conn, e *Entry, status int, body io.Reader, n int64, head bool) bool {
	e.Decision, e.Status = "allow", status
	c.SetWriteDeadline(time.Now().Add(writeTimeout))
	ct := "application/octet-stream"
	if status != 200 {
		ct = "text/plain; charset=utf-8"
	}
	hdr := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", status, http.StatusText(status), ct, n)
	if _, err := io.WriteString(c, hdr); err != nil {
		return false
	}
	if head || body == nil || n == 0 {
		return true
	}
	written, err := io.CopyN(c, body, n)
	e.BytesOut = written
	return err == nil
}

// deny writes an in-band denial (egress.md §5): 403 (502 for upstream), X-Worker-Jail-Denied and a one-line body
// naming what was denied, never the policy. The connection is closed after it.
func (s *Service) deny(c net.Conn, e *Entry, code, name string) bool {
	status, decision := 403, "deny"
	if code == CodeUpstream {
		status, decision = 502, "error"
	}
	body := "worker-jail egress: denied (" + code + "): " + printable(name, 200) + "\n"
	e.Decision, e.Code, e.Status, e.BytesOut = decision, code, status, int64(len(body))
	c.SetWriteDeadline(time.Now().Add(HeaderTimeout))
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nX-Worker-Jail-Denied: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), code, len(body), body)
	return false
}

// printable keeps visible ASCII and spaces, replaces anything else with '?', and caps the length.
func printable(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit]
	}
	b := []byte(s)
	for i, c := range b {
		if c < ' ' || c >= 0x7f {
			b[i] = '?'
		}
	}
	return string(b)
}

// logPath is the request target as logged: query stripped, at most 1 KiB (the grammar's own bound).
func logPath(target string) string {
	target, _, _ = strings.Cut(target, "?")
	if len(target) > maxPathBytes {
		return target[:256] + "...(" + strconv.Itoa(len(target)) + " bytes)"
	}
	return target
}

// Loaded returns the id of the policy the listener of key (P.W) serves, or "".
func (s *Service) Loaded(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w := s.workers[key]; w != nil {
		return w.cur.Load().pol.ID()
	}
	return ""
}

func (s *Service) listenControl() error {
	if err := os.MkdirAll(s.cfg.CacheDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(s.cfg.CacheDir, controlName)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	s.mu.Lock()
	s.ctl = ln
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			c.SetDeadline(time.Now().Add(HeaderTimeout))
			line, _ := bufio.NewReaderSize(c, 128).ReadString('\n')
			id := "none"
			if key := strings.TrimSpace(line); keyRE.MatchString(key) {
				if l := s.Loaded(key); l != "" {
					id = l
				}
			}
			io.WriteString(c, id+"\n")
			c.Close()
		}
	}()
	return nil
}

// ErrNotLoaded is Status's answer when the service serves no policy for the worker.
var ErrNotLoaded = errors.New("no policy loaded")

// Status asks the running service, through the control socket in cacheDir, which policy id it serves for key (P.W).
func Status(cacheDir, key string) (string, error) {
	if !keyRE.MatchString(key) {
		return "", fmt.Errorf("egress: invalid worker %q (want P.W)", key)
	}
	c, err := net.DialTimeout("unix", filepath.Join(cacheDir, controlName), HeaderTimeout)
	if err != nil {
		return "", fmt.Errorf("egress: service unreachable: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(HeaderTimeout))
	if _, err := io.WriteString(c, key+"\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReaderSize(c, 128).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("egress: status: %w", err)
	}
	switch id := strings.TrimSpace(line); id {
	case "none":
		return "", ErrNotLoaded
	default:
		return id, nil
	}
}
