package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Every forbidden range of egress.md §5 is refused, including its IPv4-mapped, NAT64 and 6to4 forms; public
// addresses in each family are the controls.
func TestForbidden(t *testing.T) {
	forbidden := []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.254", "127.0.0.1", "127.8.8.8",
		"169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.168.0.1", "192.168.5.2", "198.18.0.1", "198.19.255.255",
		"224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", // IPv4-mapped
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c0a8:502", // NAT64 of 127.0.0.1, metadata, the lima gateway
		"2002:7f00:1::1", "2002:a9fe:a9fe::", "2002:c0a8:0502::1", // 6to4 of the same
		"::127.0.0.1", "::8.8.8.8", // IPv4-compatible: refused whole
		"64:ff9b:1::1", "2001:0:4136:e378::1", // local-use NAT64, Teredo
		"fe80::1%eth0", // zoned
	}
	for _, s := range forbidden {
		if why := Forbidden(netip.MustParseAddr(s)); why == "" {
			t.Errorf("%s allowed", s)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "142.250.74.110", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0",
		"192.0.1.1", "192.169.0.1", "198.17.255.255", "198.20.0.0", "223.255.255.255",
		"2001:4860:4860::8888", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1"}
	for _, s := range public {
		if why := Forbidden(netip.MustParseAddr(s)); why != "" {
			t.Errorf("control %s refused: %s", s, why)
		}
	}
	if Forbidden(netip.Addr{}) == "" {
		t.Error("the zero address allowed")
	}
}

// fakeResolver answers each lookup of a name with the next entry of its list (the last one repeats).
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	lookups int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	a := f.answers[host]
	if len(a) == 0 {
		return nil, errors.New("no such host")
	}
	ans := a[0]
	if len(a) > 1 {
		f.answers[host] = a[1:]
	}
	return ans, nil
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// errDialed stands in for a connection: the guard reached the dial with a checked address.
var errDialed = errors.New("dialed")

// The guard with a fake resolver (E4): an answer in each forbidden range, a mixed answer, a mapped IPv6 answer and an IP
// literal are refused before any dial; a rebinding resolver is asked once and the checked address is what gets dialed.
// Control: the same name with a public address dials it.
func TestGuardDial(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		addr   string
		answer []netip.Addr
		want   error  // errGuard, or errDialed when the dial was reached
		dialed string // the address dialed
	}{
		{"loopback", "proxy.golang.org:443", addrs("127.0.0.1"), errGuard, ""},
		{"metadata", "proxy.golang.org:443", addrs("169.254.169.254"), errGuard, ""},
		{"rfc1918 10", "proxy.golang.org:443", addrs("10.1.2.3"), errGuard, ""},
		{"rfc1918 172", "proxy.golang.org:443", addrs("172.20.0.1"), errGuard, ""},
		{"lima gateway", "proxy.golang.org:443", addrs("192.168.5.2"), errGuard, ""},
		{"cgnat", "proxy.golang.org:443", addrs("100.100.100.100"), errGuard, ""},
		{"benchmark", "proxy.golang.org:443", addrs("198.18.0.1"), errGuard, ""},
		{"ietf", "proxy.golang.org:443", addrs("192.0.0.170"), errGuard, ""},
		{"this network", "proxy.golang.org:443", addrs("0.0.0.0"), errGuard, ""},
		{"multicast", "proxy.golang.org:443", addrs("224.0.0.251"), errGuard, ""},
		{"reserved", "proxy.golang.org:443", addrs("240.0.0.1"), errGuard, ""},
		{"v6 loopback", "proxy.golang.org:443", addrs("::1"), errGuard, ""},
		{"ula", "proxy.golang.org:443", addrs("fd00::1"), errGuard, ""},
		{"link-local v6", "proxy.golang.org:443", addrs("fe80::1"), errGuard, ""},
		{"multicast v6", "proxy.golang.org:443", addrs("ff02::fb"), errGuard, ""},
		{"mixed answer: public first", "proxy.golang.org:443", addrs("142.250.74.110", "10.0.0.1"), errGuard, ""},
		{"mixed answer: private first", "proxy.golang.org:443", addrs("192.168.1.1", "142.250.74.110"), errGuard, ""},
		{"mapped v6 of loopback", "proxy.golang.org:443", addrs("::ffff:127.0.0.1"), errGuard, ""},
		{"nat64 of metadata", "proxy.golang.org:443", addrs("64:ff9b::a9fe:a9fe"), errGuard, ""},
		{"6to4 of the lima gateway", "proxy.golang.org:443", addrs("2002:c0a8:502::1"), errGuard, ""},
		{"ip literal", "127.0.0.1:443", nil, errGuard, ""},
		{"ip literal v6", "[::1]:443", nil, errGuard, ""},
		{"control: public v4", "proxy.golang.org:443", addrs("142.250.74.110"), errDialed, "142.250.74.110:443"},
		{"control: public v6", "proxy.golang.org:443", addrs("2607:f8b0:4004:c1b::8d"), errDialed, "[2607:f8b0:4004:c1b::8d]:443"},
		{"control: mapped public is dialed as v4", "proxy.golang.org:443", addrs("::ffff:142.250.74.110"), errDialed, "142.250.74.110:443"},
	}
	for _, c := range cases {
		res := &fakeResolver{answers: map[string][][]netip.Addr{"proxy.golang.org": {c.answer}}}
		var dialed string
		g := &guard{resolver: res, timeout: time.Second, dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return nil, errDialed
		}}
		_, err := g.DialContext(ctx, "tcp", c.addr)
		if !errors.Is(err, c.want) || dialed != c.dialed {
			t.Errorf("%s: err %v dialed %q, want %v %q", c.name, err, dialed, c.want, c.dialed)
		}
	}

	// Rebinding: the first answer is public, every later one loopback. The guard asks once and dials the checked IP.
	res := &fakeResolver{answers: map[string][][]netip.Addr{"proxy.golang.org": {addrs("142.250.74.110"), addrs("127.0.0.1")}}}
	var dialed []string
	g := &guard{resolver: res, timeout: time.Second, dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errDialed
	}}
	if _, err := g.DialContext(ctx, "tcp", "proxy.golang.org:443"); !errors.Is(err, errDialed) || res.lookups != 1 ||
		len(dialed) != 1 || dialed[0] != "142.250.74.110:443" {
		t.Fatalf("rebinding: err %v lookups %d dialed %v", err, res.lookups, dialed)
	}
	// The next connection resolves again and now meets the rebound answer: refused.
	if _, err := g.DialContext(ctx, "tcp", "proxy.golang.org:443"); !errors.Is(err, errGuard) || len(dialed) != 1 {
		t.Fatalf("rebound answer: err %v dialed %v", err, dialed)
	}
	// A resolver failure is an upstream error, not a guard denial; a UDP dial is refused.
	if _, err := g.DialContext(ctx, "tcp", "unknown.example:443"); err == nil || errors.Is(err, errGuard) {
		t.Fatalf("resolver failure: %v", err)
	}
	if _, err := g.DialContext(ctx, "udp", "proxy.golang.org:53"); !errors.Is(err, errGuard) {
		t.Fatalf("udp: %v", err)
	}
}

// The control hook re-checks the peer the socket connects to, so a dialer that was handed a forbidden address
// (by a bug above it) still refuses; a real dial through the default dialer to loopback fails in the hook.
func TestGuardControlHook(t *testing.T) {
	for _, a := range []string{"127.0.0.1:443", "[::1]:443", "[::ffff:10.0.0.1]:443", "169.254.169.254:80", "garbage"} {
		if err := controlCheck("tcp", a, nil); !errors.Is(err, errGuard) {
			t.Errorf("%s: %v", a, err)
		}
	}
	if err := controlCheck("tcp", "142.250.74.110:443", nil); err != nil {
		t.Errorf("control: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := net.Dialer{Timeout: time.Second, Control: controlCheck}
	if _, err := d.Dial("tcp", ln.Addr().String()); !errors.Is(err, errGuard) {
		t.Fatalf("dial to loopback through the hook: %v", err)
	}
	// Control: the same dial without the hook connects.
	c, err := (&net.Dialer{Timeout: time.Second}).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	c.Close()
}
