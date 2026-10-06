package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Resolver resolves names in the service; *net.Resolver implements it. Tests fake it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// errGuard marks a destination the dial guard refuses (403 guard); every other dial error is 502 upstream.
var errGuard = errors.New("dial guard")

type guardError struct{ why string }

func (e *guardError) Error() string { return errGuard.Error() + ": " + e.why }
func (e *guardError) Unwrap() error { return errGuard }

// forbiddenPrefixes are the ranges no field can open (egress.md §5).
var forbiddenPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
		// Stricter than the list: IPv4-compatible addresses (::/96, deprecated), the local-use NAT64 prefix
		// (RFC 8215) and Teredo embed IPv4 addresses that are not worth unwrapping; they are refused whole.
		"::/96", "64:ff9b:1::/48", "2001::/32",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// Forbidden reports why ip may not be dialled, or "". IPv4-mapped, NAT64 (64:ff9b::/96) and
// 6to4 (2002::/16) addresses are unwrapped and their IPv4 address is checked too. A zoned address is refused.
func Forbidden(ip netip.Addr) string {
	if !ip.IsValid() {
		return "invalid address"
	}
	if ip.Zone() != "" {
		return "zoned address"
	}
	for _, p := range forbiddenPrefixes {
		if p.Contains(ip) {
			return p.String()
		}
	}
	if !ip.Is6() || ip.Is4In6() {
		if ip.Is4In6() {
			return Forbidden(ip.Unmap())
		}
		return ""
	}
	b := ip.As16()
	var inner netip.Addr
	switch {
	case nat64.Contains(ip):
		inner = netip.AddrFrom4([4]byte(b[12:16]))
	case sixToFour.Contains(ip):
		inner = netip.AddrFrom4([4]byte(b[2:6]))
	default:
		return ""
	}
	if why := Forbidden(inner); why != "" {
		return why + " (embedded in " + ip.String() + ")"
	}
	return ""
}

// guard resolves in the service, refuses if ANY answer is forbidden, dials the checked address (never the name, so a
// second lookup cannot rebind it) and checks the peer address again in the dialer's control hook.
type guard struct {
	resolver Resolver
	timeout  time.Duration
	// dial dials a checked ip:port; nil is a net.Dialer with the timeout and the control re-check. Tests replace it.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (g *guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, &guardError{"network " + network}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		rctx, cancel := context.WithTimeout(ctx, g.timeout)
		ips, err = g.resolver.LookupNetIP(rctx, "ip", host)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: no address", host)
		}
	}
	for _, ip := range ips {
		if why := Forbidden(ip); why != "" {
			return nil, &guardError{fmt.Sprintf("%s resolves to %s (%s)", host, ip, why)}
		}
	}
	target := net.JoinHostPort(ips[0].Unmap().String(), port)
	if g.dial != nil {
		return g.dial(ctx, network, target)
	}
	d := net.Dialer{Timeout: g.timeout, Control: controlCheck}
	return d.DialContext(ctx, network, target)
}

// controlCheck re-checks the address the socket is about to connect to.
func controlCheck(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &guardError{"unparsable peer " + address}
	}
	if why := Forbidden(ap.Addr()); why != "" {
		return &guardError{fmt.Sprintf("peer %s (%s)", ap.Addr(), why)}
	}
	return nil
}
