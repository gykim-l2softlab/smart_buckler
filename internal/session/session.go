// Package session identifies the client behind a request.
package session

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver derives the client IP, honoring X-Forwarded-For only when the
// connection comes from a trusted proxy (same model as nginx real_ip and
// Caddy trusted_proxies).
type Resolver struct {
	trusted []netip.Prefix
}

// NewResolver parses trusted proxy CIDRs or single IPs.
func NewResolver(trustedProxies []string) (*Resolver, error) {
	r := &Resolver{}
	for _, s := range trustedProxies {
		p, err := parsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", s, err)
		}
		r.trusted = append(r.trusted, p)
	}
	return r, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// ClientIP returns the session identifier for r: the connecting address, or,
// when that address is a trusted proxy, the rightmost untrusted address in
// X-Forwarded-For.
func (r *Resolver) ClientIP(req *http.Request) string {
	remote := remoteAddr(req)
	if !r.isTrusted(remote) {
		return addrString(remote, req.RemoteAddr)
	}
	hops := forwardedFor(req)
	for i := len(hops) - 1; i >= 0; i-- {
		if !r.isTrusted(hops[i]) {
			return hops[i].String()
		}
	}
	// Every hop is trusted (or the header is missing): fall back to the proxy.
	return addrString(remote, req.RemoteAddr)
}

// FromTrustedProxy reports whether the connection comes from a trusted proxy.
func (r *Resolver) FromTrustedProxy(req *http.Request) bool {
	return r.isTrusted(remoteAddr(req))
}

// IsTrusted reports whether ip is a trusted proxy. Such addresses must never
// be blocked: they carry every client behind them.
func (r *Resolver) IsTrusted(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && r.isTrusted(a.Unmap())
}

func (r *Resolver) isTrusted(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func remoteAddr(req *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func addrString(a netip.Addr, raw string) string {
	if a.IsValid() {
		return a.String()
	}
	return raw
}

func forwardedFor(req *http.Request) []netip.Addr {
	var out []netip.Addr
	for _, line := range req.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(line, ",") {
			a, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				// An unparsable hop breaks the chain of trust: stop here.
				out = out[:0]
				continue
			}
			out = append(out, a.Unmap())
		}
	}
	return out
}
