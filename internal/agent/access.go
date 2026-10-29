package agent

import (
	"net/netip"
	"strings"

	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

// View is what one credential may read.
type View string

// The views: everything, the standard MIBs only, or the Homematic tree (with the system group
// and the engine's objects, which every manager reads to identify the agent).
const (
	ViewAll       View = "all"
	ViewStandard  View = "standard"
	ViewHomematic View = "homematic"
)

// Valid tells whether the view is known.
func (v View) Valid() bool { return v == ViewAll || v == ViewStandard || v == ViewHomematic }

// User is an SNMPv3 user: authPriv always, the keys as Ku (the password-derived keys, not
// localised), never the password.
type User struct {
	Name   string
	Auth   usm.Auth
	Priv   usm.Priv
	KuAuth []byte
	KuPriv []byte
	View   View
}

// Community is an SNMPv1/v2c community with the sources it is accepted from.
type Community struct {
	Name string
	View View
	// Sources are prefixes; "local" in the configuration becomes the private, link-local and
	// loopback ranges. Empty accepts nobody.
	Sources []netip.Prefix
}

// LocalNetworks are the prefixes "local networks" means: RFC 1918, link-local, loopback, CGNAT
// and IPv6 unique-local and link-local.
var LocalNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// ParseSources reads a source list: "local", an address or a prefix per entry.
func ParseSources(l []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range l {
		s = strings.TrimSpace(s)
		switch {
		case s == "":
		case strings.EqualFold(s, "local"):
			out = append(out, LocalNetworks...)
		case strings.Contains(s, "/"):
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
		default:
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}

func allowedFrom(sources []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range sources {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// views decides per OID with the agent's own root (the Homematic tree).
type views struct {
	root snmp.OID
}

var (
	oidSystem      = snmp.MustOID("1.3.6.1.2.1.1")
	oidSnmpModules = snmp.MustOID("1.3.6.1.6.3")
)

// allowed tells whether the view admits the OID; when not, from is the position a GetNext
// continues from to reach the view's next admitted instance.
func (vw views) allowed(v View, o snmp.OID) (ok bool, from snmp.OID) {
	switch v {
	case ViewAll:
		return true, nil
	case ViewStandard:
		if o.HasPrefix(vw.root) {
			return false, after(vw.root)
		}
		return true, nil
	case ViewHomematic:
		if o.HasPrefix(vw.root) || o.HasPrefix(oidSystem) || o.HasPrefix(oidSnmpModules) {
			return true, nil
		}
		// jump to the next admitted subtree after o
		for _, r := range []snmp.OID{oidSystem, vw.root, oidSnmpModules} { // in OID order
			if r.Compare(o) > 0 {
				return false, r[:len(r)-1].Append(r[len(r)-1] - 1).Append(maxArcs(127 - len(r))...)
			}
		}
		return false, snmp.OID{2}.Append(maxArcs(127)...)
	}
	return false, nil
}

func maxArcs(n int) []uint32 {
	if n < 0 {
		n = 0
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = 0xffffffff
	}
	return out
}

// after is the last possible OID inside a subtree: a Next from it leaves the subtree.
func after(subtree snmp.OID) snmp.OID {
	return subtree.Append(maxArcs(128 - len(subtree))...)
}
