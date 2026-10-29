// Package snmp is the agent's wire format: BER, object identifiers, values, PDUs and the
// SNMPv1, SNMPv2c and SNMPv3 messages (RFC 3416, RFC 3412, RFC 3414's security parameters). It
// encodes and decodes; what a message means is the agent's concern.
package snmp

import (
	"fmt"
	"strconv"
	"strings"
)

// OID is an object identifier. Every sub-identifier is at most 2^32-1 (RFC 2578 §3.5).
type OID []uint32

// ParseOID reads the dotted form ("1.3.6.1.2.1.1.1.0", a leading dot allowed).
func ParseOID(s string) (OID, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	parts := strings.Split(s, ".")
	o := make(OID, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("OID %q: %v", s, err)
		}
		o[i] = uint32(n)
	}
	return o, nil
}

// MustOID is ParseOID for constants; it panics on a malformed OID.
func MustOID(s string) OID {
	o, err := ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

// String is the dotted form without a leading dot.
func (o OID) String() string {
	var b strings.Builder
	for i, n := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(n), 10))
	}
	return b.String()
}

// Compare orders OIDs lexicographically by sub-identifier: -1, 0 or 1.
func (o OID) Compare(p OID) int {
	n := min(len(o), len(p))
	for i := 0; i < n; i++ {
		switch {
		case o[i] < p[i]:
			return -1
		case o[i] > p[i]:
			return 1
		}
	}
	switch {
	case len(o) < len(p):
		return -1
	case len(o) > len(p):
		return 1
	}
	return 0
}

// HasPrefix tells whether p is o or an ancestor of o.
func (o OID) HasPrefix(p OID) bool {
	if len(p) > len(o) {
		return false
	}
	for i := range p {
		if o[i] != p[i] {
			return false
		}
	}
	return true
}

// Append answers a new OID: o followed by the arcs.
func (o OID) Append(arcs ...uint32) OID {
	out := make(OID, 0, len(o)+len(arcs))
	out = append(out, o...)
	return append(out, arcs...)
}

// Equal tells whether two OIDs are the same.
func (o OID) Equal(p OID) bool { return o.Compare(p) == 0 }

// StringIndex is a table index of one OCTET STRING column that is not IMPLIED: the length, then
// every byte as a sub-identifier (RFC 2578 §7.7).
func StringIndex(s string) []uint32 {
	out := make([]uint32, 0, len(s)+1)
	out = append(out, uint32(len(s)))
	for i := 0; i < len(s); i++ {
		out = append(out, uint32(s[i]))
	}
	return out
}

// StringsIndex concatenates the indices of several OCTET STRING columns.
func StringsIndex(l ...string) []uint32 {
	var out []uint32
	for _, s := range l {
		out = append(out, StringIndex(s)...)
	}
	return out
}

// DecodeStringsIndex reads n OCTET STRING index columns back; ok is false when the arcs do not
// hold exactly that.
func DecodeStringsIndex(arcs []uint32, n int) (out []string, ok bool) {
	for i := 0; i < n; i++ {
		if len(arcs) == 0 {
			return nil, false
		}
		l := int(arcs[0])
		if l > len(arcs)-1 {
			return nil, false
		}
		b := make([]byte, l)
		for j := 0; j < l; j++ {
			if arcs[1+j] > 255 {
				return nil, false
			}
			b[j] = byte(arcs[1+j])
		}
		out = append(out, string(b))
		arcs = arcs[1+l:]
	}
	return out, len(arcs) == 0
}
