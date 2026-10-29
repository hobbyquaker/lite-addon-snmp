package snmp

import (
	"errors"
	"fmt"
)

// BER tags SNMP uses.
const (
	TagInteger     byte = 0x02
	TagOctetString byte = 0x04
	TagNull        byte = 0x05
	TagOID         byte = 0x06
	TagSequence    byte = 0x30
	TagIPAddress   byte = 0x40
	TagCounter32   byte = 0x41
	TagGauge32     byte = 0x42
	TagTimeTicks   byte = 0x43
	TagOpaque      byte = 0x44
	TagCounter64   byte = 0x46
	// the exceptions of a v2 variable binding (RFC 3416 §3)
	TagNoSuchObject   byte = 0x80
	TagNoSuchInstance byte = 0x81
	TagEndOfMibView   byte = 0x82
)

// ErrMalformed is a message that is not the BER SNMP expects.
var ErrMalformed = errors.New("malformed BER")

// --- encoding ---

// appendLength writes a definite length.
func appendLength(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n <= 0xff:
		return append(b, 0x81, byte(n))
	case n <= 0xffff:
		return append(b, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		return append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(b, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// TLV encodes one element.
func TLV(tag byte, content []byte) []byte {
	b := make([]byte, 0, len(content)+6)
	b = append(b, tag)
	b = appendLength(b, len(content))
	return append(b, content...)
}

// Seq encodes a SEQUENCE (or any constructed tag) of already encoded elements.
func Seq(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n+6)
	b = append(b, tag)
	b = appendLength(b, n)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// Int encodes an INTEGER (two's complement, minimal).
func Int(tag byte, v int64) []byte {
	var c []byte
	for i := 7; i >= 0; i-- {
		c = append(c, byte(v>>(8*uint(i))))
	}
	// strip redundant leading bytes
	for len(c) > 1 && ((c[0] == 0 && c[1]&0x80 == 0) || (c[0] == 0xff && c[1]&0x80 != 0)) {
		c = c[1:]
	}
	return TLV(tag, c)
}

// Uint encodes an unsigned application type (Counter32, Gauge32, TimeTicks, Counter64): the
// value with a leading zero byte when its top bit is set.
func Uint(tag byte, v uint64) []byte {
	var c []byte
	for i := 7; i >= 0; i-- {
		c = append(c, byte(v>>(8*uint(i))))
	}
	for len(c) > 1 && c[0] == 0 && c[1]&0x80 == 0 {
		c = c[1:]
	}
	if c[0]&0x80 != 0 {
		c = append([]byte{0}, c...)
	}
	return TLV(tag, c)
}

// Octets encodes an OCTET STRING.
func Octets(v []byte) []byte { return TLV(TagOctetString, v) }

// EncodeOID encodes an OBJECT IDENTIFIER.
func EncodeOID(o OID) []byte {
	if len(o) < 2 {
		// 0.0 for an OID too short to encode (never one we make)
		return TLV(TagOID, []byte{0})
	}
	c := appendBase128(nil, o[0]*40+o[1])
	for _, n := range o[2:] {
		c = appendBase128(c, n)
	}
	return TLV(TagOID, c)
}

func appendBase128(b []byte, n uint32) []byte {
	if n == 0 {
		return append(b, 0)
	}
	var tmp [5]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n & 0x7f)
		n >>= 7
	}
	for j := i; j < len(tmp)-1; j++ {
		tmp[j] |= 0x80
	}
	return append(b, tmp[i:]...)
}

// --- decoding ---

// Reader walks a BER encoding.
type Reader struct {
	b   []byte
	off int
	// base is the offset of b within the whole message, for the authentication parameters' position
	base int
}

// NewReader reads b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Done tells whether everything was read.
func (r *Reader) Done() bool { return r.off >= len(r.b) }

// Offset is the reader's position in the whole message.
func (r *Reader) Offset() int { return r.base + r.off }

// Peek answers the next tag without reading it.
func (r *Reader) Peek() (byte, error) {
	if r.off >= len(r.b) {
		return 0, ErrMalformed
	}
	return r.b[r.off], nil
}

// Next reads one element: its tag, its content and the content's offset in the whole message.
func (r *Reader) Next() (tag byte, content []byte, at int, err error) {
	if r.off+2 > len(r.b) {
		return 0, nil, 0, ErrMalformed
	}
	tag = r.b[r.off]
	if tag&0x1f == 0x1f {
		return 0, nil, 0, ErrMalformed // multi-byte tags: SNMP has none
	}
	p := r.off + 1
	l := int(r.b[p])
	p++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || p+n > len(r.b) {
			return 0, nil, 0, ErrMalformed
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(r.b[p+i])
		}
		p += n
	}
	if l < 0 || p+l > len(r.b) {
		return 0, nil, 0, ErrMalformed
	}
	content = r.b[p : p+l]
	at = r.base + p
	r.off = p + l
	return tag, content, at, nil
}

// Expect reads one element of the tag.
func (r *Reader) Expect(tag byte) ([]byte, int, error) {
	t, c, at, err := r.Next()
	if err != nil {
		return nil, 0, err
	}
	if t != tag {
		return nil, 0, fmt.Errorf("%w: tag 0x%02x, want 0x%02x", ErrMalformed, t, tag)
	}
	return c, at, nil
}

// Sub answers a reader of a constructed element's content.
func (r *Reader) Sub(tag byte) (*Reader, error) {
	c, at, err := r.Expect(tag)
	if err != nil {
		return nil, err
	}
	return &Reader{b: c, base: at}, nil
}

// Int reads an INTEGER.
func (r *Reader) Int() (int64, error) {
	c, _, err := r.Expect(TagInteger)
	if err != nil {
		return 0, err
	}
	return parseInt(c)
}

// Octets reads an OCTET STRING.
func (r *Reader) Octets() ([]byte, error) {
	c, _, err := r.Expect(TagOctetString)
	return c, err
}

func parseInt(c []byte) (int64, error) {
	if len(c) == 0 || len(c) > 8 {
		return 0, ErrMalformed
	}
	v := int64(int8(c[0]))
	for _, x := range c[1:] {
		v = v<<8 | int64(x)
	}
	return v, nil
}

func parseUint(c []byte) (uint64, error) {
	if len(c) == 0 || len(c) > 9 || (len(c) == 9 && c[0] != 0) {
		return 0, ErrMalformed
	}
	var v uint64
	for _, x := range c {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// ParseOIDBytes decodes an OBJECT IDENTIFIER's content.
func ParseOIDBytes(c []byte) (OID, error) {
	if len(c) == 0 {
		return nil, ErrMalformed
	}
	var arcs []uint32
	var n uint64
	for i, x := range c {
		n = n<<7 | uint64(x&0x7f)
		if n > 0xffffffff+80 {
			return nil, ErrMalformed
		}
		if x&0x80 != 0 {
			if i == len(c)-1 {
				return nil, ErrMalformed
			}
			continue
		}
		if len(arcs) == 0 {
			switch {
			case n < 40:
				arcs = append(arcs, 0, uint32(n))
			case n < 80:
				arcs = append(arcs, 1, uint32(n-40))
			default:
				arcs = append(arcs, 2, uint32(n-80))
			}
		} else {
			if n > 0xffffffff {
				return nil, ErrMalformed
			}
			arcs = append(arcs, uint32(n))
		}
		n = 0
	}
	if len(arcs) > 128 {
		return nil, ErrMalformed
	}
	return arcs, nil
}
