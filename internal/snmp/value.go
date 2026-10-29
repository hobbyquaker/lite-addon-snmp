package snmp

import (
	"fmt"
	"net/netip"
)

// Value is one value of a variable binding.
type Value struct {
	Tag   byte
	Int   int64  // INTEGER
	Uint  uint64 // Counter32, Gauge32, TimeTicks, Counter64
	Bytes []byte // OCTET STRING, IpAddress, Opaque
	OID   OID    // OBJECT IDENTIFIER
}

// Constructors for the agent's values.

func Integer(v int64) Value     { return Value{Tag: TagInteger, Int: v} }
func String(s string) Value     { return Value{Tag: TagOctetString, Bytes: []byte(s)} }
func Bytes(b []byte) Value      { return Value{Tag: TagOctetString, Bytes: b} }
func ObjectID(o OID) Value      { return Value{Tag: TagOID, OID: o} }
func Counter32(v uint64) Value  { return Value{Tag: TagCounter32, Uint: v & 0xffffffff} }
func Counter64(v uint64) Value  { return Value{Tag: TagCounter64, Uint: v} }
func TimeTicks(v uint64) Value  { return Value{Tag: TagTimeTicks, Uint: v & 0xffffffff} }
func Null() Value               { return Value{Tag: TagNull} }
func Exception(tag byte) Value  { return Value{Tag: tag} }
func IPAddress(a [4]byte) Value { return Value{Tag: TagIPAddress, Bytes: a[:]} }

// Gauge32 caps at 2^32-1, as the type does.
func Gauge32(v uint64) Value {
	if v > 0xffffffff {
		v = 0xffffffff
	}
	return Value{Tag: TagGauge32, Uint: v}
}

// Integer32 caps a value into the 32-bit range.
func Integer32(v int64) Value {
	if v > 0x7fffffff {
		v = 0x7fffffff
	}
	if v < -0x80000000 {
		v = -0x80000000
	}
	return Value{Tag: TagInteger, Int: v}
}

// Truth is a TruthValue: true(1), false(2).
func Truth(b bool) Value {
	if b {
		return Integer(1)
	}
	return Integer(2)
}

// IP is an IpAddress from an IPv4 address; anything else is 0.0.0.0.
func IP(a netip.Addr) Value {
	if a.Is4() || a.Is4In6() {
		return IPAddress(a.Unmap().As4())
	}
	return IPAddress([4]byte{})
}

// IsException tells whether the value is noSuchObject, noSuchInstance or endOfMibView.
func (v Value) IsException() bool {
	return v.Tag == TagNoSuchObject || v.Tag == TagNoSuchInstance || v.Tag == TagEndOfMibView
}

// Encode is the value's BER.
func (v Value) Encode() []byte {
	switch v.Tag {
	case TagInteger:
		return Int(TagInteger, v.Int)
	case TagOctetString, TagIPAddress, TagOpaque:
		return TLV(v.Tag, v.Bytes)
	case TagOID:
		return EncodeOID(v.OID)
	case TagCounter32, TagGauge32, TagTimeTicks, TagCounter64:
		return Uint(v.Tag, v.Uint)
	default: // Null and the exceptions
		return TLV(v.Tag, nil)
	}
}

// String renders the value for logs and tests.
func (v Value) String() string {
	switch v.Tag {
	case TagInteger:
		return fmt.Sprintf("INTEGER %d", v.Int)
	case TagOctetString:
		return fmt.Sprintf("STRING %q", v.Bytes)
	case TagOID:
		return "OID " + v.OID.String()
	case TagIPAddress:
		if len(v.Bytes) == 4 {
			return fmt.Sprintf("IpAddress %d.%d.%d.%d", v.Bytes[0], v.Bytes[1], v.Bytes[2], v.Bytes[3])
		}
		return "IpAddress ?"
	case TagCounter32:
		return fmt.Sprintf("Counter32 %d", v.Uint)
	case TagGauge32:
		return fmt.Sprintf("Gauge32 %d", v.Uint)
	case TagTimeTicks:
		return fmt.Sprintf("Timeticks %d", v.Uint)
	case TagCounter64:
		return fmt.Sprintf("Counter64 %d", v.Uint)
	case TagNull:
		return "NULL"
	case TagNoSuchObject:
		return "noSuchObject"
	case TagNoSuchInstance:
		return "noSuchInstance"
	case TagEndOfMibView:
		return "endOfMibView"
	}
	return fmt.Sprintf("tag 0x%02x", v.Tag)
}

// DecodeValue reads a value from its tag and content.
func DecodeValue(tag byte, c []byte) (Value, error) {
	v := Value{Tag: tag}
	var err error
	switch tag {
	case TagInteger:
		v.Int, err = parseInt(c)
	case TagOctetString, TagIPAddress, TagOpaque:
		v.Bytes = append([]byte(nil), c...)
	case TagOID:
		v.OID, err = ParseOIDBytes(c)
	case TagCounter32, TagGauge32, TagTimeTicks, TagCounter64:
		v.Uint, err = parseUint(c)
	case TagNull, TagNoSuchObject, TagNoSuchInstance, TagEndOfMibView:
	default:
		return v, fmt.Errorf("%w: value tag 0x%02x", ErrMalformed, tag)
	}
	return v, err
}

// VarBind is one variable binding.
type VarBind struct {
	OID   OID
	Value Value
}

// Encode is the binding's BER.
func (vb VarBind) Encode() []byte {
	return Seq(TagSequence, EncodeOID(vb.OID), vb.Value.Encode())
}
