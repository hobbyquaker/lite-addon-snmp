package snmp

import (
	"fmt"
)

// PDU types.
const (
	GetRequest     byte = 0xa0
	GetNextRequest byte = 0xa1
	Response       byte = 0xa2
	SetRequest     byte = 0xa3
	TrapV1         byte = 0xa4
	GetBulkRequest byte = 0xa5
	InformRequest  byte = 0xa6
	SNMPv2Trap     byte = 0xa7
	Report         byte = 0xa8
)

// Error statuses (RFC 3416 §3).
const (
	NoError             = 0
	TooBig              = 1
	NoSuchName          = 2 // v1
	BadValue            = 3 // v1
	ReadOnly            = 4 // v1
	GenErr              = 5
	NoAccess            = 6
	NotWritable         = 17
	AuthorizationError  = 16
	ResourceUnavailable = 13
)

// Versions on the wire.
const (
	Version1  = 0
	Version2c = 1
	Version3  = 3
)

// PDU is a protocol data unit. For a GetBulkRequest ErrorStatus is non-repeaters and ErrorIndex
// max-repetitions.
type PDU struct {
	Type        byte
	RequestID   int32
	ErrorStatus int
	ErrorIndex  int
	VarBinds    []VarBind
}

// Encode is the PDU's BER.
func (p PDU) Encode() []byte {
	vbs := make([][]byte, len(p.VarBinds))
	for i, vb := range p.VarBinds {
		vbs[i] = vb.Encode()
	}
	return Seq(p.Type, Int(TagInteger, int64(p.RequestID)), Int(TagInteger, int64(p.ErrorStatus)), Int(TagInteger, int64(p.ErrorIndex)), Seq(TagSequence, vbs...))
}

// EncodedVarBindsLen is the size the bindings add to an encoded PDU.
func EncodedVarBindsLen(vbs []VarBind) int {
	n := 0
	for _, vb := range vbs {
		n += len(vb.Encode())
	}
	return n
}

// DecodePDU reads a PDU from a reader positioned at it.
func DecodePDU(r *Reader) (PDU, error) {
	t, err := r.Peek()
	if err != nil {
		return PDU{}, err
	}
	switch t {
	case GetRequest, GetNextRequest, Response, SetRequest, GetBulkRequest, InformRequest, SNMPv2Trap, Report:
	default:
		return PDU{}, fmt.Errorf("%w: PDU type 0x%02x", ErrMalformed, t)
	}
	s, err := r.Sub(t)
	if err != nil {
		return PDU{}, err
	}
	p := PDU{Type: t}
	id, err := s.Int()
	if err != nil {
		return p, err
	}
	p.RequestID = int32(id)
	es, err := s.Int()
	if err != nil {
		return p, err
	}
	ei, err := s.Int()
	if err != nil {
		return p, err
	}
	p.ErrorStatus, p.ErrorIndex = int(es), int(ei)
	l, err := s.Sub(TagSequence)
	if err != nil {
		return p, err
	}
	for !l.Done() {
		vb, err := l.Sub(TagSequence)
		if err != nil {
			return p, err
		}
		c, _, err := vb.Expect(TagOID)
		if err != nil {
			return p, err
		}
		o, err := ParseOIDBytes(c)
		if err != nil {
			return p, err
		}
		tag, vc, _, err := vb.Next()
		if err != nil {
			return p, err
		}
		v, err := DecodeValue(tag, vc)
		if err != nil {
			return p, err
		}
		p.VarBinds = append(p.VarBinds, VarBind{OID: o, Value: v})
		if len(p.VarBinds) > 1000 {
			return p, fmt.Errorf("%w: too many bindings", ErrMalformed)
		}
	}
	return p, nil
}

// MessageVersion reads the version of a message without decoding the rest.
func MessageVersion(b []byte) (int64, error) {
	r := NewReader(b)
	m, err := r.Sub(TagSequence)
	if err != nil {
		return 0, err
	}
	return m.Int()
}

// CommunityMessage is an SNMPv1 or SNMPv2c message.
type CommunityMessage struct {
	Version   int64
	Community []byte
	PDU       PDU
}

// Encode is the message's BER.
func (m CommunityMessage) Encode() []byte {
	return Seq(TagSequence, Int(TagInteger, m.Version), Octets(m.Community), m.PDU.Encode())
}

// DecodeCommunity reads an SNMPv1 or SNMPv2c message.
func DecodeCommunity(b []byte) (*CommunityMessage, error) {
	r := NewReader(b)
	s, err := r.Sub(TagSequence)
	if err != nil {
		return nil, err
	}
	m := &CommunityMessage{}
	if m.Version, err = s.Int(); err != nil {
		return nil, err
	}
	if m.Community, err = s.Octets(); err != nil {
		return nil, err
	}
	if m.PDU, err = DecodePDU(s); err != nil {
		return nil, err
	}
	return m, nil
}

// Message flags (RFC 3412 §6.4).
const (
	FlagAuth       byte = 0x01
	FlagPriv       byte = 0x02
	FlagReportable byte = 0x04
)

// SecurityModelUSM is the only security model the agent speaks.
const SecurityModelUSM = 3

// USMParams are the user-based security model's parameters (RFC 3414 §2.4).
type USMParams struct {
	EngineID   []byte
	Boots      int64
	Time       int64
	UserName   []byte
	AuthParams []byte
	PrivParams []byte
}

func (u USMParams) encode() (enc []byte, authAt int) {
	head := [][]byte{Octets(u.EngineID), Int(TagInteger, u.Boots), Int(TagInteger, u.Time), Octets(u.UserName)}
	n := 0
	for _, h := range head {
		n += len(h)
	}
	auth := Octets(u.AuthParams)
	authAt = n + (len(auth) - len(u.AuthParams))
	body := Seq(TagSequence, append(head, auth, Octets(u.PrivParams))...)
	return body, authAt + (len(body) - (n + len(auth) + len(Octets(u.PrivParams))))
}

// V3Message is an SNMPv3 message: the header, the security parameters and the data, either a
// plaintext scoped PDU (its encoding) or the encrypted one.
type V3Message struct {
	MsgID         int64
	MaxSize       int64
	Flags         byte
	SecurityModel int64
	USM           USMParams
	// Data is the scoped PDU's encoding (a SEQUENCE) when not encrypted, else the ciphertext.
	Data      []byte
	Encrypted bool
	// AuthAt is the offset of the authentication parameters' content in Raw.
	AuthAt int
	Raw    []byte
}

// DecodeV3 reads an SNMPv3 message.
func DecodeV3(b []byte) (*V3Message, error) {
	r := NewReader(b)
	s, err := r.Sub(TagSequence)
	if err != nil {
		return nil, err
	}
	m := &V3Message{Raw: b}
	v, err := s.Int()
	if err != nil {
		return nil, err
	}
	if v != Version3 {
		return nil, fmt.Errorf("%w: version %d", ErrMalformed, v)
	}
	h, err := s.Sub(TagSequence)
	if err != nil {
		return nil, err
	}
	if m.MsgID, err = h.Int(); err != nil {
		return nil, err
	}
	if m.MaxSize, err = h.Int(); err != nil {
		return nil, err
	}
	fl, err := h.Octets()
	if err != nil || len(fl) != 1 {
		return nil, fmt.Errorf("%w: msgFlags", ErrMalformed)
	}
	m.Flags = fl[0]
	if m.SecurityModel, err = h.Int(); err != nil {
		return nil, err
	}
	if m.MsgID < 0 || m.MaxSize < 484 {
		return nil, fmt.Errorf("%w: header", ErrMalformed)
	}
	sp, err := s.Sub(TagOctetString)
	if err != nil {
		return nil, err
	}
	if m.SecurityModel == SecurityModelUSM {
		u, err := sp.Sub(TagSequence)
		if err != nil {
			return nil, err
		}
		if m.USM.EngineID, err = u.Octets(); err != nil {
			return nil, err
		}
		if m.USM.Boots, err = u.Int(); err != nil {
			return nil, err
		}
		if m.USM.Time, err = u.Int(); err != nil {
			return nil, err
		}
		if m.USM.UserName, err = u.Octets(); err != nil {
			return nil, err
		}
		var at int
		if m.USM.AuthParams, at, err = u.Expect(TagOctetString); err != nil {
			return nil, err
		}
		m.AuthAt = at
		if m.USM.PrivParams, err = u.Octets(); err != nil {
			return nil, err
		}
	}
	t, err := s.Peek()
	if err != nil {
		return nil, err
	}
	switch t {
	case TagOctetString:
		m.Encrypted = true
		if m.Data, err = s.Octets(); err != nil {
			return nil, err
		}
	case TagSequence:
		start := s.off
		if _, _, _, err := s.Next(); err != nil {
			return nil, err
		}
		m.Data = s.b[start:s.off]
	default:
		return nil, fmt.Errorf("%w: msgData", ErrMalformed)
	}
	return m, nil
}

// EncodeV3 encodes a message whose AuthParams are a placeholder of the digest's length; it
// answers the encoding and the offset of the placeholder, where the caller writes the digest.
// data is the scoped PDU's encoding, or the ciphertext when encrypted.
func EncodeV3(m V3Message, data []byte, encrypted bool) ([]byte, int) {
	header := Seq(TagSequence, Int(TagInteger, m.MsgID), Int(TagInteger, m.MaxSize), Octets([]byte{m.Flags}), Int(TagInteger, m.SecurityModel))
	usm, authIn := m.USM.encode()
	secp := Octets(usm)
	authIn += len(secp) - len(usm)
	var d []byte
	if encrypted {
		d = Octets(data)
	} else {
		d = data
	}
	ver := Int(TagInteger, Version3)
	msg := Seq(TagSequence, ver, header, secp, d)
	inner := len(ver) + len(header) + len(secp) + len(d)
	off := len(msg) - inner
	return msg, off + len(ver) + len(header) + authIn
}

// ScopedPDU is the context and the PDU of an SNMPv3 message.
type ScopedPDU struct {
	ContextEngineID []byte
	ContextName     []byte
	PDU             PDU
}

// Encode is the scoped PDU's BER.
func (s ScopedPDU) Encode() []byte {
	return Seq(TagSequence, Octets(s.ContextEngineID), Octets(s.ContextName), s.PDU.Encode())
}

// DecodeScopedPDU reads a scoped PDU; trailing bytes after it (the cipher's padding) are ignored.
func DecodeScopedPDU(b []byte) (ScopedPDU, error) {
	r := NewReader(b)
	s, err := r.Sub(TagSequence)
	if err != nil {
		return ScopedPDU{}, err
	}
	var out ScopedPDU
	if out.ContextEngineID, err = s.Octets(); err != nil {
		return out, err
	}
	if out.ContextName, err = s.Octets(); err != nil {
		return out, err
	}
	out.PDU, err = DecodePDU(s)
	return out, err
}
