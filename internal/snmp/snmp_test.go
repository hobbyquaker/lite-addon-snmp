package snmp

import (
	"bytes"
	"testing"
)

func TestOIDOrderAndIndex(t *testing.T) {
	if MustOID("1.3.6.1.2").Compare(MustOID("1.3.6.1.10")) >= 0 || MustOID("1.3.6").Compare(MustOID("1.3.6.0")) >= 0 {
		t.Fatal("order")
	}
	idx := StringsIndex("HmIP-RF", "000A")
	got, ok := DecodeStringsIndex(idx, 2)
	if !ok || got[0] != "HmIP-RF" || got[1] != "000A" {
		t.Fatalf("index %v %v", got, ok)
	}
	if _, ok := DecodeStringsIndex(idx[:5], 2); ok {
		t.Fatal("a short index decoded")
	}
}

func TestValuesRoundTrip(t *testing.T) {
	vals := []Value{Integer(-1), Integer(0), Integer(128), Integer(-129), Integer32(1 << 40), Counter32(4294967295), Gauge32(1 << 40), Counter64(1<<64 - 1), TimeTicks(123), String("x"), ObjectID(MustOID("1.3.6.1.4.1.8072.9999.9999.47621")), Null(), Exception(TagEndOfMibView)}
	pdu := PDU{Type: Response, RequestID: -5}
	for i, v := range vals {
		pdu.VarBinds = append(pdu.VarBinds, VarBind{OID: MustOID("1.3.6.1").Append(uint32(i), 4294967295), Value: v})
	}
	m := CommunityMessage{Version: Version2c, Community: []byte("c"), PDU: pdu}
	b := m.Encode()
	d, err := DecodeCommunity(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.Encode(), b) || d.PDU.RequestID != -5 {
		t.Fatal("round trip")
	}
	if d.PDU.VarBinds[4].Value.Int != 0x7fffffff || d.PDU.VarBinds[7].Value.Uint != 1<<64-1 {
		t.Fatalf("values %v", d.PDU.VarBinds)
	}
	for _, bad := range [][]byte{{}, {0x30}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 0x03, 0x02, 0x01}} {
		if _, err := DecodeCommunity(bad); err == nil {
			t.Errorf("%x decoded", bad)
		}
	}
}

func TestV3AuthOffset(t *testing.T) {
	m := V3Message{MsgID: 7, MaxSize: 65507, Flags: FlagAuth, SecurityModel: SecurityModelUSM, USM: USMParams{EngineID: []byte{1, 2}, Boots: 1, Time: 2, UserName: []byte("u"), AuthParams: make([]byte, 24)}}
	out, at := EncodeV3(m, ScopedPDU{PDU: PDU{Type: GetRequest}}.Encode(), false)
	copy(out[at:], bytes.Repeat([]byte{0xaa}, 24))
	d, err := DecodeV3(out)
	if err != nil {
		t.Fatal(err)
	}
	if d.AuthAt != at || !bytes.Equal(d.USM.AuthParams, bytes.Repeat([]byte{0xaa}, 24)) {
		t.Fatalf("auth at %d, want %d", d.AuthAt, at)
	}
}
