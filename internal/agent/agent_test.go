package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/hobbyquaker/lite-addon-snmp/internal/mib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

var testRoot = snmp.MustOID("1.3.6.1.4.1.8072.9999.9999.47621")

func testTree() *mib.Tree {
	t := mib.New()
	t.Register(mib.FromFunc(mib.Func{OID: snmp.MustOID("1.3.6.1.2.1.1"), Collect: func() []snmp.VarBind {
		return []snmp.VarBind{
			{OID: snmp.MustOID("1.3.6.1.2.1.1.1.0"), Value: snmp.String("Linux test")},
			{OID: snmp.MustOID("1.3.6.1.2.1.1.2.0"), Value: snmp.ObjectID(testRoot.Append(4, 1))},
			{OID: snmp.MustOID("1.3.6.1.2.1.1.3.0"), Value: snmp.TimeTicks(1234)},
			{OID: snmp.MustOID("1.3.6.1.2.1.1.5.0"), Value: snmp.String("ccu")},
		}
	}}))
	t.Register(mib.FromFunc(mib.Func{OID: snmp.MustOID("1.3.6.1.2.1.31"), Collect: func() []snmp.VarBind {
		var out []snmp.VarBind
		for i := uint32(1); i <= 40; i++ {
			out = append(out, snmp.VarBind{OID: snmp.MustOID("1.3.6.1.2.1.31.1.1.1.6").Append(i), Value: snmp.Counter64(uint64(i) << 40)})
		}
		return out
	}}))
	t.Register(mib.FromFunc(mib.Func{OID: testRoot, Collect: func() []snmp.VarBind {
		return []snmp.VarBind{
			{OID: testRoot.Append(1, 1, 1, 0), Value: snmp.String("openccu-lite")},
			{OID: testRoot.Append(1, 2, 1, 2).Append(snmp.StringIndex("HmIP-RF")...), Value: snmp.Integer(2)},
		}
	}}))
	return t
}

func engineID() []byte {
	return []byte{0x80, 0x00, 0x1f, 0x88, 0x05, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
}

func startAgent(t *testing.T) (*Agent, int) {
	t.Helper()
	a := New(Options{Tree: testTree(), Root: testRoot, Engine: Engine{ID: engineID(), Boots: 3, Start: time.Now()}, RatePerSecond: 10000, Burst: 10000})
	var users []User
	for _, au := range usm.Auths {
		for _, pr := range usm.Privs {
			users = append(users, User{Name: fmt.Sprintf("u-%s-%s", au, pr), Auth: au, Priv: pr, KuAuth: usm.PasswordToKey(au, "authpassword1"), KuPriv: usm.PasswordToKey(au, "privpassword1"), View: ViewAll})
		}
	}
	users = append(users, User{Name: "std", Auth: usm.SHA256, Priv: usm.AES128, KuAuth: usm.PasswordToKey(usm.SHA256, "authpassword1"), KuPriv: usm.PasswordToKey(usm.SHA256, "privpassword1"), View: ViewStandard})
	users = append(users, User{Name: "hm", Auth: usm.SHA256, Priv: usm.AES128, KuAuth: usm.PasswordToKey(usm.SHA256, "authpassword1"), KuPriv: usm.PasswordToKey(usm.SHA256, "privpassword1"), View: ViewHomematic})
	src, _ := ParseSources([]string{"local"})
	a.SetCredentials(users, []Community{{Name: "public2", View: ViewAll, Sources: src}, {Name: "nobody", View: ViewAll}})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.Serve(ctx, pc)
	return a, pc.LocalAddr().(*net.UDPAddr).Port
}

var gAuth = map[usm.Auth]gosnmp.SnmpV3AuthProtocol{usm.SHA1: gosnmp.SHA, usm.SHA224: gosnmp.SHA224, usm.SHA256: gosnmp.SHA256, usm.SHA384: gosnmp.SHA384, usm.SHA512: gosnmp.SHA512}
var gPriv = map[usm.Priv]gosnmp.SnmpV3PrivProtocol{usm.AES128: gosnmp.AES, usm.AES192: gosnmp.AES192, usm.AES256: gosnmp.AES256}

func v3Client(port int, user string, au usm.Auth, pr usm.Priv, authPW string) *gosnmp.GoSNMP {
	return &gosnmp.GoSNMP{
		Target: "127.0.0.1", Port: uint16(port), Version: gosnmp.Version3, Timeout: 2 * time.Second, Retries: 0,
		SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, MaxRepetitions: 10,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: user, AuthenticationProtocol: gAuth[au], AuthenticationPassphrase: authPW, PrivacyProtocol: gPriv[pr], PrivacyPassphrase: "privpassword1"},
	}
}

func TestV3AllProtocols(t *testing.T) {
	_, port := startAgent(t)
	for _, au := range usm.Auths {
		for _, pr := range usm.Privs {
			t.Run(fmt.Sprintf("%s/%s", au, pr), func(t *testing.T) {
				c := v3Client(port, fmt.Sprintf("u-%s-%s", au, pr), au, pr, "authpassword1")
				if err := c.Connect(); err != nil {
					t.Fatal(err)
				}
				defer c.Conn.Close()
				r, err := c.Get([]string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.9.0"})
				if err != nil {
					t.Fatal(err)
				}
				if string(r.Variables[0].Value.([]byte)) != "Linux test" || r.Variables[1].Type != gosnmp.NoSuchObject {
					t.Fatalf("get: %+v", r.Variables)
				}
				var n int
				if err := c.BulkWalk("1.3.6.1", func(pdu gosnmp.SnmpPDU) error { n++; return nil }); err != nil {
					t.Fatal(err)
				}
				if n != 46 {
					t.Fatalf("bulk walk: %d", n)
				}
			})
		}
	}
}

func TestV3WrongPassword(t *testing.T) {
	a, port := startAgent(t)
	c := v3Client(port, "u-SHA-256-AES", usm.SHA256, usm.AES128, "wrongpassword")
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Conn.Close()
	if _, err := c.Get([]string{"1.3.6.1.2.1.1.1.0"}); err == nil {
		t.Fatal("a wrong password was answered")
	}
	if a.C.WrongDigests.Load() == 0 {
		t.Error("no wrong digest counted")
	}
	c = v3Client(port, "nosuchuser", usm.SHA256, usm.AES128, "authpassword1")
	_ = c.Connect()
	defer c.Conn.Close()
	if _, err := c.Get([]string{"1.3.6.1.2.1.1.1.0"}); err == nil {
		t.Fatal("an unknown user was answered")
	}
}

func TestViews(t *testing.T) {
	_, port := startAgent(t)
	walk := func(user string) []string {
		c := v3Client(port, user, usm.SHA256, usm.AES128, "authpassword1")
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		defer c.Conn.Close()
		var out []string
		if err := c.Walk("1.3", func(p gosnmp.SnmpPDU) error { out = append(out, p.Name); return nil }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	std := walk("std")
	if len(std) != 44 || strings.Contains(strings.Join(std, " "), "47621") {
		t.Errorf("standard view: %d %v", len(std), std)
	}
	hm := walk("hm")
	if len(hm) != 6 || strings.Contains(strings.Join(hm, " "), ".31.1.1") {
		t.Errorf("homematic view: %d %v", len(hm), hm)
	}
}

func TestCommunity(t *testing.T) {
	a, port := startAgent(t)
	for _, v := range []gosnmp.SnmpVersion{gosnmp.Version1, gosnmp.Version2c} {
		c := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Version: v, Community: "public2", Timeout: 2 * time.Second, Retries: 0}
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := c.Walk("1.3.6.1", func(p gosnmp.SnmpPDU) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
		// v1 skips the 40 Counter64
		want := 46
		if v == gosnmp.Version1 {
			want = 6
		}
		if n != want {
			t.Errorf("%v walk: %d, want %d", v, n, want)
		}
		r, err := c.Set([]gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "x"}})
		if err != nil {
			t.Fatal(err)
		}
		if r.Error == gosnmp.NoError {
			t.Errorf("%v: a set was accepted", v)
		}
		c.Conn.Close()
	}
	// a community without sources and a wrong one get no answer
	for _, com := range []string{"nobody", "wrong"} {
		c := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Version: gosnmp.Version2c, Community: com, Timeout: 300 * time.Millisecond, Retries: 0}
		_ = c.Connect()
		if _, err := c.Get([]string{"1.3.6.1.2.1.1.1.0"}); err == nil {
			t.Errorf("community %q answered", com)
		}
		c.Conn.Close()
	}
	if a.C.InBadCommunityNames.Load() != 2 || a.C.SetsRefused.Load() != 2 {
		t.Errorf("counters: bad %d sets %d", a.C.InBadCommunityNames.Load(), a.C.SetsRefused.Load())
	}
}

func TestNoCredentialsNoAnswer(t *testing.T) {
	a := New(Options{Tree: testTree(), Root: testRoot, Engine: Engine{ID: engineID(), Boots: 1, Start: time.Now()}})
	m := snmp.CommunityMessage{Version: 1, Community: []byte("public"), PDU: snmp.PDU{Type: snmp.GetRequest, RequestID: 1, VarBinds: []snmp.VarBind{{OID: snmp.MustOID("1.3.6.1.2.1.1.1.0"), Value: snmp.Null()}}}}
	if out := a.Handle(m.Encode(), mustAddrPort("127.0.0.1:1")); out != nil {
		t.Fatal("answered without credentials")
	}
}

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
