package app

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/hobbyquaker/ccu-addon-kit/go/litesource"
	"github.com/hobbyquaker/ccu-addon-kit/go/litesource/fakelite"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/fakesys"
	"github.com/hobbyquaker/lite-addon-snmp/internal/hmmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
	"github.com/hobbyquaker/lite-addon-snmp/mibs"
)

// Harness is a running addon against the fake system.
type Harness struct {
	Sys  *fakesys.System
	Src  *source.Source
	App  *App
	Conf *config.Store
	Port int
}

func start(t *testing.T, prepare func(c *config.Config)) *Harness {
	t.Helper()
	fl := fakelite.New()
	sys := fakesys.New(fl)
	fakesys.Demo(sys)
	t.Cleanup(sys.Close)
	dir := t.TempDir()
	conf, err := config.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conf.Update(func(c *config.Config) error {
		c.Communities = []config.Community{{ID: "c1", Name: "testcommunity", View: agent.ViewAll, Sources: []string{"127.0.0.1"}}}
		if prepare != nil {
			prepare(c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	eng, err := config.LoadEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	eng.Start = time.Now()
	lite := litesource.New(sys.URL(), nil)
	src := source.New(source.Options{Lite: lite, Sys: source.NewSysClient(sys.URL(), nil), Log: t.Logf, RadioEvery: 200 * time.Millisecond, MessagesEvery: 200 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go src.Run(ctx)
	a := New(Options{Conf: conf, Source: src, Engine: eng, Version: "test", Port: 0, Listen: "127.0.0.1", Log: t.Logf})
	go a.Run(ctx)
	h := &Harness{Sys: sys, Src: src, App: a, Conf: conf}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ready := false
		src.View(func(st *source.State) {
			ready = st.Ready && st.SysReady && st.Names != nil && len(st.Devices) == 4 && st.StreamConnected
		})
		if addrs := a.Addrs(); ready && len(addrs) > 0 {
			h.Port = addrs[0].(*net.UDPAddr).Port
			return h
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the addon did not get ready")
	return nil
}

func (h *Harness) client(t *testing.T) *gosnmp.GoSNMP {
	c := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(h.Port), Version: gosnmp.Version2c, Community: "testcommunity", Timeout: 2 * time.Second, Retries: 1, MaxRepetitions: 20}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Conn.Close() })
	return c
}

func walk(t *testing.T, c *gosnmp.GoSNMP, root snmp.OID) map[string]gosnmp.SnmpPDU {
	out := map[string]gosnmp.SnmpPDU{}
	if err := c.BulkWalk(root.String(), func(p gosnmp.SnmpPDU) error {
		out[strings.TrimPrefix(p.Name, ".")] = p
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func idx(parts ...string) string { return snmp.OID(snmp.StringsIndex(parts...)).String() }

func TestHomematicTree(t *testing.T) {
	h := start(t, nil)
	got := walk(t, h.client(t), hmmib.Root)
	dev := hmmib.DeviceTbl.Append(1).String()
	want := map[string]any{
		hmmib.System.String() + ".1.0":                                                       "openccu-lite",
		hmmib.System.String() + ".2.0":                                                       "1.1.0-dev.5",
		hmmib.System.String() + ".5.0":                                                       2, // degraded: the stream down? no - a radio fine; see below
		dev + ".5." + idx("HmIP-RF", "000A1B2C3D4E5F"):                                       "Thermostat Bad",
		dev + ".6." + idx("HmIP-RF", "000A1B2C3D4E5F"):                                       "Bad",
		dev + ".7." + idx("HmIP-RF", "000A1B2C3D4E5F"):                                       "Heizung",
		dev + ".9." + idx("HmIP-RF", "000E1A2B3C4D5E"):                                       2,
		dev + ".10." + idx("HmIP-RF", "000E1A2B3C4D5E"):                                      1,
		dev + ".14." + idx("HmIP-RF", "000A1B2C3D4E5F"):                                      2900,
		dev + ".13." + idx("BidCos-RF", "JEQ0123456"):                                        -72,
		dev + ".16." + idx("HmIP-RF", "000E1A2B3C4D5E"):                                      2,
		hmmib.InterfaceTbl.String() + ".1.5." + idx("HmIP-RF"):                               7,
		hmmib.InterfaceTbl.String() + ".1.6." + idx("HmIP-RF"):                               4,
		hmmib.InterfaceTbl.String() + ".1.6." + idx("BidCos-RF"):                             -1,
		hmmib.InterfaceTbl.String() + ".1.11." + idx("HmIP-RF"):                              3,
		hmmib.InterfaceTbl.String() + ".1.12." + idx("HmIP-RF"):                              1,
		hmmib.ServiceMsgs.String() + ".1.0":                                                  2,
		hmmib.ServiceMsgs.String() + ".3.1.7." + idx("HmIP-RF", "000E1A2B3C4D5E", "UNREACH"): "Fenster Küche",
	}
	delete(want, hmmib.System.String()+".5.0")
	for o, w := range want {
		p, ok := got[o]
		if !ok {
			t.Errorf("%s: missing", o)
			continue
		}
		switch w := w.(type) {
		case string:
			if b, _ := p.Value.([]byte); string(b) != w {
				t.Errorf("%s: %v, want %q", o, p.Value, w)
			}
		case int:
			if gosnmp.ToBigInt(p.Value).Int64() != int64(w) {
				t.Errorf("%s: %v, want %d", o, p.Value, w)
			}
		}
	}
	if v := gosnmp.ToBigInt(got[dev+".17."+idx("HmIP-RF", "000A1B2C3D4E5F")].Value).Int64(); v < 0 || v > 60 {
		t.Errorf("hmDevLastSeenAge %d", v)
	}
	if v := gosnmp.ToBigInt(got[hmmib.System.String()+".5.0"].Value).Int64(); v != 1 {
		t.Errorf("hmSysHealth %d, want ok(1)", v)
	}
	// every walked instance is an object of the MIB, and every scalar of the MIB is answered
	idxm, err := mibs.Index(mibs.File, hmmib.Root)
	if err != nil {
		t.Fatal(err)
	}
	var leaves []mibs.Object
	for _, o := range idxm {
		if o.Leaf {
			leaves = append(leaves, o)
		}
	}
	for o := range got {
		oid := snmp.MustOID(o)
		found := false
		for _, l := range leaves {
			if oid.HasPrefix(l.OID) && len(oid) > len(l.OID) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s is answered but not defined in the MIB", o)
		}
	}
	for _, l := range leaves {
		if !strings.Contains(l.Name, "Trap") && !strings.HasPrefix(l.Name, "hmNotif") && !strings.HasPrefix(l.Name, "hmDp") {
			hit := false
			for o := range got {
				if snmp.MustOID(o).HasPrefix(l.OID) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("%s (%v) is defined but not answered", l.Name, l.OID)
			}
		}
	}
}

func TestDeviceTableSelection(t *testing.T) {
	h := start(t, func(c *config.Config) {
		c.Selections = []selection.Selection{{ID: "s1", Name: "Flur", Rooms: []string{"Flur"}}, {ID: "s2", Name: "Batteries", Keys: []string{"LOW*"}}}
		c.DeviceTable = "s1"
	})
	count := func() []string {
		var out []string
		for o := range walk(t, h.client(t), hmmib.DeviceTbl.Append(1, 3)) {
			out = append(out, o)
		}
		return out
	}
	if n := count(); len(n) != 2 {
		t.Fatalf("room Flur: %d rows %v", len(n), n)
	}
	if _, err := h.Conf.Update(func(c *config.Config) error { c.DeviceTable = "s2"; return nil }); err != nil {
		t.Fatal(err)
	}
	h.App.Apply()
	// the thermostat, the window contact (LOW_BAT) and the remote (LOWBAT)
	if n := count(); len(n) != 3 {
		t.Fatalf("keys LOW*: %d rows %v", len(n), n)
	}
}

func TestStandardMIBs(t *testing.T) {
	h := start(t, nil)
	c := h.client(t)
	r, err := c.Get([]string{"1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.2021.4.5.0", "1.3.6.1.2.1.25.1.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Variables[0].Value.(string) != "."+hmmib.AgentOID.String() {
		t.Errorf("sysObjectID %v", r.Variables[0].Value)
	}
	for _, v := range r.Variables[1:] {
		if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance {
			t.Errorf("%s: %v", v.Name, v.Type)
		}
	}
	if n := len(walk(t, c, snmp.MustOID("1.3.6.1.2.1.2.2.1.2"))); n == 0 {
		t.Error("no interfaces")
	}
}
