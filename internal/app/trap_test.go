package app

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/fakesys"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

type received struct {
	mu   sync.Mutex
	oids []string
}

func (r *received) has(oid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.oids {
		if o == oid {
			return true
		}
	}
	return false
}

func listener(t *testing.T, params *gosnmp.GoSNMP) (*received, int) {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	tl := gosnmp.NewTrapListener()
	tl.Params = params
	r := &received{}
	tl.OnNewTrap = func(p *gosnmp.SnmpPacket, _ *net.UDPAddr) {
		for _, v := range p.Variables {
			if strings.TrimPrefix(v.Name, ".") == "1.3.6.1.6.3.1.1.4.1.0" {
				r.mu.Lock()
				r.oids = append(r.oids, strings.TrimPrefix(v.Value.(string), "."))
				r.mu.Unlock()
			}
		}
	}
	go func() { _ = tl.Listen(fmt.Sprintf("127.0.0.1:%d", port)) }()
	<-tl.Listening()
	t.Cleanup(tl.Close)
	return r, port
}

func wait(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// coldStart, a test, a service message raised by the fake system and cleared again reach a v2c
// listener and a v3 (SHA-256/AES) listener, gosnmp's trap receiver.
func TestTraps(t *testing.T) {
	v2, p2 := listener(t, &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "trapcommunity"})
	var engineID []byte
	h := start(t, func(c *config.Config) {
		u, _ := config.NewUser("trapper", usm.SHA256, usm.AES128, agent.ViewAll, "authpassword1", "privpassword1")
		c.Users = append(c.Users, u)
	})
	engineID = h.App.Agent.Engine().ID
	v3, p3 := listener(t, &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "trapper", AuthoritativeEngineID: string(engineID), AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: "authpassword1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpassword1"}})
	if _, err := h.Conf.Update(func(c *config.Config) error {
		c.Traps.Targets = []config.Target{
			{ID: "t2", Name: "v2c", Enabled: true, Host: "127.0.0.1", Port: p2, Kind: config.TargetV2cTrap, Community: "trapcommunity"},
			{ID: "t3", Name: "v3", Enabled: true, Host: "127.0.0.1", Port: p3, Kind: config.TargetV3Trap, User: "trapper"},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	h.App.Apply()
	for _, id := range []string{"t2", "t3"} {
		if err := h.Traps.Test(id); err != nil {
			t.Fatalf("test %s: %v", id, err)
		}
	}
	test := "1.3.6.1.4.1.8072.9999.9999.47621.2.0.13"
	wait(t, "the test notifications", func() bool { return v2.has(test) && v3.has(test) })

	h.Sys.Update(func(s *fakesys.System) {
		s.ServiceMessages = append(s.ServiceMessages, map[string]any{"interface": "BidCos-RF", "address": "JEQ0123456", "channel": "0", "key": "CONFIG_PENDING", "value": true, "since": time.Now().Format(time.RFC3339), "seen": "event"})
	})
	raised := "1.3.6.1.4.1.8072.9999.9999.47621.2.0.1"
	wait(t, "hmServiceMessageRaised", func() bool { return v2.has(raised) && v3.has(raised) })
	h.Sys.Update(func(s *fakesys.System) { s.ServiceMessages = s.ServiceMessages[:2] })
	cleared := "1.3.6.1.4.1.8072.9999.9999.47621.2.0.2"
	wait(t, "hmServiceMessageCleared", func() bool { return v2.has(cleared) && v3.has(cleared) })
	if h.Traps.Sent() < 6 {
		t.Errorf("sent %d", h.Traps.Sent())
	}
}
