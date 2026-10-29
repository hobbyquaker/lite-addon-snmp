package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

func TestStoreKeepsNoPassword(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c := s.Get(); !c.Enabled || len(c.Users)+len(c.Communities) != 0 {
		t.Fatalf("default %+v", c)
	}
	if _, err := NewUser("u", usm.SHA256, usm.AES128, agent.ViewAll, "short", "short"); err == nil {
		t.Fatal("short passwords accepted")
	}
	u, err := NewUser("u", usm.SHA256, usm.AES128, agent.ViewAll, "authpassword1", "privpassword1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(func(c *Config) error { c.Users = append(c.Users, u); return nil }); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, FileName))
	if strings.Contains(string(b), "authpassword1") || strings.Contains(string(b), "privpassword1") {
		t.Fatal("a password was stored")
	}
	st, _ := os.Stat(filepath.Join(dir, FileName))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := s.Update(func(c *Config) error { c.Users = append(c.Users, u); return nil }); err == nil {
		t.Fatal("a duplicate user accepted")
	}
	if _, err := s.Update(func(c *Config) error { c.DeviceTable = "nope"; return nil }); err == nil {
		t.Fatal("a missing selection accepted")
	}
	s2, _ := Open(dir)
	if len(s2.Get().Users) != 1 || len(s2.Get().Traps.Rules) != len(RuleKinds) {
		t.Fatalf("reread %+v", s2.Get())
	}
}

func TestEngine(t *testing.T) {
	dir := t.TempDir()
	e1, err := LoadEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := LoadEngine(dir)
	if string(e1.ID) != string(e2.ID) || e2.Boots != e1.Boots+1 || e1.Boots != 1 {
		t.Fatalf("%x/%d %x/%d", e1.ID, e1.Boots, e2.ID, e2.Boots)
	}
	if e1.ID[0] != 0x80 || e1.ID[3] != 0x88 || e1.ID[4] != 5 || len(e1.ID) != 21 {
		t.Fatalf("engine id %x", e1.ID)
	}
}
