// Package config is the addon's configuration: the agent's settings, the SNMPv3 users and the
// v1/v2c communities, the selections and which selection fills each table. It lives in one JSON
// file, written atomically with mode 0600: the users are stored as their password-derived keys
// (Ku), never as the passwords, and the communities are secrets as well. The engine's identity
// lives beside it in engine.json.
package config

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

// User is an SNMPv3 user as stored.
type User struct {
	Name string     `json:"name"`
	Auth usm.Auth   `json:"auth"`
	Priv usm.Priv   `json:"priv"`
	View agent.View `json:"view"`
	// AuthKey and PrivKey are Ku in hex (RFC 3414 §A.2), derived from the passwords.
	AuthKey string `json:"auth_key"`
	PrivKey string `json:"priv_key"`
}

// Community is a v1/v2c community as stored.
type Community struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	View    agent.View `json:"view"`
	Sources []string   `json:"sources"`
}

// Config is the whole file.
type Config struct {
	// Enabled switches the agent; off, it answers nothing.
	Enabled     bool   `json:"enabled"`
	SysName     string `json:"sys_name"`
	SysLocation string `json:"sys_location"`
	SysContact  string `json:"sys_contact"`
	IPv4        bool   `json:"ipv4"`
	IPv6        bool   `json:"ipv6"`
	// Lang is the language of the room and function names in the tables.
	Lang        string                `json:"lang"`
	Users       []User                `json:"users"`
	Communities []Community           `json:"communities"`
	Selections  []selection.Selection `json:"selections"`
	// DeviceTable is the id of the selection that fills hmDeviceTable; "" is every device.
	DeviceTable string `json:"device_table"`
	// AuthTraps is snmpEnableAuthenTraps.
	AuthTraps bool `json:"auth_traps"`
	// Traps are the trap targets and rules (0.2.0).
	Traps Traps `json:"traps"`
}

// Default is the configuration of a fresh install: the agent on, but no credential, so it
// answers nobody until a user or a community is made.
func Default() Config {
	return Config{Enabled: true, IPv4: true, IPv6: true, Lang: "de", Users: []User{}, Communities: []Community{}, Selections: []selection.Selection{}, Traps: DefaultTraps()}
}

// Store holds the configuration and writes it.
type Store struct {
	dir string
	mu  sync.RWMutex
	c   Config
}

// FileName is the configuration's file in the directory.
const FileName = "snmp.json"

// Open reads the configuration from dir; a missing file is the default.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir, c: Default()}
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	c.normalise()
	s.c = c
	return s, nil
}

func (c *Config) normalise() {
	if c.Users == nil {
		c.Users = []User{}
	}
	if c.Communities == nil {
		c.Communities = []Community{}
	}
	if c.Selections == nil {
		c.Selections = []selection.Selection{}
	}
	if c.Lang != "en" {
		c.Lang = "de"
	}
	c.Traps.normalise()
}

// Get answers a copy of the configuration.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.c)
	var c Config
	_ = json.Unmarshal(b, &c)
	c.normalise()
	return c
}

// Update changes the configuration through f, validates and writes it; nothing changes when f or
// the validation fails.
func (s *Store) Update(f func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.c)
	var c Config
	_ = json.Unmarshal(b, &c)
	c.normalise()
	if err := f(&c); err != nil {
		return s.c, err
	}
	if err := c.Validate(); err != nil {
		return s.c, err
	}
	if err := s.write(c); err != nil {
		return s.c, err
	}
	s.c = c
	return c, nil
}

func (s *Store) write(c Config) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteSecret(filepath.Join(s.dir, FileName), b)
}

// WriteSecret writes a file atomically with mode 0600.
func WriteSecret(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)

// MinPassword is the shortest password a user may have.
const MinPassword = 12

// Validate checks the whole configuration.
func (c *Config) Validate() error {
	if len(c.SysName) > 255 || len(c.SysLocation) > 255 || len(c.SysContact) > 255 {
		return fmt.Errorf("sysName, sysLocation and sysContact take at most 255 characters")
	}
	if !c.IPv4 && !c.IPv6 {
		return fmt.Errorf("the agent needs IPv4 or IPv6")
	}
	seen := map[string]bool{}
	for _, u := range c.Users {
		if !nameRE.MatchString(u.Name) {
			return fmt.Errorf("user name %q: 1 to 32 of A-Z a-z 0-9 . _ @ -", u.Name)
		}
		if seen["u:"+u.Name] {
			return fmt.Errorf("user %q exists", u.Name)
		}
		seen["u:"+u.Name] = true
		if !u.Auth.Valid() || !u.Priv.Valid() || !u.View.Valid() {
			return fmt.Errorf("user %q: unknown protocol or view", u.Name)
		}
		a, err1 := hex.DecodeString(u.AuthKey)
		p, err2 := hex.DecodeString(u.PrivKey)
		if err1 != nil || err2 != nil || len(a) != u.Auth.KeyLen() || len(p) != u.Auth.KeyLen() {
			return fmt.Errorf("user %q: the keys do not match the protocol", u.Name)
		}
	}
	for _, cm := range c.Communities {
		if cm.Name == "" || len(cm.Name) > 64 || strings.ContainsAny(cm.Name, "\x00\n\r") {
			return fmt.Errorf("a community takes 1 to 64 characters")
		}
		if seen["c:"+cm.Name] || cm.ID == "" || seen["cid:"+cm.ID] {
			return fmt.Errorf("the community exists")
		}
		seen["c:"+cm.Name], seen["cid:"+cm.ID] = true, true
		if !cm.View.Valid() {
			return fmt.Errorf("community: unknown view")
		}
		if _, err := agent.ParseSources(cm.Sources); err != nil {
			return fmt.Errorf("community sources: %v", err)
		}
	}
	ids := map[string]bool{}
	for i := range c.Selections {
		s := &c.Selections[i]
		if s.ID == "" || ids[s.ID] {
			return fmt.Errorf("selection %q: missing or duplicate id", s.Name)
		}
		ids[s.ID] = true
		if err := s.Validate(); err != nil {
			return err
		}
	}
	if c.DeviceTable != "" && !ids[c.DeviceTable] {
		return fmt.Errorf("the device table's selection does not exist")
	}
	return c.Traps.validate(ids, seen)
}

// NewUser makes a user from passwords.
func NewUser(name string, auth usm.Auth, priv usm.Priv, view agent.View, authPassword, privPassword string) (User, error) {
	if len(authPassword) < MinPassword || len(privPassword) < MinPassword {
		return User{}, fmt.Errorf("the passwords need at least %d characters", MinPassword)
	}
	if !auth.Valid() || !priv.Valid() {
		return User{}, fmt.Errorf("unknown protocol")
	}
	return User{Name: name, Auth: auth, Priv: priv, View: view, AuthKey: hex.EncodeToString(usm.PasswordToKey(auth, authPassword)), PrivKey: hex.EncodeToString(usm.PasswordToKey(auth, privPassword))}, nil
}

// AgentUser converts a stored user.
func (u User) AgentUser() agent.User {
	a, _ := hex.DecodeString(u.AuthKey)
	p, _ := hex.DecodeString(u.PrivKey)
	return agent.User{Name: u.Name, Auth: u.Auth, Priv: u.Priv, KuAuth: a, KuPriv: p, View: u.View}
}

// AgentCommunity converts a stored community.
func (c Community) AgentCommunity() agent.Community {
	src, _ := agent.ParseSources(c.Sources)
	return agent.Community{Name: c.Name, View: c.View, Sources: src}
}

// NewID makes a selection or target id.
func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Selection answers a selection by id.
func (c *Config) Selection(id string) (selection.Selection, bool) {
	for _, s := range c.Selections {
		if s.ID == id {
			return s, true
		}
	}
	return selection.Selection{}, false
}

// --- the engine ---

// Engine is engine.json: the engine id and the boots counter.
type Engine struct {
	ID    string `json:"engine_id"`
	Boots int64  `json:"boots"`
}

// EnterpriseNumber is the one written into a new engine id (RFC 3411 format 5): net-snmp's,
// matching the provisional root's owner. An engine id never changes once made.
const EnterpriseNumber = 8072

// LoadEngine reads engine.json, makes the id on the first start, increments the boots and writes
// it back.
func LoadEngine(dir string) (agent.Engine, error) {
	p := filepath.Join(dir, "engine.json")
	var e Engine
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &e); err != nil {
			return agent.Engine{}, fmt.Errorf("engine.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return agent.Engine{}, err
	}
	id, err := hex.DecodeString(e.ID)
	if err != nil || len(id) < 5 || len(id) > 32 {
		id = make([]byte, 21)
		binary.BigEndian.PutUint32(id, 0x80000000|EnterpriseNumber)
		id[4] = 5
		if _, err := rand.Read(id[5:]); err != nil {
			return agent.Engine{}, err
		}
		e.ID, e.Boots = hex.EncodeToString(id), 0
	}
	if e.Boots < 2147483647 {
		e.Boots++
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return agent.Engine{}, err
	}
	b, _ := json.MarshalIndent(e, "", "  ")
	if err := WriteSecret(p, b); err != nil {
		return agent.Engine{}, err
	}
	return agent.Engine{ID: id, Boots: e.Boots}, nil
}
