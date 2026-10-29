package trap

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

var reqID atomic.Int32

func init() {
	var b [4]byte
	_, _ = rand.Read(b[:])
	reqID.Store(int32(binary.BigEndian.Uint32(b[:]) & 0x3fffffff))
}

var salt atomic.Uint64

func init() {
	var b [8]byte
	_, _ = rand.Read(b[:])
	salt.Store(binary.BigEndian.Uint64(b[:]))
}

// remoteEngine is an inform receiver's engine, as its report said.
type remoteEngine struct {
	id    []byte
	boots int64
	time  int64
	at    time.Time
}

func (r *remoteEngine) now(t time.Time) int64 { return r.time + int64(t.Sub(r.at)/time.Second) }

// sender sends one target's notifications.
type sender struct {
	timeout time.Duration
	retries int
	engine  agent.Engine
	remote  *remoteEngine
}

func (s *sender) dial(tg config.Target) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(tg.Host, strconv.Itoa(tg.Port)))
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

// send delivers one notification; user is the target's SNMPv3 user (nil for v2c).
func (s *sender) send(tg config.Target, user *agent.User, vbs []snmp.VarBind, now time.Time) error {
	switch tg.Kind {
	case config.TargetV2cTrap:
		c, err := s.dial(tg)
		if err != nil {
			return err
		}
		defer c.Close()
		msg := snmp.CommunityMessage{Version: snmp.Version2c, Community: []byte(tg.Community), PDU: snmp.PDU{Type: snmp.SNMPv2Trap, RequestID: reqID.Add(1), VarBinds: vbs}}
		_, err = c.Write(msg.Encode())
		return err
	case config.TargetV3Trap:
		if user == nil {
			return errors.New("the target's user does not exist")
		}
		c, err := s.dial(tg)
		if err != nil {
			return err
		}
		defer c.Close()
		// a trap's authoritative engine is ours
		keys := usm.LocalKeys(user.Auth, user.Priv, user.KuAuth, user.KuPriv, s.engine.ID)
		out, err := encode(snmp.PDU{Type: snmp.SNMPv2Trap, RequestID: reqID.Add(1), VarBinds: vbs}, user.Name, &keys, s.engine.ID, s.engine.Boots, s.engine.Time(now), s.engine.ID, false)
		if err != nil {
			return err
		}
		_, err = c.Write(out)
		return err
	case config.TargetV3Inform:
		if user == nil {
			return errors.New("the target's user does not exist")
		}
		return s.inform(tg, user, vbs)
	}
	return fmt.Errorf("unknown kind %q", tg.Kind)
}

// encode builds an SNMPv3 message; keys nil sends noAuthNoPriv (discovery).
func encode(pdu snmp.PDU, user string, keys *usm.Keys, engineID []byte, boots, etime int64, contextEngine []byte, reportable bool) ([]byte, error) {
	sp := snmp.ScopedPDU{ContextEngineID: contextEngine, PDU: pdu}
	m := snmp.V3Message{MsgID: int64(reqID.Add(1)), MaxSize: 65507, SecurityModel: snmp.SecurityModelUSM}
	if reportable {
		m.Flags |= snmp.FlagReportable
	}
	m.USM = snmp.USMParams{EngineID: engineID, Boots: boots, Time: etime, UserName: []byte(user)}
	data := sp.Encode()
	encrypted := false
	if keys != nil {
		m.Flags |= snmp.FlagAuth
		m.USM.AuthParams = make([]byte, keys.Auth.DigestLen())
		if keys.PrivKey != nil {
			m.Flags |= snmp.FlagPriv
			sl := make([]byte, 8)
			binary.BigEndian.PutUint64(sl, salt.Add(1))
			m.USM.PrivParams = sl
			ct, err := usm.Encrypt(keys.PrivKey, boots, etime, sl, data)
			if err != nil {
				return nil, err
			}
			data, encrypted = ct, true
		}
	}
	out, at := snmp.EncodeV3(m, data, encrypted)
	if keys != nil {
		usm.Sign(keys.Auth, keys.AuthKey, out, at)
	}
	return out, nil
}

// errNoAnswer is an inform nobody acknowledged.
var errNoAnswer = errors.New("no acknowledgement")

// exchange sends a request and waits for one answer, retrying.
func (s *sender) exchange(tg config.Target, req []byte, accept func([]byte) (bool, error)) error {
	c, err := s.dial(tg)
	if err != nil {
		return err
	}
	defer c.Close()
	buf := make([]byte, 65535)
	for try := 0; try <= s.retries; try++ {
		if _, err := c.Write(req); err != nil {
			return err
		}
		deadline := time.Now().Add(s.timeout)
		for {
			_ = c.SetReadDeadline(deadline)
			n, err := c.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				return err
			}
			done, err := accept(append([]byte(nil), buf[:n]...))
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}
	}
	return errNoAnswer
}

// discover learns the receiver's engine id, boots and time from its report to an empty request.
func (s *sender) discover(tg config.Target) error {
	req, err := encode(snmp.PDU{Type: snmp.GetRequest, RequestID: reqID.Add(1)}, "", nil, nil, 0, 0, nil, true)
	if err != nil {
		return err
	}
	return s.exchange(tg, req, func(b []byte) (bool, error) {
		m, err := snmp.DecodeV3(b)
		if err != nil || len(m.USM.EngineID) == 0 {
			return false, nil
		}
		s.remote = &remoteEngine{id: m.USM.EngineID, boots: m.USM.Boots, time: m.USM.Time, at: time.Now()}
		return true, nil
	})
}

var oidNotInTimeWindows = snmp.MustOID("1.3.6.1.6.3.15.1.1.2.0")

// inform sends an InformRequest and waits for the receiver's response: the receiver's engine is
// discovered first (and again after a report that it does not know us or our time).
func (s *sender) inform(tg config.Target, user *agent.User, vbs []snmp.VarBind) error {
	for attempt := 0; attempt < 2; attempt++ {
		if s.remote == nil {
			if err := s.discover(tg); err != nil {
				return fmt.Errorf("engine discovery: %w", err)
			}
		}
		r := s.remote
		keys := usm.LocalKeys(user.Auth, user.Priv, user.KuAuth, user.KuPriv, r.id)
		id := reqID.Add(1)
		req, err := encode(snmp.PDU{Type: snmp.InformRequest, RequestID: id, VarBinds: vbs}, user.Name, &keys, r.id, r.boots, r.now(time.Now()), s.engine.ID, true)
		if err != nil {
			return err
		}
		resync := false
		err = s.exchange(tg, req, func(b []byte) (bool, error) {
			m, err := snmp.DecodeV3(b)
			if err != nil || !bytes.Equal(m.USM.EngineID, r.id) {
				return false, nil
			}
			if m.Flags&snmp.FlagAuth != 0 {
				if usm.Verify(keys.Auth, keys.AuthKey, m.Raw, m.AuthAt, m.USM.AuthParams) != nil {
					return false, nil
				}
			}
			data := m.Data
			if m.Encrypted {
				if data, err = usm.Decrypt(keys.PrivKey, m.USM.Boots, m.USM.Time, m.USM.PrivParams, m.Data); err != nil {
					return false, nil
				}
			}
			sp, err := snmp.DecodeScopedPDU(data)
			if err != nil {
				return false, nil
			}
			switch sp.PDU.Type {
			case snmp.Response:
				return sp.PDU.RequestID == id, nil
			case snmp.Report:
				if len(sp.PDU.VarBinds) > 0 && sp.PDU.VarBinds[0].OID.Equal(oidNotInTimeWindows) {
					s.remote = &remoteEngine{id: r.id, boots: m.USM.Boots, time: m.USM.Time, at: time.Now()}
				} else {
					s.remote = nil
				}
				resync = true
				return true, nil
			}
			return false, nil
		})
		if err == nil && !resync {
			return nil
		}
		if err != nil {
			s.remote = nil
			return err
		}
	}
	return errors.New("the receiver refused the inform (wrong user, password or protocol?)")
}
