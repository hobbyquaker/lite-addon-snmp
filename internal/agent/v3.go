package agent

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

// The usmStats and snmpMPDStats objects a report carries (RFC 3414 §5, RFC 3412 §5).
var (
	oidUnsupportedSecLevels = snmp.MustOID("1.3.6.1.6.3.15.1.1.1.0")
	oidNotInTimeWindows     = snmp.MustOID("1.3.6.1.6.3.15.1.1.2.0")
	oidUnknownUserNames     = snmp.MustOID("1.3.6.1.6.3.15.1.1.3.0")
	oidUnknownEngineIDs     = snmp.MustOID("1.3.6.1.6.3.15.1.1.4.0")
	oidWrongDigests         = snmp.MustOID("1.3.6.1.6.3.15.1.1.5.0")
	oidDecryptionErrors     = snmp.MustOID("1.3.6.1.6.3.15.1.1.6.0")
)

// timeWindow is RFC 3414 §3.2's 150 seconds.
const timeWindow = 150

func (a *Agent) handleV3(pkt []byte, addr netip.Addr, now time.Time) []byte {
	m, err := snmp.DecodeV3(pkt)
	if err != nil {
		a.C.InASNParseErrs.Add(1)
		a.C.InvalidMsgs.Add(1)
		return nil
	}
	reportable := m.Flags&snmp.FlagReportable != 0
	if m.SecurityModel != snmp.SecurityModelUSM {
		a.C.UnknownSecurityModels.Add(1)
		return nil
	}
	if m.Flags&snmp.FlagPriv != 0 && m.Flags&snmp.FlagAuth == 0 {
		a.C.InvalidMsgs.Add(1)
		return nil
	}
	eng := a.o.Engine
	// plaintext request id, for the reports that can carry it
	reqID := int32(0)
	if !m.Encrypted {
		if s, err := snmp.DecodeScopedPDU(m.Data); err == nil {
			reqID = s.PDU.RequestID
		}
	}
	report := func(o snmp.OID, n uint64, keys *usm.Keys) []byte {
		if !reportable {
			return nil
		}
		return a.encodeV3(m, snmp.PDU{Type: snmp.Report, RequestID: reqID, VarBinds: []snmp.VarBind{{OID: o, Value: snmp.Counter32(n)}}}, keys, false, now)
	}
	// discovery, or another engine's id
	if !bytes.Equal(m.USM.EngineID, eng.ID) {
		n := a.C.UnknownEngineIDs.Add(1)
		return report(oidUnknownEngineIDs, n, nil)
	}
	a.mu.RLock()
	uk := a.users[string(m.USM.UserName)]
	a.mu.RUnlock()
	if uk == nil {
		n := a.C.UnknownUserNames.Add(1)
		a.authFailed(addr, now, "unknown user")
		return report(oidUnknownUserNames, n, nil)
	}
	// every user is authPriv: a request below it is refused
	if m.Flags&(snmp.FlagAuth|snmp.FlagPriv) != snmp.FlagAuth|snmp.FlagPriv {
		n := a.C.UnsupportedSecLevels.Add(1)
		return report(oidUnsupportedSecLevels, n, nil)
	}
	keys := uk.keys
	if err := usm.Verify(keys.Auth, keys.AuthKey, m.Raw, m.AuthAt, m.USM.AuthParams); err != nil {
		n := a.C.WrongDigests.Add(1)
		a.authFailed(addr, now, "wrong digest for user "+uk.u.Name)
		return report(oidWrongDigests, n, nil)
	}
	et := eng.Time(now)
	if m.USM.Boots != eng.Boots || eng.Boots == 2147483647 || abs(m.USM.Time-et) > timeWindow {
		n := a.C.NotInTimeWindows.Add(1)
		if !reportable {
			return nil
		}
		// authenticated, not encrypted (RFC 3414 §3.2 step 7)
		auth := keys
		auth.PrivKey = nil
		return a.encodeV3(m, snmp.PDU{Type: snmp.Report, RequestID: reqID, VarBinds: []snmp.VarBind{{OID: oidNotInTimeWindows, Value: snmp.Counter32(n)}}}, &auth, false, now)
	}
	if !m.Encrypted {
		n := a.C.UnsupportedSecLevels.Add(1)
		return report(oidUnsupportedSecLevels, n, nil)
	}
	plain, err := usm.Decrypt(keys.PrivKey, m.USM.Boots, m.USM.Time, m.USM.PrivParams, m.Data)
	if err != nil {
		n := a.C.DecryptionErrors.Add(1)
		return report(oidDecryptionErrors, n, nil)
	}
	sp, err := snmp.DecodeScopedPDU(plain)
	if err != nil {
		n := a.C.DecryptionErrors.Add(1)
		return report(oidDecryptionErrors, n, nil)
	}
	limit := int(min(m.MaxSize, 65507))
	bulkLimit := min(limit, a.o.MaxBulkSize)
	// the header, the security parameters and the cipher's framing
	overhead := 160 + len(m.USM.UserName) + len(eng.ID)
	maxPDU := limit - overhead
	if sp.PDU.Type == snmp.GetBulkRequest {
		maxPDU = bulkLimit - overhead
	}
	resp, ok := a.process(sp.PDU, uk.u.View, false, maxPDU)
	if !ok {
		return nil
	}
	a.answered(now, addr, "v3", uk.u.Name, sp.PDU.Type)
	return a.encodeV3(m, resp, &keys, true, now)
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// encodeV3 answers a request message: the same msgID, our engine's parameters, the user and the
// security level given by keys (nil: noAuthNoPriv; without a privacy key: authNoPriv).
func (a *Agent) encodeV3(req *snmp.V3Message, pdu snmp.PDU, keys *usm.Keys, priv bool, now time.Time) []byte {
	eng := a.o.Engine
	sp := snmp.ScopedPDU{ContextEngineID: eng.ID, PDU: pdu}
	m := snmp.V3Message{MsgID: req.MsgID, MaxSize: 65507, SecurityModel: snmp.SecurityModelUSM}
	m.USM = snmp.USMParams{EngineID: eng.ID, Boots: eng.Boots, Time: eng.Time(now), UserName: req.USM.UserName}
	data := sp.Encode()
	encrypted := false
	if keys != nil {
		m.Flags |= snmp.FlagAuth
		m.USM.AuthParams = make([]byte, keys.Auth.DigestLen())
		if priv && keys.PrivKey != nil {
			m.Flags |= snmp.FlagPriv
			salt := make([]byte, 8)
			binary.BigEndian.PutUint64(salt, a.salt.Add(1))
			m.USM.PrivParams = salt
			ct, err := usm.Encrypt(keys.PrivKey, m.USM.Boots, m.USM.Time, salt, data)
			if err != nil {
				return nil
			}
			data, encrypted = ct, true
		}
	}
	out, at := snmp.EncodeV3(m, data, encrypted)
	if keys != nil {
		usm.Sign(keys.Auth, keys.AuthKey, out, at)
	}
	return out
}
