package agent

import (
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/mib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
)

var (
	oidSnmpGroup = snmp.MustOID("1.3.6.1.2.1.11")
)

// Register adds the agent's own objects to the tree: SNMPv2-MIB's snmp group, the engine
// (SNMP-FRAMEWORK-MIB), the message processing statistics (SNMP-MPD-MIB) and usmStats
// (SNMP-USER-BASED-SM-MIB). snmpEnableAuthenTraps answers what authTraps says.
func (a *Agent) Register(t *mib.Tree, authTraps func() bool) {
	t.Register(mib.FromFunc(mib.Func{OID: oidSnmpGroup, Collect: func() []snmp.VarBind {
		g := oidSnmpGroup
		en := int64(2)
		if authTraps != nil && authTraps() {
			en = 1
		}
		c := &a.C
		return []snmp.VarBind{
			{OID: g.Append(1, 0), Value: snmp.Counter32(c.InPkts.Load())},
			{OID: g.Append(3, 0), Value: snmp.Counter32(c.InBadVersions.Load())},
			{OID: g.Append(4, 0), Value: snmp.Counter32(c.InBadCommunityNames.Load())},
			{OID: g.Append(5, 0), Value: snmp.Counter32(c.InBadCommunityUses.Load())},
			{OID: g.Append(6, 0), Value: snmp.Counter32(c.InASNParseErrs.Load())},
			{OID: g.Append(30, 0), Value: snmp.Integer(en)},
			{OID: g.Append(31, 0), Value: snmp.Counter32(c.SilentDrops.Load())},
			{OID: g.Append(32, 0), Value: snmp.Counter32(0)},
		}
	}}))
	t.Register(mib.FromFunc(mib.Func{OID: oidSnmpModules, Collect: func() []snmp.VarBind {
		e := a.o.Engine
		c := &a.C
		eng := snmp.MustOID("1.3.6.1.6.3.10.2.1")
		mpd := snmp.MustOID("1.3.6.1.6.3.11.2.1")
		us := snmp.MustOID("1.3.6.1.6.3.15.1.1")
		return []snmp.VarBind{
			{OID: eng.Append(1, 0), Value: snmp.Bytes(e.ID)},
			{OID: eng.Append(2, 0), Value: snmp.Integer(e.Boots)},
			{OID: eng.Append(3, 0), Value: snmp.Integer(e.Time(time.Now()))},
			{OID: eng.Append(4, 0), Value: snmp.Integer(65507)},
			{OID: mpd.Append(1, 0), Value: snmp.Counter32(c.UnknownSecurityModels.Load())},
			{OID: mpd.Append(2, 0), Value: snmp.Counter32(c.InvalidMsgs.Load())},
			{OID: mpd.Append(3, 0), Value: snmp.Counter32(c.UnknownPDUHandlers.Load())},
			{OID: us.Append(1, 0), Value: snmp.Counter32(c.UnsupportedSecLevels.Load())},
			{OID: us.Append(2, 0), Value: snmp.Counter32(c.NotInTimeWindows.Load())},
			{OID: us.Append(3, 0), Value: snmp.Counter32(c.UnknownUserNames.Load())},
			{OID: us.Append(4, 0), Value: snmp.Counter32(c.UnknownEngineIDs.Load())},
			{OID: us.Append(5, 0), Value: snmp.Counter32(c.WrongDigests.Load())},
			{OID: us.Append(6, 0), Value: snmp.Counter32(c.DecryptionErrors.Load())},
		}
	}}))
}
