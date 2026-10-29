// Package trap is the notification engine: it watches the source's state, turns its changes
// into the LITE-SNMP-MIB notifications the rules switch on (service messages, interfaces, duty
// cycle, services, Status warnings, unreachable devices), and sends them to the targets as v2c
// traps, v3 traps or v3 informs, each target with a bounded queue, a rate limit and, for informs,
// retries. A restart is no flood: the first complete state is the baseline, only what changes
// after it is sent.
package trap

import (
	"github.com/hobbyquaker/lite-addon-snmp/internal/hmmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
)

// The notification objects (R.1.9, accessible-for-notify), sent with the instance .0.
var (
	objInterface  = hmmib.NotifObjects.Append(1)
	objAddress    = hmmib.NotifObjects.Append(2)
	objKey        = hmmib.NotifObjects.Append(3)
	objValue      = hmmib.NotifObjects.Append(4)
	objDeviceType = hmmib.NotifObjects.Append(5)
	objDeviceName = hmmib.NotifObjects.Append(6)
	objRooms      = hmmib.NotifObjects.Append(7)
	objSeverity   = hmmib.NotifObjects.Append(8)
	objText       = hmmib.NotifObjects.Append(9)
	objThreshold  = hmmib.NotifObjects.Append(10)
	objDutyCycle  = hmmib.NotifObjects.Append(11)
	objService    = hmmib.NotifObjects.Append(12)
	objWarningID  = hmmib.NotifObjects.Append(13)
	objModule     = hmmib.NotifObjects.Append(14)
)

// The notifications (R.2.0.n).
var (
	ServiceMessageRaised  = hmmib.Notifications.Append(1)
	ServiceMessageCleared = hmmib.Notifications.Append(2)
	InterfaceDisconnected = hmmib.Notifications.Append(3)
	InterfaceConnected    = hmmib.Notifications.Append(4)
	DutyCycleHigh         = hmmib.Notifications.Append(5)
	DutyCycleNormal       = hmmib.Notifications.Append(6)
	ServiceDown           = hmmib.Notifications.Append(7)
	ServiceUp             = hmmib.Notifications.Append(8)
	WarningRaised         = hmmib.Notifications.Append(9)
	WarningCleared        = hmmib.Notifications.Append(10)
	DeviceUnreachable     = hmmib.Notifications.Append(11)
	DeviceReachable       = hmmib.Notifications.Append(12)
	TestNotification      = hmmib.Notifications.Append(13)

	// SNMPv2-MIB's generic traps
	ColdStart             = snmp.MustOID("1.3.6.1.6.3.1.1.5.1")
	AuthenticationFailure = snmp.MustOID("1.3.6.1.6.3.1.1.5.5")

	oidSysUpTime   = snmp.MustOID("1.3.6.1.2.1.1.3.0")
	oidSnmpTrapOID = snmp.MustOID("1.3.6.1.6.3.1.1.4.1.0")
)

// Names are the notifications' MIB names, for the status page.
var Names = map[string]string{
	ServiceMessageRaised.String():  "hmServiceMessageRaised",
	ServiceMessageCleared.String(): "hmServiceMessageCleared",
	InterfaceDisconnected.String(): "hmInterfaceDisconnected",
	InterfaceConnected.String():    "hmInterfaceConnected",
	DutyCycleHigh.String():         "hmDutyCycleHigh",
	DutyCycleNormal.String():       "hmDutyCycleNormal",
	ServiceDown.String():           "hmServiceDown",
	ServiceUp.String():             "hmServiceUp",
	WarningRaised.String():         "hmWarningRaised",
	WarningCleared.String():        "hmWarningCleared",
	DeviceUnreachable.String():     "hmDeviceUnreachable",
	DeviceReachable.String():       "hmDeviceReachable",
	TestNotification.String():      "hmTestNotification",
	ColdStart.String():             "coldStart",
	AuthenticationFailure.String(): "authenticationFailure",
}

// Notification is one notification before it is addressed: its OID, its objects, the rule it
// belongs to ("" for coldStart, authenticationFailure and the test) and a short text for the page.
type Notification struct {
	OID  snmp.OID
	Rule string
	Vars []snmp.VarBind
	Text string
}

func v(o snmp.OID, val snmp.Value) snmp.VarBind { return snmp.VarBind{OID: o.Append(0), Value: val} }

// VarBinds are the notification's bindings as SNMPv2-Trap-PDU carries them: sysUpTime.0,
// snmpTrapOID.0, then its objects.
func (n Notification) VarBinds(uptime uint64) []snmp.VarBind {
	out := []snmp.VarBind{{OID: oidSysUpTime, Value: snmp.TimeTicks(uptime)}, {OID: oidSnmpTrapOID, Value: snmp.ObjectID(n.OID)}}
	return append(out, n.Vars...)
}

// Severity is hmNotifSeverity: info(1), warning(2), error(3).
func Severity(s string) int64 {
	switch s {
	case "error":
		return 3
	case "warning":
		return 2
	}
	return 1
}
