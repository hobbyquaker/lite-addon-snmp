// Package mibs holds LITE-SNMP-MIB: the template, the rendered module the agent serves for
// download and ships in its package, and the renderer (go generate). The root is filled in from
// one place, so the move to an own enterprise number changes the template's parameters only.
package mibs

import (
	"bytes"
	_ "embed"
	"text/template"
)

//go:generate go run ./gen

//go:embed LITE-SNMP-MIB.txt.tmpl
var tmpl string

// File is the rendered module.
//
//go:embed LITE-SNMP-MIB.txt
var File []byte

// FileName is the module's file name.
const FileName = "LITE-SNMP-MIB.txt"

// Params are the template's parameters.
type Params struct {
	Banner                 string
	RootParent, RootModule string
	RootArc                int
	Updated, Revision      string
	Notifications, Groups  string
	ComplianceGroups       string
}

// Current are the parameters of this release: the provisional root under net-snmp's playpen.
var Current = Params{
	Banner:           "PROVISIONAL root: NET-SNMP-MIB netSnmpPlaypen (1.3.6.1.4.1.8072.9999.9999) 47621, until the move to an own IANA PEN.",
	RootParent:       "netSnmpPlaypen",
	RootModule:       "NET-SNMP-MIB",
	RootArc:          47621,
	Updated:          "202610292300Z",
	Revision:         "0.2.0: the notifications and their objects.",
	Notifications:    notifications,
	Groups:           groups,
	ComplianceGroups: ",\n                           hmNotificationObjectGroup, hmNotificationGroup",
}

// notifications are the 0.2.0 definitions the template inserts after hmStatistics.
const notifications = `
-- hmNotificationObjects: the objects the notifications carry

hmNotificationObjects OBJECT IDENTIFIER ::= { liteSnmpObjects 9 }

hmNotifInterface OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..24))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The interface the notification is about."
    ::= { hmNotificationObjects 1 }

hmNotifAddress OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..32))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The device's address."
    ::= { hmNotificationObjects 2 }

hmNotifKey OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..40))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The service message's datapoint key."
    ::= { hmNotificationObjects 3 }

hmNotifValue OBJECT-TYPE
    SYNTAX      SnmpAdminString
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The service message's value as text."
    ::= { hmNotificationObjects 4 }

hmNotifDeviceType OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..64))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The device's type."
    ::= { hmNotificationObjects 5 }

hmNotifDeviceName OBJECT-TYPE
    SYNTAX      SnmpAdminString
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The device's name."
    ::= { hmNotificationObjects 6 }

hmNotifRooms OBJECT-TYPE
    SYNTAX      SnmpAdminString
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The device's rooms, joined by a comma."
    ::= { hmNotificationObjects 7 }

hmNotifSeverity OBJECT-TYPE
    SYNTAX      INTEGER { info(1), warning(2), error(3) }
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "A Status warning's severity."
    ::= { hmNotificationObjects 8 }

hmNotifText OBJECT-TYPE
    SYNTAX      SnmpAdminString
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "A short text: the warning's id and variant, or the test's words."
    ::= { hmNotificationObjects 9 }

hmNotifThreshold OBJECT-TYPE
    SYNTAX      Gauge32 (0..100)
    UNITS       "percent"
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The duty cycle threshold."
    ::= { hmNotificationObjects 10 }

hmNotifDutyCycle OBJECT-TYPE
    SYNTAX      Gauge32 (0..100)
    UNITS       "percent"
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The radio's duty cycle."
    ::= { hmNotificationObjects 11 }

hmNotifService OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..32))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The interface daemon: rfd, hmipserver, multimacd, hs485d."
    ::= { hmNotificationObjects 12 }

hmNotifWarningId OBJECT-TYPE
    SYNTAX      SnmpAdminString
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The Status warning's id and variant, id/variant."
    ::= { hmNotificationObjects 13 }

hmNotifModule OBJECT-TYPE
    SYNTAX      DisplayString (SIZE (0..64))
    MAX-ACCESS  accessible-for-notify
    STATUS      current
    DESCRIPTION "The radio module's type."
    ::= { hmNotificationObjects 14 }

-- liteSnmpNotifications

liteSnmpNotifications OBJECT IDENTIFIER ::= { liteSnmpMIB 2 }
liteSnmpNotificationPrefix OBJECT IDENTIFIER ::= { liteSnmpNotifications 0 }

hmServiceMessageRaised NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifAddress, hmNotifKey, hmNotifValue,
              hmNotifDeviceType, hmNotifDeviceName, hmNotifRooms }
    STATUS  current
    DESCRIPTION "A service message came up on a device of the rule's selection."
    ::= { liteSnmpNotificationPrefix 1 }

hmServiceMessageCleared NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifAddress, hmNotifKey, hmNotifValue,
              hmNotifDeviceType, hmNotifDeviceName, hmNotifRooms }
    STATUS  current
    DESCRIPTION "A service message went away."
    ::= { liteSnmpNotificationPrefix 2 }

hmInterfaceDisconnected NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifModule }
    STATUS  current
    DESCRIPTION "An interface's radio module is no longer connected."
    ::= { liteSnmpNotificationPrefix 3 }

hmInterfaceConnected NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifModule }
    STATUS  current
    DESCRIPTION "An interface's radio module is connected again."
    ::= { liteSnmpNotificationPrefix 4 }

hmDutyCycleHigh NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifDutyCycle, hmNotifThreshold }
    STATUS  current
    DESCRIPTION
        "The duty cycle reached the threshold in two samples in a row (the
        system samples once a minute)."
    ::= { liteSnmpNotificationPrefix 5 }

hmDutyCycleNormal NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifDutyCycle, hmNotifThreshold }
    STATUS  current
    DESCRIPTION "The duty cycle fell ten points below the threshold."
    ::= { liteSnmpNotificationPrefix 6 }

hmServiceDown NOTIFICATION-TYPE
    OBJECTS { hmNotifService }
    STATUS  current
    DESCRIPTION "An interface daemon stopped running."
    ::= { liteSnmpNotificationPrefix 7 }

hmServiceUp NOTIFICATION-TYPE
    OBJECTS { hmNotifService }
    STATUS  current
    DESCRIPTION "An interface daemon runs again."
    ::= { liteSnmpNotificationPrefix 8 }

hmWarningRaised NOTIFICATION-TYPE
    OBJECTS { hmNotifWarningId, hmNotifSeverity, hmNotifText }
    STATUS  current
    DESCRIPTION "A Status warning came up."
    ::= { liteSnmpNotificationPrefix 9 }

hmWarningCleared NOTIFICATION-TYPE
    OBJECTS { hmNotifWarningId, hmNotifSeverity, hmNotifText }
    STATUS  current
    DESCRIPTION "A Status warning went away."
    ::= { liteSnmpNotificationPrefix 10 }

hmDeviceUnreachable NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifAddress, hmNotifDeviceType, hmNotifDeviceName, hmNotifRooms }
    STATUS  current
    DESCRIPTION "A device of the rule's selection reports UNREACH."
    ::= { liteSnmpNotificationPrefix 11 }

hmDeviceReachable NOTIFICATION-TYPE
    OBJECTS { hmNotifInterface, hmNotifAddress, hmNotifDeviceType, hmNotifDeviceName, hmNotifRooms }
    STATUS  current
    DESCRIPTION "A device of the rule's selection is reachable again."
    ::= { liteSnmpNotificationPrefix 12 }

hmTestNotification NOTIFICATION-TYPE
    OBJECTS { hmNotifText }
    STATUS  current
    DESCRIPTION "Sent by the page's Test button; never an alarm."
    ::= { liteSnmpNotificationPrefix 13 }
`

const groups = `
hmNotificationObjectGroup OBJECT-GROUP
    OBJECTS { hmNotifInterface, hmNotifAddress, hmNotifKey, hmNotifValue, hmNotifDeviceType,
              hmNotifDeviceName, hmNotifRooms, hmNotifSeverity, hmNotifText, hmNotifThreshold,
              hmNotifDutyCycle, hmNotifService, hmNotifWarningId, hmNotifModule }
    STATUS      current
    DESCRIPTION "The objects the notifications carry."
    ::= { liteSnmpGroups 6 }

hmNotificationGroup NOTIFICATION-GROUP
    NOTIFICATIONS { hmServiceMessageRaised, hmServiceMessageCleared, hmInterfaceDisconnected,
                    hmInterfaceConnected, hmDutyCycleHigh, hmDutyCycleNormal, hmServiceDown,
                    hmServiceUp, hmWarningRaised, hmWarningCleared, hmDeviceUnreachable,
                    hmDeviceReachable, hmTestNotification }
    STATUS      current
    DESCRIPTION "The notifications."
    ::= { liteSnmpGroups 7 }
`

// Render renders the template.
func Render(p Params) ([]byte, error) {
	t, err := template.New("mib").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, p); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
