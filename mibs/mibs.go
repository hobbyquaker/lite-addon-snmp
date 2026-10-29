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
	Banner:     "PROVISIONAL root: NET-SNMP-MIB netSnmpPlaypen (1.3.6.1.4.1.8072.9999.9999) 47621, until the move to an own IANA PEN.",
	RootParent: "netSnmpPlaypen",
	RootModule: "NET-SNMP-MIB",
	RootArc:    47621,
	Updated:    "202610290000Z",
	Revision:   "0.1.0: the system, interface, service message, device and statistics objects.",
}

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
