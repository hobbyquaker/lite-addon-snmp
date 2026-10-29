package mibs

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Object is one definition of the module.
type Object struct {
	Name string
	OID  []uint32
	// Leaf is an OBJECT-TYPE that carries a value: a scalar or a column, not a table or an entry.
	Leaf   bool
	Access string
	Kind   string // OBJECT-TYPE, NOTIFICATION-TYPE, OBJECT IDENTIFIER, …
}

var defRE = regexp.MustCompile(`(?m)^([a-z][A-Za-z0-9-]*)\s+(OBJECT-TYPE|OBJECT IDENTIFIER|OBJECT-IDENTITY|NOTIFICATION-TYPE|MODULE-IDENTITY|MODULE-COMPLIANCE|OBJECT-GROUP|NOTIFICATION-GROUP)\b([\s\S]*?)::=\s*\{\s*([A-Za-z0-9-]+)\s+(\d+)\s*\}`)

// Index resolves every definition of the module to its OID, the module identity's parent at root.
func Index(text []byte, root []uint32) (map[string]Object, error) {
	defs := map[string]Object{}
	parents := map[string]string{}
	arcs := map[string]uint32{}
	for _, m := range defRE.FindAllStringSubmatch(string(text), -1) {
		name, kind, body, parent := m[1], m[2], m[3], m[4]
		n, _ := strconv.ParseUint(m[5], 10, 32)
		o := Object{Name: name, Kind: kind}
		if kind == "OBJECT-TYPE" {
			acc := regexp.MustCompile(`MAX-ACCESS\s+(\S+)`).FindStringSubmatch(body)
			if acc != nil {
				o.Access = acc[1]
			}
			syn := regexp.MustCompile(`SYNTAX\s+(.+)`).FindStringSubmatch(body)
			o.Leaf = o.Access != "not-accessible" && (syn == nil || !strings.HasPrefix(strings.TrimSpace(syn[1]), "SEQUENCE OF"))
		}
		if kind == "MODULE-IDENTITY" {
			o.OID = append([]uint32(nil), root...)
			defs[name] = o
			continue
		}
		defs[name] = o
		parents[name], arcs[name] = parent, uint32(n)
	}
	var resolve func(name string, depth int) ([]uint32, error)
	resolve = func(name string, depth int) ([]uint32, error) {
		d, ok := defs[name]
		if !ok {
			return nil, fmt.Errorf("unknown parent %q", name)
		}
		if d.OID != nil {
			return d.OID, nil
		}
		if depth > 64 {
			return nil, fmt.Errorf("a cycle at %q", name)
		}
		p, err := resolve(parents[name], depth+1)
		if err != nil {
			return nil, err
		}
		d.OID = append(append([]uint32(nil), p...), arcs[name])
		defs[name] = d
		return d.OID, nil
	}
	for name := range defs {
		if _, err := resolve(name, 0); err != nil {
			return nil, err
		}
	}
	return defs, nil
}
