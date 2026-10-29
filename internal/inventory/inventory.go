// Package inventory applies selections to the devices the source keeps: which devices a
// selection puts into the device table, the live count and preview the editor shows, and the
// catalogue the editor browses (the device tree, interfaces, types, keys, rooms, functions).
package inventory

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/litesource"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
)

// KeyIndex maps "<interface>/<device type>/<channel type>" to the channel's VALUES keys, from the
// paramset description cache (firmware and version left aside: the keys of one channel type rarely
// change between firmwares, and the editor only suggests).
type KeyIndex map[string][]string

// NewKeyIndex builds the index.
func NewKeyIndex(ps litesource.ParamsetCache) KeyIndex {
	sets := map[string]map[string]bool{}
	for k, p := range ps {
		parts := strings.Split(k, "/")
		if len(parts) != 6 || parts[5] != "VALUES" {
			continue
		}
		ik := parts[0] + "/" + parts[1] + "/" + parts[4]
		if sets[ik] == nil {
			sets[ik] = map[string]bool{}
		}
		for name := range p {
			sets[ik][name] = true
		}
	}
	out := KeyIndex{}
	for k, s := range sets {
		l := make([]string, 0, len(s))
		for n := range s {
			l = append(l, n)
		}
		sort.Strings(l)
		out[k] = l
	}
	return out
}

// Keys answers a channel's keys.
func (x KeyIndex) Keys(iface, devType, chType string) []string {
	return x[iface+"/"+devType+"/"+chType]
}

// Labels are the names a channel is matched on.
type Labels struct {
	Name, DeviceName string
	Rooms, Functions []string
}

// ChannelLabels are a channel's rooms and functions (its own, else its device's), in lang.
func ChannelLabels(st *source.State, iface, device, channel, lang string) Labels {
	var l Labels
	if st.Names == nil {
		return l
	}
	l.DeviceName = st.Names.Name(iface, device)
	l.Name = st.Names.Name(iface, channel)
	l.Rooms = st.Names.RoomNames(iface, channel, lang)
	if len(l.Rooms) == 0 {
		l.Rooms = st.Names.RoomNames(iface, device, lang)
	}
	l.Functions = st.Names.FunctionNames(iface, channel, lang)
	if len(l.Functions) == 0 {
		l.Functions = st.Names.FunctionNames(iface, device, lang)
	}
	return l
}

// Match is a selection applied to one device: the channels that match and how many datapoints.
type Match struct {
	Channels   []string
	Datapoints int
}

// MatchDevice applies a compiled selection to a device: each channel (channel 0 included) is
// matched once per VALUES key it has (a key criterion means "the channel has such a datapoint"),
// or once without a key when its keys are not known.
func MatchDevice(m *selection.Matcher, st *source.State, keys KeyIndex, d *source.Device, lang string) Match {
	var out Match
	for _, c := range d.Channels {
		lb := ChannelLabels(st, d.Interface, d.Address, c.Address, lang)
		sub := selection.Subject{Kind: selection.KindEvent, Interface: d.Interface, Device: d.Address, Address: c.Address, DeviceType: d.Type, ChannelType: c.Type, Rooms: lb.Rooms, Functions: lb.Functions, Source: "event"}
		ks := keys.Keys(d.Interface, d.Type, c.Type)
		n := 0
		if len(ks) == 0 {
			if m.Match(sub) {
				n = 1
			}
		} else {
			for _, k := range ks {
				sub.Key = k
				if m.Match(sub) {
					n++
				}
			}
		}
		if n > 0 {
			out.Channels = append(out.Channels, c.Address)
			if len(ks) > 0 {
				out.Datapoints += n
			}
		}
	}
	return out
}

// Count is the editor's live count.
type Count struct {
	Devices    int `json:"devices"`
	Channels   int `json:"channels"`
	Datapoints int `json:"datapoints"`
}

// Row is one row of a preview.
type Row struct {
	Interface string   `json:"interface"`
	Address   string   `json:"address"`
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	Rooms     []string `json:"rooms"`
	Channels  int      `json:"channels"`
	// Index is the device table row's index OID suffix (after the column).
	Index string `json:"index,omitempty"`
}

// Preview applies a selection to every device: the count and the first n rows, sorted by
// interface and address.
func Preview(sel selection.Selection, st *source.State, keys KeyIndex, lang string, n int) (Count, []Row) {
	m := selection.New(sel)
	var c Count
	rows := []Row{}
	for _, d := range Sorted(st) {
		mt := MatchDevice(m, st, keys, d, lang)
		if len(mt.Channels) == 0 {
			continue
		}
		c.Devices++
		c.Channels += len(mt.Channels)
		c.Datapoints += mt.Datapoints
		if len(rows) < n {
			r := Row{Interface: d.Interface, Address: d.Address, Type: d.Type, Channels: len(mt.Channels), Rooms: []string{}}
			if st.Names != nil {
				r.Name = st.Names.Name(d.Interface, d.Address)
				if rr := st.Names.RoomNames(d.Interface, d.Address, lang); rr != nil {
					r.Rooms = rr
				}
			}
			rows = append(rows, r)
		}
	}
	return c, rows
}

// Sorted answers the devices by interface and address.
func Sorted(st *source.State) []*source.Device {
	l := make([]*source.Device, 0, len(st.Devices))
	for _, d := range st.Devices {
		l = append(l, d)
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].Interface != l[j].Interface {
			return l[i].Interface < l[j].Interface
		}
		return l[i].Address < l[j].Address
	})
	return l
}

// Includer answers the device table's row test for a selection ("" or a missing one: every
// device). The compiled selection and the key index are rebuilt when the source changes.
type Includer struct {
	sel   *selection.Selection
	m     *selection.Matcher
	lang  string
	keys  KeyIndex
	cache map[string]bool
	gen   uint64
}

// NewIncluder makes the row test.
func NewIncluder(sel *selection.Selection, lang string) *Includer {
	in := &Includer{sel: sel, lang: lang}
	if sel != nil {
		in.m = selection.New(*sel)
	}
	return in
}

// Include is the test; call it with the state's generation so the per-device answers are cached
// for one generation.
func (in *Includer) Include(st *source.State, d *source.Device, gen uint64) bool {
	if in.m == nil {
		return true
	}
	if in.cache == nil || in.gen != gen {
		in.cache, in.gen = map[string]bool{}, gen
		in.keys = NewKeyIndex(st.Paramsets)
	}
	k := d.Interface + "/" + d.Address
	if v, ok := in.cache[k]; ok {
		return v
	}
	v := len(MatchDevice(in.m, st, in.keys, d, in.lang).Channels) > 0
	in.cache[k] = v
	return v
}

// The editor's inventory, in lite-addon-forwarder's shape (its SelectionEditor reads it).

// CatalogChannel is one channel in the editor's tree.
type CatalogChannel struct {
	Address   string   `json:"address"`
	Index     int      `json:"index"`
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	Rooms     []string `json:"rooms"`
	Functions []string `json:"functions"`
	Keys      []string `json:"keys"`
}

// CatalogDevice is one device in the editor's tree.
type CatalogDevice struct {
	Interface string           `json:"interface"`
	Address   string           `json:"address"`
	Type      string           `json:"type"`
	Name      string           `json:"name"`
	Rooms     []string         `json:"rooms"`
	Functions []string         `json:"functions"`
	Channels  []CatalogChannel `json:"channels"`
}

// Counted is a name with how often it occurs.
type Counted struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// CatalogInterface is one interface process.
type CatalogInterface struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Running  bool   `json:"running"`
	Devices  int    `json:"devices"`
}

// Catalog is what the selection editor offers.
type Catalog struct {
	Interfaces   []CatalogInterface `json:"interfaces"`
	Devices      []CatalogDevice    `json:"devices"`
	Rooms        []string           `json:"rooms"`
	Functions    []string           `json:"functions"`
	DeviceTypes  []Counted          `json:"device_types"`
	ChannelTypes []Counted          `json:"channel_types"`
	Keys         []Counted          `json:"keys"`
	Datapoints   int                `json:"datapoints"`
	UpdatedAt    time.Time          `json:"updated_at"`
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func counted(m map[string]int) []Counted {
	out := []Counted{}
	for k, n := range m {
		if k != "" {
			out = append(out, Counted{k, n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// BuildCatalog builds the editor's inventory.
func BuildCatalog(st *source.State, lang string) Catalog {
	keys := NewKeyIndex(st.Paramsets)
	dt, ct, kc := map[string]int{}, map[string]int{}, map[string]int{}
	rooms, funcs := map[string]bool{}, map[string]bool{}
	perIf := map[string]int{}
	c := Catalog{Devices: []CatalogDevice{}, Interfaces: []CatalogInterface{}, UpdatedAt: time.Now()}
	for _, d := range Sorted(st) {
		cd := CatalogDevice{Interface: d.Interface, Address: d.Address, Type: d.Type, Channels: []CatalogChannel{}, Rooms: []string{}, Functions: []string{}}
		perIf[d.Interface]++
		dt[d.Type]++
		if st.Names != nil {
			cd.Name = st.Names.Name(d.Interface, d.Address)
			cd.Rooms = nonNil(st.Names.RoomNames(d.Interface, d.Address, lang))
			cd.Functions = nonNil(st.Names.FunctionNames(d.Interface, d.Address, lang))
		}
		for _, ch := range d.Channels {
			lb := ChannelLabels(st, d.Interface, d.Address, ch.Address, lang)
			ks := nonNil(keys.Keys(d.Interface, d.Type, ch.Type))
			cd.Channels = append(cd.Channels, CatalogChannel{Address: ch.Address, Index: channelIndex(ch.Address), Type: ch.Type, Name: lb.Name, Rooms: nonNil(lb.Rooms), Functions: nonNil(lb.Functions), Keys: ks})
			ct[ch.Type]++
			for _, k := range ks {
				kc[k]++
			}
			c.Datapoints += len(ks)
			for _, r := range lb.Rooms {
				rooms[r] = true
			}
			for _, f := range lb.Functions {
				funcs[f] = true
			}
		}
		c.Devices = append(c.Devices, cd)
	}
	names := make([]string, 0, len(st.Interfaces))
	for n := range st.Interfaces {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		i := st.Interfaces[n]
		c.Interfaces = append(c.Interfaces, CatalogInterface{Name: n, Protocol: i.Protocol, Running: i.Running, Devices: perIf[n]})
	}
	// rooms and functions nobody is in yet are offered too
	if st.Names != nil && st.Names.Snapshot() != nil {
		snap := st.Names.Snapshot()
		for enum, set := range map[string]map[string]bool{"room": rooms, "function": funcs} {
			var walk func(prefix string, nodes []litesource.MetaNode)
			walk = func(prefix string, nodes []litesource.MetaNode) {
				for _, n := range nodes {
					p := prefix + "/" + n.ID
					set[snap.NodeName(p, lang)] = true
					walk(p, n.Children)
				}
			}
			walk(enum, snap.Enums[enum].Tree)
		}
	}
	list := func(m map[string]bool) []string {
		out := []string{}
		for v := range m {
			if v != "" {
				out = append(out, v)
			}
		}
		sort.Strings(out)
		return out
	}
	c.Rooms, c.Functions = list(rooms), list(funcs)
	c.DeviceTypes, c.ChannelTypes, c.Keys = counted(dt), counted(ct), counted(kc)
	return c
}

func channelIndex(a string) int {
	_, n, _ := strings.Cut(a, ":")
	v, _ := strconv.Atoi(n)
	return v
}
