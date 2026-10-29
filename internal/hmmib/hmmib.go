// Package hmmib answers LITE-SNMP-MIB, the agent's own subtree: the system's identity and health,
// the interface table, the service messages, the device table and the statistics, read from the
// source's memory. Every table that names Homematic things is indexed by strings (interface,
// address, key), so a row keeps its OID across restarts and re-pairing.
package hmmib

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/hostmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/mib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
)

// Root is the provisional root: net-snmp's playpen (NET-SNMP-MIB netSnmpPlaypen,
// 1.3.6.1.4.1.8072.9999.9999) with one sub-arc of our own. It moves to an IANA Private
// Enterprise Number; nothing else in the code names it.
var Root = snmp.MustOID("1.3.6.1.4.1.8072.9999.9999.47621")

// The subtrees.
var (
	Objects       = Root.Append(1)
	System        = Objects.Append(1)
	InterfaceTbl  = Objects.Append(2)
	ServiceMsgs   = Objects.Append(3)
	DeviceTbl     = Objects.Append(4)
	Statistics    = Objects.Append(5)
	NotifObjects  = Objects.Append(9)
	Notifications = Root.Append(2, 0)
	Products      = Root.Append(4)
	// AgentOID is sysObjectID.
	AgentOID = Products.Append(1)
)

// Tri is the MIB's HmTriState: true(1), false(2), unknown(3).
func Tri(known, v bool) snmp.Value {
	switch {
	case !known:
		return snmp.Integer(3)
	case v:
		return snmp.Integer(1)
	}
	return snmp.Integer(2)
}

// Counters are the agent's statistics the tree reports.
type Counters interface {
	Requests() uint64
	AuthFailures() uint64
	TrapsSent() uint64
	TrapsFailed() uint64
}

// Options configure the module.
type Options struct {
	Source *source.Source
	// IncludeDevice decides the device table's rows (the table's selection).
	IncludeDevice func(st *source.State, d *source.Device) bool
	Counters      Counters
	AgentVersion  string
	// Lang is the language of room and function names (de, en).
	Lang func() string
	Now  func() time.Time
}

// Module is the tree's module.
type Module struct {
	o       Options
	started time.Time
}

// New makes the module.
func New(o Options) *Module {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Lang == nil {
		o.Lang = func() string { return "de" }
	}
	return &Module{o: o, started: o.Now()}
}

// Root implements mib.Module.
func (m *Module) Root() snmp.OID { return Root }

// TTL implements mib.Module.
func (m *Module) TTL() time.Duration { return 2 * time.Second }

var _ mib.Module = (*Module)(nil)

type vbs []snmp.VarBind

func (l *vbs) add(o snmp.OID, v snmp.Value) { *l = append(*l, snmp.VarBind{OID: o, Value: v}) }

// Collect implements mib.Module.
func (m *Module) Collect() []snmp.VarBind {
	var l vbs
	m.o.Source.View(func(st *source.State) {
		m.system(&l, st)
		m.interfaces(&l, st)
		m.messages(&l, st)
		m.devices(&l, st)
		m.statistics(&l, st)
	})
	return l
}

// Health is hmSysHealth's verdict: ok(1), degraded(2), unknown(3).
func Health(st *source.State, now time.Time) int64 {
	if !st.SysReady || now.Sub(st.SysAt) > 5*time.Minute {
		return 3
	}
	if !st.Health.OK || !st.StreamConnected {
		return 2
	}
	for _, w := range st.Warnings {
		if w.Severity == "error" {
			return 2
		}
	}
	for _, i := range st.Interfaces {
		if i.HasRadio && !i.Connected {
			return 2
		}
	}
	return 1
}

func (m *Module) system(l *vbs, st *source.State) {
	now := m.o.Now()
	s := System
	warn, errs := 0, 0
	for _, w := range st.Warnings {
		switch w.Severity {
		case "error":
			errs++
			warn++
		case "warning":
			warn++
		}
	}
	age := uint64(math.MaxUint32)
	if !st.SysAt.IsZero() {
		age = uint64(now.Sub(st.SysAt) / time.Second)
	}
	rev := st.Health.Meta.Revision
	if st.Names != nil && st.Names.Revision > rev {
		rev = st.Names.Revision
	}
	l.add(s.Append(1, 0), snmp.String("openccu-lite"))
	l.add(s.Append(2, 0), snmp.String(st.Health.Release))
	l.add(s.Append(3, 0), snmp.String(st.Health.Base))
	l.add(s.Append(4, 0), snmp.String(st.Health.Commit))
	l.add(s.Append(5, 0), snmp.Integer(Health(st, now)))
	l.add(s.Append(6, 0), snmp.Gauge32(uint64(warn)))
	l.add(s.Append(7, 0), snmp.Gauge32(uint64(errs)))
	l.add(s.Append(8, 0), snmp.Counter64(uint64(max(rev, 0))))
	l.add(s.Append(9, 0), snmp.String(m.o.AgentVersion))
	l.add(s.Append(10, 0), snmp.Gauge32(age))
}

// Protocol is hmIfProtocol: bidcos(1) hmip(2) wired(3) virtual(4) other(5).
func Protocol(name string) int64 {
	switch name {
	case "BidCos-RF":
		return 1
	case "HmIP-RF":
		return 2
	case "BidCos-Wired":
		return 3
	case "VirtualDevices":
		return 4
	}
	return 5
}

// DeviceFacts are a device's service datapoints, as the device table and the counts read them.
type DeviceFacts struct {
	ReachKnown, Reachable bool
	LowBatKnown, LowBat   bool
	PendingKnown, Pending bool
	DutyKnown, Duty       bool
	RssiDevice, RssiPeer  int64
	VoltageMV             int64
	ServiceMessages       int
}

func boolOf(raw json.RawMessage) (known, v bool) {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "true", "1":
		return true, true
	case "false", "0":
		return true, false
	}
	return false, false
}

func numOf(raw json.RawMessage) (float64, bool) {
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return 0, false
	}
	return f, true
}

// Facts reads a device's facts from the state.
func Facts(st *source.State, d *source.Device) DeviceFacts {
	f := DeviceFacts{VoltageMV: -1}
	ch0 := d.Interface + "/" + d.Address + ":0/"
	if v, ok := st.Values[ch0+"UNREACH"]; ok {
		k, u := boolOf(v.Raw)
		f.ReachKnown, f.Reachable = k, !u
	}
	for _, key := range []string{"LOWBAT", "LOW_BAT"} {
		if v, ok := st.Values[ch0+key]; ok {
			k, b := boolOf(v.Raw)
			f.LowBatKnown, f.LowBat = k, b || f.LowBat
		}
	}
	if v, ok := st.Values[ch0+"CONFIG_PENDING"]; ok {
		f.PendingKnown, f.Pending = boolOf(v.Raw)
	}
	if v, ok := st.Values[ch0+"DUTY_CYCLE"]; ok {
		f.DutyKnown, f.Duty = boolOf(v.Raw)
	}
	if v, ok := st.Values[ch0+"RSSI_DEVICE"]; ok {
		if n, ok := numOf(v.Raw); ok {
			f.RssiDevice = int64(n)
		}
	}
	if v, ok := st.Values[ch0+"RSSI_PEER"]; ok {
		if n, ok := numOf(v.Raw); ok {
			f.RssiPeer = int64(n)
		}
	}
	if v, ok := st.Values[ch0+"OPERATING_VOLTAGE"]; ok {
		if n, ok := numOf(v.Raw); ok {
			f.VoltageMV = int64(math.Round(n * 1000))
		}
	}
	for _, sm := range st.ServiceMessages {
		if sm.Interface == d.Interface && source.DeviceOf(sm.Address) == d.Address {
			f.ServiceMessages++
		}
	}
	return f
}

func (m *Module) interfaces(l *vbs, st *source.State) {
	names := make([]string, 0, len(st.Interfaces))
	for n := range st.Interfaces {
		names = append(names, n)
	}
	sort.Strings(names)
	type counts struct{ devices, unreach, lowbat, sm int }
	c := map[string]*counts{}
	for _, n := range names {
		c[n] = &counts{}
	}
	for _, d := range st.Devices {
		x := c[d.Interface]
		if x == nil {
			continue
		}
		x.devices++
		f := Facts(st, d)
		if f.ReachKnown && !f.Reachable {
			x.unreach++
		}
		if f.LowBat {
			x.lowbat++
		}
	}
	for _, sm := range st.ServiceMessages {
		if x := c[sm.Interface]; x != nil {
			x.sm++
		}
	}
	now := m.o.Now()
	e := InterfaceTbl.Append(1)
	for _, n := range names {
		i := st.Interfaces[n]
		idx := snmp.StringIndex(n)
		col := func(c uint32) snmp.OID { return e.Append(c).Append(idx...) }
		age := int64(-1)
		if !i.LastEvent.IsZero() {
			age = int64(now.Sub(i.LastEvent) / time.Second)
		}
		dc, thr := uint64(0), uint64(0)
		if i.HasRadio {
			dc, thr = uint64(max(i.DutyCycle, 0)), uint64(max(i.DCThreshold, 0))
		}
		l.add(col(2), snmp.Integer(Protocol(n)))
		l.add(col(3), snmp.Truth(i.Running))
		l.add(col(4), Tri(i.HasRadio, i.Connected))
		l.add(col(5), snmp.Gauge32(dc))
		l.add(col(6), snmp.Integer32(int64(i.CarrierSense)))
		l.add(col(7), snmp.Gauge32(thr))
		l.add(col(8), snmp.String(i.Module))
		l.add(col(9), snmp.String(i.Firmware))
		l.add(col(10), snmp.String(i.Address))
		l.add(col(11), snmp.Gauge32(uint64(c[n].devices)))
		l.add(col(12), snmp.Gauge32(uint64(c[n].unreach)))
		l.add(col(13), snmp.Gauge32(uint64(c[n].lowbat)))
		l.add(col(14), snmp.Gauge32(uint64(c[n].sm)))
		l.add(col(15), snmp.Counter64(i.Events))
		l.add(col(16), snmp.Integer32(age))
		l.add(col(17), snmp.TimeTicks(0))
	}
}

// ValueText renders a service message's value: true as "true", numbers as they are, strings
// unquoted.
func ValueText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

func (m *Module) messages(l *vbs, st *source.State) {
	s := ServiceMsgs
	l.add(s.Append(1, 0), snmp.Gauge32(uint64(len(st.ServiceMessages))))
	types := map[string]int{}
	for _, sm := range st.ServiceMessages {
		types[sm.Key]++
	}
	for k, n := range types {
		l.add(s.Append(2, 1, 2).Append(snmp.StringIndex(k)...), snmp.Gauge32(uint64(n)))
	}
	lang := m.o.Lang()
	for _, sm := range st.ServiceMessages {
		idx := snmp.StringsIndex(sm.Interface, sm.Address, sm.Key)
		col := func(c uint32) snmp.OID { return s.Append(3, 1, c).Append(idx...) }
		dev := source.DeviceOf(sm.Address)
		name := sm.Name
		if name == "" && st.Names != nil {
			name = st.Names.Name(sm.Interface, dev)
		}
		var rooms []string
		if st.Names != nil {
			rooms = st.Names.RoomNames(sm.Interface, dev, lang)
		}
		if len(rooms) == 0 {
			rooms = sm.EnumNames
		}
		seen := int64(1)
		if sm.Seen == "start" {
			seen = 2
		}
		l.add(col(4), snmp.String(ValueText(sm.Value)))
		l.add(col(5), snmp.Bytes(hostmib.DateAndTime(sm.Since)))
		l.add(col(6), snmp.String(sm.Type))
		l.add(col(7), snmp.String(name))
		l.add(col(8), snmp.String(strings.Join(rooms, ", ")))
		l.add(col(9), snmp.Integer(seen))
	}
}

func (m *Module) devices(l *vbs, st *source.State) {
	now := m.o.Now()
	lang := m.o.Lang()
	e := DeviceTbl.Append(1)
	for _, d := range st.Devices {
		if m.o.IncludeDevice != nil && !m.o.IncludeDevice(st, d) {
			continue
		}
		idx := snmp.StringsIndex(d.Interface, d.Address)
		col := func(c uint32) snmp.OID { return e.Append(c).Append(idx...) }
		f := Facts(st, d)
		var name string
		var rooms, funcs []string
		if st.Names != nil {
			name = st.Names.Name(d.Interface, d.Address)
			rooms = st.Names.RoomNames(d.Interface, d.Address, lang)
			funcs = st.Names.FunctionNames(d.Interface, d.Address, lang)
			for _, c := range d.Channels {
				rooms = appendNew(rooms, st.Names.RoomNames(d.Interface, c.Address, lang)...)
				funcs = appendNew(funcs, st.Names.FunctionNames(d.Interface, c.Address, lang)...)
			}
		}
		age := int64(-1)
		if !d.LastSeen.IsZero() {
			age = int64(now.Sub(d.LastSeen) / time.Second)
		}
		fw := d.Firmware
		if fw == "" && d.Version > 0 {
			fw = strconv.Itoa(d.Version)
		}
		l.add(col(3), snmp.String(d.Type))
		l.add(col(4), snmp.String(fw))
		l.add(col(5), snmp.String(name))
		l.add(col(6), snmp.String(strings.Join(rooms, ", ")))
		l.add(col(7), snmp.String(strings.Join(funcs, ", ")))
		l.add(col(8), snmp.Gauge32(uint64(len(d.Channels))))
		l.add(col(9), Tri(f.ReachKnown, f.Reachable))
		l.add(col(10), Tri(f.LowBatKnown, f.LowBat))
		l.add(col(11), Tri(f.PendingKnown, f.Pending))
		l.add(col(12), snmp.Integer32(f.RssiDevice))
		l.add(col(13), snmp.Integer32(f.RssiPeer))
		l.add(col(14), snmp.Integer32(f.VoltageMV))
		l.add(col(15), Tri(f.DutyKnown, f.Duty))
		l.add(col(16), snmp.Gauge32(uint64(f.ServiceMessages)))
		l.add(col(17), snmp.Integer32(age))
	}
}

func appendNew(l []string, add ...string) []string {
	for _, a := range add {
		found := false
		for _, x := range l {
			if x == a {
				found = true
				break
			}
		}
		if !found {
			l = append(l, a)
		}
	}
	return l
}

func (m *Module) statistics(l *vbs, st *source.State) {
	s := Statistics
	l.add(s.Append(1, 0), snmp.Counter32(st.Stats.StreamReconnects))
	l.add(s.Append(2, 0), snmp.Counter32(st.Stats.Resyncs))
	l.add(s.Append(3, 0), snmp.Gauge32(uint64(st.Subscribers)))
	l.add(s.Append(4, 0), snmp.Gauge32(uint64(st.Stalls)))
	if c := m.o.Counters; c != nil {
		l.add(s.Append(5, 0), snmp.Counter64(c.Requests()))
		l.add(s.Append(6, 0), snmp.Counter32(c.AuthFailures()))
		l.add(s.Append(7, 0), snmp.Counter64(c.TrapsSent()))
		l.add(s.Append(8, 0), snmp.Counter32(c.TrapsFailed()))
	}
	l.add(s.Append(9, 0), snmp.Truth(st.StreamConnected))
}
