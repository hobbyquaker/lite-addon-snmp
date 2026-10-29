package trap

import (
	"sort"
	"strings"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/hmmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/inventory"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
)

// watchedUnits are the interface daemons hmServiceDown watches.
var watchedUnits = map[string]bool{"rfd": true, "hmipserver": true, "multimacd": true, "hs485d": true}

// snapshot is what the watcher compares.
type snapshot struct {
	messages  map[string]source.ServiceMessage
	connected map[string]bool
	modules   map[string]string
	duty      map[string]int
	dutyThr   map[string]int
	sysAt     time.Time
	units     map[string]bool
	warnings  map[string]source.Warning
	unreach   map[string]bool
}

func take(st *source.State) snapshot {
	s := snapshot{messages: map[string]source.ServiceMessage{}, connected: map[string]bool{}, modules: map[string]string{}, duty: map[string]int{}, dutyThr: map[string]int{},
		units: map[string]bool{}, warnings: map[string]source.Warning{}, unreach: map[string]bool{}, sysAt: st.SysAt}
	for _, m := range st.ServiceMessages {
		s.messages[m.ID()] = m
	}
	for name, i := range st.Interfaces {
		if i.HasRadio {
			s.connected[name] = i.Connected
			s.modules[name] = i.Module
			s.duty[name] = i.DutyCycle
			s.dutyThr[name] = i.DCThreshold
		}
	}
	for _, u := range st.Units {
		if watchedUnits[u.Unit] {
			s.units[u.Unit] = u.ActiveState == "active"
		}
	}
	for _, w := range st.Warnings {
		s.warnings[w.Key()] = w
	}
	for k, val := range st.Values {
		parts := strings.SplitN(k, "/", 3)
		if len(parts) != 3 || parts[2] != "UNREACH" || !strings.HasSuffix(parts[1], ":0") {
			continue
		}
		known, on := hmmibBool(val.Raw)
		if known {
			s.unreach[parts[0]+"/"+source.DeviceOf(parts[1])] = on
		}
	}
	return s
}

func hmmibBool(raw []byte) (known, v bool) {
	switch strings.TrimSpace(string(raw)) {
	case "true", "1":
		return true, true
	case "false", "0":
		return true, false
	}
	return false, false
}

// watcher keeps the previous snapshot and the duty cycle's hysteresis.
type watcher struct {
	prev     *snapshot
	dutyHigh map[string]bool
	dutyOver map[string]int
	lastDuty time.Time
}

func newWatcher() *watcher { return &watcher{dutyHigh: map[string]bool{}, dutyOver: map[string]int{}} }

// ruleView is the configuration the watcher reads per call.
type ruleView struct {
	rules map[string]config.Rule
	sel   map[string]*selection.Matcher
	keys  inventory.KeyIndex
	lang  string
}

func (r ruleView) enabled(kind string) bool { return r.rules[kind].Enabled }

// device tells whether a device is in the rule's selection.
func (r ruleView) device(kind string, st *source.State, iface, address string) bool {
	m := r.sel[kind]
	if m == nil {
		return true
	}
	d := st.Devices[iface+"/"+address]
	if d == nil {
		return false
	}
	return len(inventory.MatchDevice(m, st, r.keys, d, r.lang).Channels) > 0
}

// step compares the state with the previous one and answers the notifications. The first call
// (and any call before the state is complete) only takes the baseline.
func (w *watcher) step(st *source.State, rv ruleView) []Notification {
	if !st.Ready || !st.SysReady {
		return nil
	}
	cur := take(st)
	if w.prev == nil {
		w.prev = &cur
		w.lastDuty = cur.sysAt
		for name, dc := range cur.duty {
			w.dutyHigh[name] = dc >= threshold(rv, cur, name)
		}
		return nil
	}
	p := w.prev
	var out []Notification
	names := st.Names
	devInfo := func(iface, address string) (typ, name, rooms string) {
		if d := st.Devices[iface+"/"+address]; d != nil {
			typ = d.Type
		}
		if names != nil {
			name = names.Name(iface, address)
			rooms = strings.Join(names.RoomNames(iface, address, rv.lang), ", ")
		}
		return
	}
	// service messages
	if rv.enabled(config.RuleServiceMessage) {
		for _, id := range sortedKeys(cur.messages) {
			if _, ok := p.messages[id]; !ok {
				m := cur.messages[id]
				if rv.device(config.RuleServiceMessage, st, m.Interface, source.DeviceOf(m.Address)) {
					out = append(out, smNotification(ServiceMessageRaised, m, devInfo))
				}
			}
		}
		for _, id := range sortedKeys(p.messages) {
			if _, ok := cur.messages[id]; !ok {
				m := p.messages[id]
				if rv.device(config.RuleServiceMessage, st, m.Interface, source.DeviceOf(m.Address)) {
					out = append(out, smNotification(ServiceMessageCleared, m, devInfo))
				}
			}
		}
	}
	// interfaces
	if rv.enabled(config.RuleInterface) {
		for _, name := range sortedKeys(cur.connected) {
			was, known := p.connected[name]
			now := cur.connected[name]
			if known && was != now {
				oid, text := InterfaceConnected, "connected"
				if !now {
					oid, text = InterfaceDisconnected, "disconnected"
				}
				out = append(out, Notification{OID: oid, Rule: config.RuleInterface, Text: name + " " + text,
					Vars: []snmp.VarBind{v(objInterface, snmp.String(name)), v(objModule, snmp.String(cur.modules[name]))}})
			}
		}
	}
	// duty cycle: two samples at or above the threshold raise it, below threshold-10 clears it
	if cur.sysAt.After(w.lastDuty) {
		w.lastDuty = cur.sysAt
		for _, name := range sortedKeys(cur.duty) {
			dc, thr := cur.duty[name], threshold(rv, cur, name)
			switch {
			case !w.dutyHigh[name] && dc >= thr:
				w.dutyOver[name]++
				if w.dutyOver[name] >= 2 {
					w.dutyHigh[name], w.dutyOver[name] = true, 0
					if rv.enabled(config.RuleDutyCycle) {
						out = append(out, dutyNotification(DutyCycleHigh, name, dc, thr))
					}
				}
			case !w.dutyHigh[name]:
				w.dutyOver[name] = 0
			case w.dutyHigh[name] && dc < thr-10:
				w.dutyHigh[name] = false
				if rv.enabled(config.RuleDutyCycle) {
					out = append(out, dutyNotification(DutyCycleNormal, name, dc, thr))
				}
			}
		}
	}
	// services
	if rv.enabled(config.RuleService) {
		for _, u := range sortedKeys(cur.units) {
			was, known := p.units[u]
			if known && was != cur.units[u] {
				oid, text := ServiceUp, "up"
				if !cur.units[u] {
					oid, text = ServiceDown, "down"
				}
				out = append(out, Notification{OID: oid, Rule: config.RuleService, Text: u + " " + text, Vars: []snmp.VarBind{v(objService, snmp.String(u))}})
			}
		}
	}
	// Status warnings
	if rv.enabled(config.RuleWarning) {
		for _, k := range sortedKeys(cur.warnings) {
			if _, ok := p.warnings[k]; !ok {
				out = append(out, warnNotification(WarningRaised, cur.warnings[k]))
			}
		}
		for _, k := range sortedKeys(p.warnings) {
			if _, ok := cur.warnings[k]; !ok {
				out = append(out, warnNotification(WarningCleared, p.warnings[k]))
			}
		}
	}
	// unreachable devices
	if rv.enabled(config.RuleUnreachable) {
		for _, k := range sortedKeys(cur.unreach) {
			was, known := p.unreach[k]
			if !known || was == cur.unreach[k] {
				continue
			}
			iface, addr, _ := strings.Cut(k, "/")
			if !rv.device(config.RuleUnreachable, st, iface, addr) {
				continue
			}
			oid, text := DeviceReachable, "reachable"
			if cur.unreach[k] {
				oid, text = DeviceUnreachable, "unreachable"
			}
			typ, name, rooms := devInfo(iface, addr)
			out = append(out, Notification{OID: oid, Rule: config.RuleUnreachable, Text: label(iface, addr, name) + " " + text,
				Vars: []snmp.VarBind{v(objInterface, snmp.String(iface)), v(objAddress, snmp.String(addr)), v(objDeviceType, snmp.String(typ)), v(objDeviceName, snmp.String(name)), v(objRooms, snmp.String(rooms))}})
		}
	}
	w.prev = &cur
	return out
}

func threshold(rv ruleView, s snapshot, name string) int {
	if t := rv.rules[config.RuleDutyCycle].Threshold; t > 0 {
		return t
	}
	if t := s.dutyThr[name]; t > 0 {
		return t
	}
	return 80
}

func label(iface, addr, name string) string {
	if name != "" {
		return name + " (" + iface + " " + addr + ")"
	}
	return iface + " " + addr
}

func smNotification(oid snmp.OID, m source.ServiceMessage, info func(iface, address string) (string, string, string)) Notification {
	dev := source.DeviceOf(m.Address)
	typ, name, rooms := info(m.Interface, dev)
	if m.Type != "" {
		typ = m.Type
	}
	if m.Name != "" {
		name = m.Name
	}
	text := "raised"
	if oid.Equal(ServiceMessageCleared) {
		text = "cleared"
	}
	return Notification{OID: oid, Rule: config.RuleServiceMessage, Text: m.Key + " " + label(m.Interface, dev, name) + " " + text,
		Vars: []snmp.VarBind{v(objInterface, snmp.String(m.Interface)), v(objAddress, snmp.String(dev)), v(objKey, snmp.String(m.Key)), v(objValue, snmp.String(hmmib.ValueText(m.Value))),
			v(objDeviceType, snmp.String(typ)), v(objDeviceName, snmp.String(name)), v(objRooms, snmp.String(rooms))}}
}

func dutyNotification(oid snmp.OID, name string, dc, thr int) Notification {
	text := "duty cycle high"
	if oid.Equal(DutyCycleNormal) {
		text = "duty cycle normal"
	}
	return Notification{OID: oid, Rule: config.RuleDutyCycle, Text: name + " " + text,
		Vars: []snmp.VarBind{v(objInterface, snmp.String(name)), v(objDutyCycle, snmp.Gauge32(uint64(max(dc, 0)))), v(objThreshold, snmp.Gauge32(uint64(max(thr, 0))))}}
}

func warnNotification(oid snmp.OID, w source.Warning) Notification {
	text := w.ID
	if w.Variant != "" {
		text += " (" + w.Variant + ")"
	}
	state := "raised"
	if oid.Equal(WarningCleared) {
		state = "cleared"
	}
	return Notification{OID: oid, Rule: config.RuleWarning, Text: "warning " + text + " " + state,
		Vars: []snmp.VarBind{v(objWarningID, snmp.String(w.Key())), v(objSeverity, snmp.Integer(Severity(w.Severity))), v(objText, snmp.String(text))}}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
