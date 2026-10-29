package trap

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
)

func state() *source.State {
	return &source.State{Ready: true, SysReady: true, SysAt: time.Unix(1000, 0),
		Interfaces: map[string]*source.Interface{"HmIP-RF": {Name: "HmIP-RF", HasRadio: true, Connected: true, DutyCycle: 5, DCThreshold: 25, Module: "HmIP-RFUSB"}},
		Devices:    map[string]*source.Device{"HmIP-RF/A": {Interface: "HmIP-RF", Address: "A", Type: "HmIP-SWDO-2", Channels: []source.Channel{{Address: "A:0", Type: "MAINTENANCE"}}}, "HmIP-RF/B": {Interface: "HmIP-RF", Address: "B", Type: "HmIP-BSM", Channels: []source.Channel{{Address: "B:0", Type: "MAINTENANCE"}}}},
		Values:     map[string]source.Value{"HmIP-RF/A:0/UNREACH": {Raw: json.RawMessage("false")}, "HmIP-RF/B:0/UNREACH": {Raw: json.RawMessage("false")}},
		Units:      []source.RadioUnit{{Unit: "hmipserver", ActiveState: "active"}, {Unit: "occu-init-rf-hardware", ActiveState: "active"}},
		LastSeen:   map[string]time.Time{},
	}
}

func allRules() ruleView {
	rv := ruleView{rules: map[string]config.Rule{}, sel: map[string]*selection.Matcher{}, lang: "de"}
	for _, k := range config.RuleKinds {
		rv.rules[k] = config.Rule{Kind: k, Enabled: true}
	}
	return rv
}

func oids(ns []Notification) []string {
	var out []string
	for _, n := range ns {
		out = append(out, Names[n.OID.String()])
	}
	return out
}

func TestWatcher(t *testing.T) {
	w := newWatcher()
	rv := allRules()
	st := state()
	if n := w.step(st, rv); n != nil {
		t.Fatalf("the baseline sent %v", oids(n))
	}
	// a service message, an unreachable device, a warning, a daemon down, the radio gone
	st.ServiceMessages = []source.ServiceMessage{{Interface: "HmIP-RF", Address: "A", Key: "UNREACH", Value: json.RawMessage("true")}}
	st.Values["HmIP-RF/A:0/UNREACH"] = source.Value{Raw: json.RawMessage("true")}
	st.Warnings = []source.Warning{{ID: "storage", Variant: "watch", Severity: "warning"}}
	st.Units[0].ActiveState = "inactive"
	st.Interfaces["HmIP-RF"].Connected = false
	got := oids(w.step(st, rv))
	want := []string{"hmServiceMessageRaised", "hmInterfaceDisconnected", "hmServiceDown", "hmWarningRaised", "hmDeviceUnreachable"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// the same state again: nothing (one raised per object until cleared)
	if n := w.step(st, rv); len(n) != 0 {
		t.Fatalf("repeated %v", oids(n))
	}
	// all back
	st.ServiceMessages = nil
	st.Values["HmIP-RF/A:0/UNREACH"] = source.Value{Raw: json.RawMessage("false")}
	st.Warnings = nil
	st.Units[0].ActiveState = "active"
	st.Interfaces["HmIP-RF"].Connected = true
	if got := oids(w.step(st, rv)); len(got) != 5 || got[0] != "hmServiceMessageCleared" || got[4] != "hmDeviceReachable" {
		t.Fatalf("cleared %v", got)
	}
}

func TestDutyCycleHysteresis(t *testing.T) {
	w := newWatcher()
	rv := allRules()
	st := state()
	w.step(st, rv)
	sample := func(dc int) []string {
		st.SysAt = st.SysAt.Add(time.Minute)
		st.Interfaces["HmIP-RF"].DutyCycle = dc
		return oids(w.step(st, rv))
	}
	if g := sample(30); len(g) != 0 {
		t.Fatalf("one sample over raised %v", g)
	}
	if g := sample(31); len(g) != 1 || g[0] != "hmDutyCycleHigh" {
		t.Fatalf("two samples: %v", g)
	}
	if g := sample(20); len(g) != 0 {
		t.Fatalf("inside the hysteresis: %v", g)
	}
	if g := sample(14); len(g) != 1 || g[0] != "hmDutyCycleNormal" {
		t.Fatalf("below threshold-10: %v", g)
	}
	// a change without a new sample is no sample
	st.Interfaces["HmIP-RF"].DutyCycle = 90
	if g := oids(w.step(st, rv)); len(g) != 0 {
		t.Fatalf("no new sample: %v", g)
	}
}

func TestRulesAndSelections(t *testing.T) {
	w := newWatcher()
	rv := allRules()
	r := rv.rules[config.RuleServiceMessage]
	r.Selection = "x"
	rv.rules[config.RuleServiceMessage] = r
	rv.sel[config.RuleServiceMessage] = selection.New(selection.Selection{Name: "B only", Objects: []string{"HmIP-RF/B"}})
	rv.rules[config.RuleWarning] = config.Rule{Kind: config.RuleWarning, Enabled: false}
	st := state()
	w.step(st, rv)
	st.ServiceMessages = []source.ServiceMessage{{Interface: "HmIP-RF", Address: "A", Key: "LOW_BAT"}, {Interface: "HmIP-RF", Address: "B", Key: "LOW_BAT"}}
	st.Warnings = []source.Warning{{ID: "x", Severity: "error"}}
	got := w.step(st, rv)
	if len(got) != 1 || !got[0].OID.Equal(ServiceMessageRaised) {
		t.Fatalf("got %v", oids(got))
	}
	vb := got[0].VarBinds(5)
	if !vb[1].Value.OID.Equal(ServiceMessageRaised) || vb[0].Value.Tag != snmp.TagTimeTicks || string(vb[3].Value.Bytes) != "B" {
		t.Fatalf("bindings %v", vb)
	}
}

func TestWants(t *testing.T) {
	tg := config.Target{Enabled: true, Rules: []string{config.RuleService}}
	if !wants(tg, Notification{Rule: config.RuleService}) || wants(tg, Notification{Rule: config.RuleWarning}) || !wants(tg, Notification{OID: ColdStart}) {
		t.Fatal("rules per target")
	}
	tg.Enabled = false
	if wants(tg, Notification{OID: ColdStart}) {
		t.Fatal("a disabled target got a notification")
	}
}
