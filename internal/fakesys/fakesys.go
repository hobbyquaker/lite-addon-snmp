// Package fakesys is a fake openccu-lite for the tests and the page's development: the kit's
// fakelite for lite-rpc and the metadata, and occulited's system API routes the agent reads
// (health, radio health, warnings, service messages with their stream, stalls) in front of it,
// on one URL. Demo fills it with a small system.
package fakesys

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/litesource/fakelite"
)

// System is the fake.
type System struct {
	Lite *fakelite.Server
	srv  *httptest.Server
	mu   sync.Mutex
	// the system API's answers
	Health          map[string]any
	Radio           map[string]any
	Warnings        []map[string]any
	ServiceMessages []map[string]any
	streams         map[chan struct{}]bool
}

// New starts a fake around a fakelite on a free port.
func New(fl *fakelite.Server) *System { return NewOn(fl, "") }

// NewOn starts a fake on an address ("127.0.0.1:18080"; "" picks a free port).
func NewOn(fl *fakelite.Server, addr string) *System {
	s := &System{Lite: fl, streams: map[chan struct{}]bool{}}
	s.Health = map[string]any{"ok": true, "version": "abc", "commit": "abc1234", "release": "1.1.0-dev.5", "base": "3.89.11", "meta": map[string]any{"revision": 1}}
	s.Radio = map[string]any{"interfaces": []any{}, "units": []any{}, "subscribers": map[string]any{}}
	u, _ := url.Parse(fl.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.FlushInterval = -1
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/v1/", s.system)
	mux.Handle("/", proxy)
	s.srv = httptest.NewUnstartedServer(mux)
	if addr != "" {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			panic(err)
		}
		s.srv.Listener.Close()
		s.srv.Listener = l
	}
	s.srv.Start()
	return s
}

// URL is the fake system's base URL.
func (s *System) URL() string { return s.srv.URL }

// Close stops both servers.
func (s *System) Close() {
	s.srv.CloseClientConnections()
	s.srv.Close()
	s.Lite.Close()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Update changes the answers under the lock and wakes the message streams.
func (s *System) Update(f func(s *System)) {
	s.mu.Lock()
	f(s)
	for c := range s.streams {
		select {
		case c <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
}

func (s *System) messages() map[string]any {
	l := s.ServiceMessages
	if l == nil {
		l = []map[string]any{}
	}
	return map[string]any{"count": len(l), "messages": l}
}

func (s *System) system(w http.ResponseWriter, r *http.Request) {
	if s.Lite.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.Lite.Token {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/api/system/v1")
	if p == "/stream" {
		s.stream(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch p {
	case "/health":
		writeJSON(w, s.Health)
	case "/radio/health":
		writeJSON(w, s.Radio)
	case "/warnings":
		l := s.Warnings
		if l == nil {
			l = []map[string]any{}
		}
		writeJSON(w, map[string]any{"warnings": l})
	case "/service-messages":
		writeJSON(w, s.messages())
	case "/radio/subscribers/stalls":
		writeJSON(w, map[string]any{"stalls": []any{}})
	default:
		http.NotFound(w, r)
	}
}

func (s *System) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	c := make(chan struct{}, 1)
	s.mu.Lock()
	s.streams[c] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.streams, c)
		s.mu.Unlock()
	}()
	send := func() {
		s.mu.Lock()
		b, _ := json.Marshal(s.messages())
		s.mu.Unlock()
		fmt.Fprintf(w, "event: messages\ndata: %s\n\n", b)
		fl.Flush()
	}
	send()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-c:
			send()
		case <-t.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

// Demo fills the fake with a small system: HmIP-RF and BidCos-RF with a radio each, a
// thermostat, a wall switch, a window contact and a BidCos remote, rooms and functions, one
// unreachable device with its service message and a low battery.
func Demo(s *System) {
	fl := s.Lite
	fl.Interfaces = []string{"BidCos-RF", "HmIP-RF", "VirtualDevices"}
	dev := func(addr, typ string, fw string, chans ...string) []map[string]any {
		children := []any{}
		for i := range chans {
			children = append(children, fmt.Sprintf("%s:%d", addr, i))
		}
		out := []map[string]any{{"ADDRESS": addr, "TYPE": typ, "PARENT": "", "CHILDREN": children, "FIRMWARE": fw, "VERSION": 1, "PARAMSETS": []any{"MASTER"}}}
		for i, c := range chans {
			out = append(out, map[string]any{"ADDRESS": fmt.Sprintf("%s:%d", addr, i), "TYPE": c, "PARENT": addr, "PARAMSETS": []any{"MASTER", "VALUES"}, "VERSION": 1})
		}
		return out
	}
	var hmip []map[string]any
	hmip = append(hmip, dev("000A1B2C3D4E5F", "HmIP-eTRV-2", "2.2.8", "HmIP-eTRV-2", "HEATING_CLIMATECONTROL_TRANSCEIVER")...)
	hmip = append(hmip, dev("0001D3C99C1234", "HmIP-BSM", "1.10.12", "MAINTENANCE", "KEY_TRANSCEIVER", "KEY_TRANSCEIVER", "SWITCH_VIRTUAL_RECEIVER")...)
	hmip = append(hmip, dev("000E1A2B3C4D5E", "HmIP-SWDO-2", "1.2.8", "MAINTENANCE", "SHUTTER_CONTACT")...)
	var bidcos []map[string]any
	bidcos = append(bidcos, dev("JEQ0123456", "HM-PB-2-WM55-2", "2.8", "MAINTENANCE", "KEY", "KEY")...)
	fl.Devices = map[string][]map[string]any{"HmIP-RF": hmip, "BidCos-RF": bidcos, "VirtualDevices": {}}
	ps := func(keys ...string) map[string]any {
		m := map[string]any{}
		for _, k := range keys {
			m[k] = map[string]any{"TYPE": "BOOL", "OPERATIONS": 5}
		}
		return m
	}
	fl.Paramsets = map[string]map[string]any{
		"HmIP-RF/HmIP-eTRV-2/2.2.8/1/HmIP-eTRV-2/VALUES":                        ps("UNREACH", "LOW_BAT", "CONFIG_PENDING", "RSSI_DEVICE", "OPERATING_VOLTAGE", "DUTY_CYCLE"),
		"HmIP-RF/HmIP-eTRV-2/2.2.8/1/HEATING_CLIMATECONTROL_TRANSCEIVER/VALUES": ps("ACTUAL_TEMPERATURE", "SET_POINT_TEMPERATURE", "LEVEL", "VALVE_STATE"),
		"HmIP-RF/HmIP-BSM/1.10.12/1/MAINTENANCE/VALUES":                         ps("UNREACH", "CONFIG_PENDING", "RSSI_DEVICE", "DUTY_CYCLE"),
		"HmIP-RF/HmIP-BSM/1.10.12/1/KEY_TRANSCEIVER/VALUES":                     ps("PRESS_SHORT", "PRESS_LONG"),
		"HmIP-RF/HmIP-BSM/1.10.12/1/SWITCH_VIRTUAL_RECEIVER/VALUES":             ps("STATE"),
		"HmIP-RF/HmIP-SWDO-2/1.2.8/1/MAINTENANCE/VALUES":                        ps("UNREACH", "LOW_BAT", "RSSI_DEVICE", "OPERATING_VOLTAGE"),
		"HmIP-RF/HmIP-SWDO-2/1.2.8/1/SHUTTER_CONTACT/VALUES":                    ps("STATE"),
		"BidCos-RF/HM-PB-2-WM55-2/2.8/1/MAINTENANCE/VALUES":                     ps("UNREACH", "LOWBAT", "CONFIG_PENDING", "RSSI_DEVICE", "RSSI_PEER"),
		"BidCos-RF/HM-PB-2-WM55-2/2.8/1/KEY/VALUES":                             ps("PRESS_SHORT", "PRESS_LONG"),
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	st := func(iface, addr, key string, v any) map[string]any {
		return map[string]any{"interface": iface, "address": addr, "datapoint": key, "key": key, "value": v, "ts": now, "lc": now, "confirmed": true, "source": "event"}
	}
	fl.State = []map[string]any{
		st("HmIP-RF", "000A1B2C3D4E5F:0", "UNREACH", false), st("HmIP-RF", "000A1B2C3D4E5F:0", "LOW_BAT", false), st("HmIP-RF", "000A1B2C3D4E5F:0", "RSSI_DEVICE", -61), st("HmIP-RF", "000A1B2C3D4E5F:0", "OPERATING_VOLTAGE", 2.9),
		st("HmIP-RF", "0001D3C99C1234:0", "UNREACH", false), st("HmIP-RF", "0001D3C99C1234:0", "RSSI_DEVICE", -48),
		st("HmIP-RF", "000E1A2B3C4D5E:0", "UNREACH", true), st("HmIP-RF", "000E1A2B3C4D5E:0", "LOW_BAT", true), st("HmIP-RF", "000E1A2B3C4D5E:0", "OPERATING_VOLTAGE", 1.1),
		st("BidCos-RF", "JEQ0123456:0", "UNREACH", false), st("BidCos-RF", "JEQ0123456:0", "LOWBAT", false), st("BidCos-RF", "JEQ0123456:0", "RSSI_DEVICE", -70), st("BidCos-RF", "JEQ0123456:0", "RSSI_PEER", -72),
	}
	fl.EventID = "boot1-0"
	room := func(id, de, en string) map[string]any {
		return map[string]any{"id": id, "name": map[string]any{"de": de, "en": en}}
	}
	fl.Meta = map[string]any{"format": 1, "revision": 7,
		"objects": map[string]any{
			"HmIP-RF.000A1B2C3D4E5F":   map[string]any{"name": "Thermostat Bad", "enums": []any{"room/bad", "function/heizung"}},
			"HmIP-RF.000A1B2C3D4E5F:1": map[string]any{"name": "Thermostat Bad:1", "enums": []any{"room/bad", "function/heizung"}},
			"HmIP-RF.0001D3C99C1234":   map[string]any{"name": "Licht Flur", "enums": []any{"room/flur", "function/licht"}},
			"HmIP-RF.000E1A2B3C4D5E":   map[string]any{"name": "Fenster Küche", "enums": []any{"room/kueche", "function/sicherheit"}},
			"BidCos-RF.JEQ0123456":     map[string]any{"name": "Taster Flur", "enums": []any{"room/flur"}},
		},
		"enums": map[string]any{
			"room":     map[string]any{"tree": []any{room("bad", "Bad", "Bathroom"), room("flur", "Flur", "Hall"), room("kueche", "Küche", "Kitchen"), room("keller", "Keller", "Cellar")}},
			"function": map[string]any{"tree": []any{room("heizung", "Heizung", "Heating"), room("licht", "Licht", "Light"), room("sicherheit", "Sicherheit", "Security")}},
		}}
	s.Health["meta"] = map[string]any{"revision": 7}
	s.Radio = map[string]any{
		"interfaces": []any{
			map[string]any{"interface": "BidCos-RF", "address": "JEQ0000042", "type": "USB Interface", "connected": true, "default": true, "firmware": "967", "duty_cycle": 3, "module": "HM-CFG-USB-2", "dc_threshold": 25},
			map[string]any{"interface": "HmIP-RF", "address": "3014F711A000000000000042", "type": "HMIP_CCU2", "connected": true, "default": true, "firmware": "4.2.14", "duty_cycle": 7, "carrier_sense": 4, "module": "HmIP-RFUSB", "dc_threshold": 25},
		},
		"units": []any{
			map[string]any{"unit": "rfd", "interfaces": []any{"BidCos-RF"}, "active_state": "active", "sub_state": "running"},
			map[string]any{"unit": "hmipserver", "interfaces": []any{"HmIP-RF", "VirtualDevices"}, "active_state": "active", "sub_state": "running"},
		},
		"subscribers": map[string]any{"BidCos-RF": map[string]any{"total": 3}, "HmIP-RF": map[string]any{"total": 3}},
	}
	s.Warnings = []map[string]any{{"id": "backup-unencrypted", "variant": "plain", "severity": "warning"}}
	s.ServiceMessages = []map[string]any{{"interface": "HmIP-RF", "address": "000E1A2B3C4D5E", "channel": "0", "key": "UNREACH", "value": true, "since": now, "seen": "event", "type": "HmIP-SWDO-2", "name": "Fenster Küche"},
		{"interface": "HmIP-RF", "address": "000E1A2B3C4D5E", "channel": "0", "key": "LOW_BAT", "value": true, "since": now, "seen": "event", "type": "HmIP-SWDO-2", "name": "Fenster Küche"}}
}
