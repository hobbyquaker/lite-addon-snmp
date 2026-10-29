// Package source keeps what the agent answers about the Homematic side in memory: the interfaces,
// the devices and channels, the service datapoints of the state store, the names, rooms and
// functions, the service messages, the Status warnings and the radio health. It reads openccu-lite's
// APIs - lite-rpc's state store and event stream, the metadata API, occulited's system API - and
// never anything that makes the radio transmit: no getValue, no getParamset of a value channel.
// An SNMP request reads only this memory.
package source

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/litesource"
)

// Keys are the datapoints the device table reads from the state store and the stream.
var Keys = []string{"UNREACH", "STICKY_UNREACH", "LOWBAT", "LOW_BAT", "CONFIG_PENDING", "UPDATE_PENDING", "RSSI_DEVICE", "RSSI_PEER", "OPERATING_VOLTAGE", "DUTY_CYCLE"}

var keySet = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range Keys {
		m[k] = true
	}
	return m
}()

// Interface is one interface process with its radio's health.
type Interface struct {
	Name      string
	Protocol  string
	Running   bool
	HasRadio  bool
	Connected bool
	DutyCycle int
	// CarrierSense is -1 when unknown.
	CarrierSense int
	DCThreshold  int
	Module       string
	Firmware     string
	Address      string
	Events       uint64
	LastEvent    time.Time
}

// Channel is one channel of a device.
type Channel struct {
	Address string
	Type    string
}

// Device is one device.
type Device struct {
	Interface string
	Address   string
	Type      string
	Firmware  string
	Version   int
	Channels  []Channel
}

// Value is one datapoint value from the store or the stream.
type Value struct {
	Raw json.RawMessage
	TS  time.Time
}

// Stats are the source's own counters.
type Stats struct {
	StreamReconnects uint64
	Resyncs          uint64
}

// State is everything the source keeps. Readers get it through View and must not keep it.
type State struct {
	Interfaces map[string]*Interface
	Devices    map[string]*Device // "<interface>/<address>"
	Values     map[string]Value   // "<interface>/<channel address>/<key>"
	// LastSeen is the newest event or confirmed value per device, "<interface>/<address>".
	LastSeen map[string]time.Time
	Names    *litesource.Names
	// Paramsets is the description cache (keys per channel type).
	Paramsets       litesource.ParamsetCache
	ServiceMessages []ServiceMessage
	Warnings        []Warning
	Health          Health
	Units           []RadioUnit
	Subscribers     int
	Stalls          int
	Stats           Stats
	StreamConnected bool
	// SysAt is the last successful read of occulited's system API.
	SysAt time.Time
	// Ready is set once the devices and the store have been read the first time.
	Ready          bool
	seeded, listed bool
	// SysReady is set once the system API was read the first time.
	SysReady bool
}

// Options configure a source.
type Options struct {
	Lite *litesource.Client
	Sys  *SysClient
	Log  func(format string, args ...any)
	Now  func() time.Time
	// RadioEvery, SlowEvery and MessagesEvery are the polling periods (60 s, 5 min, 30 s).
	RadioEvery, SlowEvery, MessagesEvery time.Duration
}

// Source keeps the state.
type Source struct {
	o   Options
	mu  sync.RWMutex
	st  State
	gen atomic.Uint64

	subMu sync.Mutex
	subs  []chan struct{}

	devicesDirty chan struct{}
	metaDirty    chan struct{}
}

// New makes a source; Run fills it.
func New(o Options) *Source {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RadioEvery <= 0 {
		o.RadioEvery = time.Minute
	}
	if o.SlowEvery <= 0 {
		o.SlowEvery = 5 * time.Minute
	}
	if o.MessagesEvery <= 0 {
		o.MessagesEvery = 30 * time.Second
	}
	s := &Source{o: o, devicesDirty: make(chan struct{}, 1), metaDirty: make(chan struct{}, 1)}
	s.st = State{Interfaces: map[string]*Interface{}, Devices: map[string]*Device{}, Values: map[string]Value{}, LastSeen: map[string]time.Time{}}
	return s
}

// View reads the state under the lock.
func (s *Source) View(f func(*State)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f(&s.st)
}

// Generation changes with every update; a cache compares it.
func (s *Source) Generation() uint64 { return s.gen.Load() }

// Changes delivers a signal (coalesced) after every update, for the trap engine.
func (s *Source) Changes() <-chan struct{} {
	c := make(chan struct{}, 1)
	s.subMu.Lock()
	s.subs = append(s.subs, c)
	s.subMu.Unlock()
	return c
}

func (s *Source) update(f func(*State)) {
	s.mu.Lock()
	f(&s.st)
	s.mu.Unlock()
	s.gen.Add(1)
	s.subMu.Lock()
	for _, c := range s.subs {
		select {
		case c <- struct{}{}:
		default:
		}
	}
	s.subMu.Unlock()
}

func poke(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// Run reads until ctx ends.
func (s *Source) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, f := range []func(context.Context){s.runRPC, s.runDevices, s.runMeta, s.runSys, s.runMessages} {
		wg.Add(1)
		go func(f func(context.Context)) {
			defer wg.Done()
			f(ctx)
		}(f)
	}
	wg.Wait()
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// --- lite-rpc: interfaces, devices, the state store, the event stream ---

// runDevices lists the interfaces, their devices and the paramset descriptions at start and
// whenever the stream says devices changed (debounced).
func (s *Source) runDevices(ctx context.Context) {
	poke(s.devicesDirty)
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.devicesDirty:
		}
		if !first && !sleep(ctx, 2*time.Second) {
			return
		}
		first = false
		for !s.listDevices(ctx) {
			if !sleep(ctx, 15*time.Second) {
				return
			}
		}
	}
}

func (s *Source) listDevices(ctx context.Context) bool {
	ifs, err := s.o.Lite.Interfaces(ctx)
	if err != nil {
		s.o.Log("snmp: reading the interfaces: %v", err)
		return false
	}
	devices := map[string]*Device{}
	for _, i := range ifs {
		if !i.Running {
			continue
		}
		l, err := s.o.Lite.ListDevices(ctx, i.Name)
		if err != nil {
			s.o.Log("snmp: listDevices %s: %v", i.Name, err)
			continue
		}
		for _, d := range l {
			if d.Parent != "" {
				continue
			}
			devices[i.Name+"/"+d.Address] = &Device{Interface: i.Name, Address: d.Address, Type: d.Type, Firmware: d.Firmware, Version: d.Version}
		}
		for _, d := range l {
			if d.Parent == "" {
				continue
			}
			if dev := devices[i.Name+"/"+d.Parent]; dev != nil {
				dev.Channels = append(dev.Channels, Channel{Address: d.Address, Type: d.Type})
			}
		}
	}
	for _, d := range devices {
		sort.Slice(d.Channels, func(a, b int) bool { return channelNo(d.Channels[a].Address) < channelNo(d.Channels[b].Address) })
	}
	ps, err := s.o.Lite.Paramsets(ctx)
	if err != nil {
		s.o.Log("snmp: reading the paramset descriptions: %v", err)
	}
	s.update(func(st *State) {
		for _, i := range ifs {
			x := st.Interfaces[i.Name]
			if x == nil {
				x = &Interface{Name: i.Name, CarrierSense: -1}
				st.Interfaces[i.Name] = x
			}
			x.Protocol, x.Running = i.Protocol, i.Running
		}
		for name := range st.Interfaces {
			found := false
			for _, i := range ifs {
				found = found || i.Name == name
			}
			if !found {
				delete(st.Interfaces, name)
			}
		}
		st.Devices = devices
		if ps != nil {
			st.Paramsets = ps
		}
		st.listed = true
		st.Ready = st.seeded
	})
	return true
}

func channelNo(a string) int {
	_, n, _ := strings.Cut(a, ":")
	v, _ := strconv.Atoi(n)
	return v
}

// DeviceOf is the device address of a channel address.
func DeviceOf(a string) string {
	d, _, _ := strings.Cut(a, ":")
	return d
}

func (s *Source) seed(ctx context.Context) (string, error) {
	snap, err := s.o.Lite.State(ctx, litesource.Filter{Keys: Keys})
	if err != nil {
		return "", err
	}
	s.update(func(st *State) {
		st.Values = map[string]Value{}
		for _, e := range snap.Entries {
			st.Values[e.Interface+"/"+e.Address+"/"+e.Key] = Value{Raw: e.Value, TS: e.TS}
			if k := e.Interface + "/" + DeviceOf(e.Address); e.Confirmed && e.TS.After(st.LastSeen[k]) {
				st.LastSeen[k] = e.TS
			}
		}
		st.seeded = true
		st.Ready = st.listed
	})
	return snap.EventID, nil
}

// runRPC seeds from the state store, then follows the event stream; a resync seeds again.
func (s *Source) runRPC(ctx context.Context) {
	for ctx.Err() == nil {
		since, err := s.seed(ctx)
		if err != nil {
			s.o.Log("snmp: reading the state store: %v", err)
			if !sleep(ctx, 15*time.Second) {
				return
			}
			continue
		}
		sctx, cancel := context.WithCancel(ctx)
		resync := s.follow(sctx, since)
		cancel()
		if !resync {
			return
		}
	}
}

// follow reads the stream; it answers true when a resync asks for a new seed.
func (s *Source) follow(ctx context.Context, since string) bool {
	hellos := 0
	for m := range s.o.Lite.Events(ctx, litesource.Filter{}, since) {
		switch m.Type {
		case "hello":
			hellos++
			s.update(func(st *State) {
				st.StreamConnected = true
				if hellos > 1 {
					st.Stats.StreamReconnects++
				}
			})
		case "resync":
			s.update(func(st *State) { st.Stats.Resyncs++ })
			poke(s.devicesDirty)
			return true
		case "event", "state":
			if m.Event == nil {
				continue
			}
			e := *m.Event
			ts := e.TS
			if ts.IsZero() {
				ts = s.o.Now()
			}
			s.update(func(st *State) {
				if i := st.Interfaces[e.Interface]; i != nil && m.Type == "event" {
					i.Events++
					i.LastEvent = ts
				}
				if k := e.Interface + "/" + DeviceOf(e.Address); ts.After(st.LastSeen[k]) {
					st.LastSeen[k] = ts
				}
				if keySet[e.Key] {
					st.Values[e.Interface+"/"+e.Address+"/"+e.Key] = Value{Raw: e.Value, TS: ts}
				}
			})
		case "newDevices", "deleteDevices", "readdedDevice", "replaceDevice", "updateDevice":
			poke(s.devicesDirty)
		case "interface":
			poke(s.devicesDirty)
		}
	}
	s.update(func(st *State) { st.StreamConnected = false })
	return ctx.Err() == nil
}

// --- the metadata ---

func (s *Source) runMeta(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := s.o.Lite.Names(ctx)
		if err != nil {
			s.o.Log("snmp: reading the metadata: %v", err)
			if !sleep(ctx, 15*time.Second) {
				return
			}
			continue
		}
		s.update(func(st *State) { st.Names = n })
		evctx, cancel := context.WithCancel(ctx)
		events := s.o.Lite.NameEvents(evctx, n.Revision)
		reread := false
		for !reread {
			select {
			case <-ctx.Done():
				cancel()
				return
			case _, ok := <-events:
				if !ok {
					reread = true
					break
				}
				// any change: read the snapshot again, a second later, once for a burst
				t := time.NewTimer(time.Second)
			drain:
				for {
					select {
					case _, ok := <-events:
						if !ok {
							break drain
						}
					case <-t.C:
						break drain
					case <-ctx.Done():
						t.Stop()
						cancel()
						return
					}
				}
				reread = true
			}
		}
		cancel()
	}
}

// --- occulited's system API ---

func (s *Source) runSys(ctx context.Context) {
	slow := time.Time{}
	for {
		s.readSys(ctx, s.o.Now().Sub(slow) >= s.o.SlowEvery)
		if s.o.Now().Sub(slow) >= s.o.SlowEvery {
			slow = s.o.Now()
		}
		if !sleep(ctx, s.o.RadioEvery) {
			return
		}
	}
}

func (s *Source) readSys(ctx context.Context, slow bool) {
	var h Health
	var rh RadioHealth
	var w Warnings
	ok := true
	if err := s.o.Sys.Get(ctx, "/api/system/v1/health", &h); err != nil {
		s.o.Log("snmp: %v", err)
		ok = false
	}
	if err := s.o.Sys.Get(ctx, "/api/system/v1/radio/health", &rh); err != nil {
		s.o.Log("snmp: %v", err)
		ok = false
	}
	if err := s.o.Sys.Get(ctx, "/api/system/v1/warnings", &w); err != nil {
		s.o.Log("snmp: %v", err)
		ok = false
	}
	stalls := -1
	if slow {
		var st Stalls
		if err := s.o.Sys.Get(ctx, "/api/system/v1/radio/subscribers/stalls", &st); err == nil {
			stalls = len(st.Stalls)
		}
	}
	s.update(func(st *State) {
		if ok {
			st.SysAt = s.o.Now()
			st.SysReady = true
		}
		if h.Release != "" || h.OK {
			st.Health = h
		}
		if w.Warnings != nil || ok {
			st.Warnings = w.Warnings
		}
		if rh.Interfaces != nil || rh.Units != nil {
			st.Units = rh.Units
			for _, i := range st.Interfaces {
				i.HasRadio = false
			}
			// the default entry of each interface, else its first
			seen := map[string]bool{}
			for pass := 0; pass < 2; pass++ {
				for _, e := range rh.Interfaces {
					if seen[e.Interface] || (pass == 0 && !e.Default) {
						continue
					}
					seen[e.Interface] = true
					i := st.Interfaces[e.Interface]
					if i == nil {
						i = &Interface{Name: e.Interface, CarrierSense: -1}
						st.Interfaces[e.Interface] = i
					}
					i.HasRadio, i.Connected, i.DutyCycle, i.DCThreshold = true, e.Connected, e.DutyCycle, e.DCThreshold
					i.Module, i.Firmware, i.Address = e.Module, e.Firmware, e.Address
					if i.Module == "" {
						i.Module = e.Type
					}
					i.CarrierSense = -1
					if e.CarrierSense != nil {
						i.CarrierSense = *e.CarrierSense
					}
				}
			}
			n := 0
			for _, sub := range rh.Subscribers {
				n += sub.Total
			}
			st.Subscribers = n
		}
		if stalls >= 0 {
			st.Stalls = stalls
		}
	})
}

// runMessages follows the service messages: the topic of occulited's stream, and a read every
// MessagesEvery in case the stream is down (as the Status page does).
func (s *Source) runMessages(ctx context.Context) {
	go func() {
		for ctx.Err() == nil {
			err := s.o.Sys.Stream(ctx, "/api/system/v1/stream?topics=service-messages", func(event, data string) {
				if event != "messages" {
					return
				}
				var sm ServiceMessages
				if json.Unmarshal([]byte(data), &sm) == nil {
					s.setMessages(sm.Messages)
				}
			})
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				s.o.Log("snmp: the service message stream: %v", err)
			}
			sleep(ctx, 10*time.Second)
		}
	}()
	for {
		var sm ServiceMessages
		if err := s.o.Sys.Get(ctx, "/api/system/v1/service-messages", &sm); err == nil {
			s.setMessages(sm.Messages)
		} else if ctx.Err() == nil {
			s.o.Log("snmp: %v", err)
		}
		if !sleep(ctx, s.o.MessagesEvery) {
			return
		}
	}
}

func (s *Source) setMessages(l []ServiceMessage) {
	if l == nil {
		l = []ServiceMessage{}
	}
	s.update(func(st *State) { st.ServiceMessages = l })
}
