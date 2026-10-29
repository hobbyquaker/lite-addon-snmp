// Package app wires the addon together: the configuration, the agent and its listeners, the
// MIB tree with the standard and the Homematic modules, and the source. Apply makes a changed
// configuration effective: the credentials, the device table's selection and, when the switches
// changed, the listeners.
package app

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/hmmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/hostmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/inventory"
	"github.com/hobbyquaker/lite-addon-snmp/internal/mib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
)

// Options configure the app.
type Options struct {
	Conf    *config.Store
	Source  *source.Source
	Engine  agent.Engine
	Version string
	// Port is the agent's UDP port (161; 0 takes any free port, for tests).
	Port int
	// Listen is the address family's bind address override for tests ("127.0.0.1").
	Listen string
	FS     hostmib.FS
	Log    func(format string, args ...any)
}

// App is the running addon.
type App struct {
	o       Options
	Tree    *mib.Tree
	Agent   *agent.Agent
	Sampler *hostmib.Sampler
	Started time.Time

	incMu    sync.Mutex
	includer *inventory.Includer
	mu       sync.Mutex
	listen   listenKey
	cancel   context.CancelFunc
	done     chan struct{}
	ctx      context.Context
	// ListenErr is the last listener error, for the status page.
	listenErr string
	addrs     []net.Addr

	// TrapCounters is filled by the trap engine (0.2.0).
	TrapCounters TrapCounters
}

// TrapCounters are the notification statistics the tree reports.
type TrapCounters interface {
	Sent() uint64
	Failed() uint64
}

type listenKey struct {
	on         bool
	ipv4, ipv6 bool
}

// New builds the app; Run starts it.
func New(o Options) *App {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.FS.Proc == "" {
		o.FS = hostmib.DefaultFS
	}
	a := &App{o: o, Tree: mib.New(), Started: time.Now()}
	a.Sampler = hostmib.NewSampler(o.FS)
	a.Agent = agent.New(agent.Options{Tree: a.Tree, Root: hmmib.Root, Engine: o.Engine, Log: o.Log})
	a.Agent.Register(a.Tree, func() bool { return o.Conf.Get().AuthTraps })
	host := &hostmib.Host{FS: o.FS, Sampler: a.Sampler, ObjectID: hmmib.AgentOID, Started: a.Started, ORs: ORs(), Config: func() hostmib.System {
		c := o.Conf.Get()
		return hostmib.System{Name: c.SysName, Location: c.SysLocation, Contact: c.SysContact}
	}}
	host.Register(a.Tree)
	a.Tree.Register(hmmib.New(hmmib.Options{Source: o.Source, AgentVersion: o.Version, Counters: counters{a},
		Lang: func() string { return o.Conf.Get().Lang },
		IncludeDevice: func(st *source.State, d *source.Device) bool {
			a.incMu.Lock()
			defer a.incMu.Unlock()
			return a.includer == nil || a.includer.Include(st, d, o.Source.Generation())
		}}))
	return a
}

// ORs are the sysORTable's rows: the MIB modules the agent implements.
func ORs() []hostmib.OR {
	return []hostmib.OR{
		{ID: snmp.MustOID("1.3.6.1.6.3.1"), Descr: "The MIB module for SNMPv2 entities"},
		{ID: snmp.MustOID("1.3.6.1.6.3.10.3.1.1"), Descr: "The SNMP Management Architecture MIB"},
		{ID: snmp.MustOID("1.3.6.1.6.3.11.3.1.1"), Descr: "The MIB for Message Processing and Dispatching"},
		{ID: snmp.MustOID("1.3.6.1.6.3.15.2.1.1"), Descr: "The management information definitions for the SNMP User-based Security Model"},
		{ID: snmp.MustOID("1.3.6.1.2.1.31"), Descr: "The MIB module to describe generic objects for network interface sub-layers"},
		{ID: snmp.MustOID("1.3.6.1.2.1.25.7.1"), Descr: "The MIB module for managing host systems"},
		{ID: snmp.MustOID("1.3.6.1.4.1.2021"), Descr: "UCD-SNMP-MIB: memory, load, disks and CPU statistics"},
		{ID: hmmib.Root, Descr: "LITE-SNMP-MIB: Homematic interfaces, devices and service messages of openccu-lite (provisional root)"},
	}
}

type counters struct{ a *App }

func (c counters) Requests() uint64     { return c.a.Agent.C.Requests.Load() }
func (c counters) AuthFailures() uint64 { return c.a.Agent.C.AuthFailures.Load() }
func (c counters) TrapsSent() uint64 {
	if c.a.TrapCounters == nil {
		return 0
	}
	return c.a.TrapCounters.Sent()
}
func (c counters) TrapsFailed() uint64 {
	if c.a.TrapCounters == nil {
		return 0
	}
	return c.a.TrapCounters.Failed()
}

// Run starts the sampler and the listeners and applies the configuration until ctx ends.
func (a *App) Run(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	go a.Sampler.Run(ctx)
	a.Apply()
	<-ctx.Done()
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	done := a.done
	a.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Apply makes the stored configuration effective.
func (a *App) Apply() {
	c := a.o.Conf.Get()
	var users []agent.User
	for _, u := range c.Users {
		users = append(users, u.AgentUser())
	}
	var comms []agent.Community
	for _, cm := range c.Communities {
		comms = append(comms, cm.AgentCommunity())
	}
	a.Agent.SetCredentials(users, comms)
	var sel *selection.Selection
	if s, ok := c.Selection(c.DeviceTable); ok {
		sel = &s
	}
	in := inventory.NewIncluder(sel, c.Lang)
	a.incMu.Lock()
	a.includer = in
	a.incMu.Unlock()
	a.Tree.Invalidate()
	a.relisten(listenKey{on: c.Enabled, ipv4: c.IPv4, ipv6: c.IPv6})
}

func (a *App) relisten(k listenKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx == nil || (k == a.listen && a.cancel != nil) {
		return
	}
	if a.cancel != nil {
		a.cancel()
		<-a.done
		a.cancel, a.done = nil, nil
	}
	a.listen = k
	a.listenErr = ""
	if !k.on {
		return
	}
	var conns []net.PacketConn
	var errs []string
	port := strconv.Itoa(a.o.Port)
	if k.ipv4 {
		addr := "0.0.0.0"
		if a.o.Listen != "" {
			addr = a.o.Listen
		}
		if c, err := net.ListenPacket("udp4", net.JoinHostPort(addr, port)); err == nil {
			conns = append(conns, c)
		} else {
			errs = append(errs, err.Error())
		}
	}
	if k.ipv6 && a.o.Listen == "" {
		if c, err := net.ListenPacket("udp6", net.JoinHostPort("::", port)); err == nil {
			conns = append(conns, c)
		} else {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		a.listenErr = fmt.Sprint(errs)
		a.o.Log("snmp: listening on UDP %s: %v", port, errs)
	}
	if len(conns) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(a.ctx)
	done := make(chan struct{})
	a.cancel, a.done = cancel, done
	a.addrs = nil
	for _, c := range conns {
		a.addrs = append(a.addrs, c.LocalAddr())
		a.o.Log("snmp: answering on udp %s", c.LocalAddr())
	}
	go func() {
		defer close(done)
		a.Agent.Serve(ctx, conns...)
	}()
}

// Listening answers whether the agent listens, and the last listener error.
func (a *App) Listening() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cancel != nil, a.listenErr
}

// Addrs answers the agent's bound addresses.
func (a *App) Addrs() []net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel == nil {
		return nil
	}
	return append([]net.Addr(nil), a.addrs...)
}
