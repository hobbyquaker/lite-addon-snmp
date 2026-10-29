package trap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/inventory"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
)

// QueueSize is a target's queue; the oldest notification is dropped when it is full.
const QueueSize = 1000

// RatePerMinute is how many notifications a target gets per minute; the rest are dropped.
const RatePerMinute = 20

// Options configure the engine.
type Options struct {
	Conf   *config.Store
	Source *source.Source
	Engine agent.Engine
	// Started is the agent's start, for sysUpTime in the notifications.
	Started time.Time
	Log     func(format string, args ...any)
	// Timeout and Retries are an inform's (5 s, 3).
	Timeout time.Duration
	Retries int
	// Every is how often the state is compared besides on a change (5 s).
	Every time.Duration
}

// TargetStatus is one target's counters.
type TargetStatus struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Sent      uint64    `json:"sent"`
	Failed    uint64    `json:"failed"`
	Dropped   uint64    `json:"dropped"`
	Queued    int       `json:"queued"`
	LastError string    `json:"last_error"`
	LastSent  time.Time `json:"last_sent"`
}

// Recent is one notification the page lists.
type Recent struct {
	At   time.Time `json:"at"`
	Name string    `json:"name"`
	Text string    `json:"text"`
}

type item struct {
	n    Notification
	done chan error // the test's answer; nil otherwise
}

type worker struct {
	id     string
	mu     sync.Mutex
	queue  []item
	signal chan struct{}
	stop   context.CancelFunc
	sent   []time.Time // the rate limit's window
	st     TargetStatus
	snd    *sender
}

// Engine is the notification engine.
type Engine struct {
	o       Options
	mu      sync.Mutex
	workers map[string]*worker
	recent  []Recent
	ctx     context.Context
	w       *watcher
	sent    atomic.Uint64
	failed  atomic.Uint64
	authMu  sync.Mutex
	authAt  time.Time
}

// New makes the engine; Run starts it.
func New(o Options) *Engine {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Retries <= 0 {
		o.Retries = 3
	}
	if o.Every <= 0 {
		o.Every = 5 * time.Second
	}
	return &Engine{o: o, workers: map[string]*worker{}, w: newWatcher()}
}

// Sent and Failed are the totals for hmStatTrapsSent and hmStatTrapsFailed.
func (e *Engine) Sent() uint64 { return e.sent.Load() }

// Failed counts the dropped and the unacknowledged.
func (e *Engine) Failed() uint64 { return e.failed.Load() }

// Run watches the state and sends until ctx ends; coldStart goes to every target first.
func (e *Engine) Run(ctx context.Context) {
	e.mu.Lock()
	e.ctx = ctx
	e.mu.Unlock()
	e.Apply()
	e.dispatch(Notification{OID: ColdStart, Text: "agent started"})
	changes := e.o.Source.Changes()
	t := time.NewTicker(e.o.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-t.C:
		}
		for _, n := range e.check() {
			e.dispatch(n)
		}
	}
}

func (e *Engine) check() []Notification {
	c := e.o.Conf.Get()
	rv := ruleView{rules: map[string]config.Rule{}, sel: map[string]*selection.Matcher{}, lang: c.Lang}
	for _, r := range c.Traps.Rules {
		rv.rules[r.Kind] = r
		if s, ok := c.Selection(r.Selection); ok && r.Selection != "" {
			rv.sel[r.Kind] = selection.New(s)
		}
	}
	var out []Notification
	e.o.Source.View(func(st *source.State) {
		if len(rv.sel) > 0 {
			rv.keys = inventory.NewKeyIndex(st.Paramsets)
		}
		out = e.w.step(st, rv)
	})
	return out
}

// AuthFailure is the agent's hook: authenticationFailure, at most once a minute, when
// snmpEnableAuthenTraps is on.
func (e *Engine) AuthFailure() {
	if !e.o.Conf.Get().AuthTraps {
		return
	}
	e.authMu.Lock()
	if time.Since(e.authAt) < time.Minute {
		e.authMu.Unlock()
		return
	}
	e.authAt = time.Now()
	e.authMu.Unlock()
	e.dispatch(Notification{OID: AuthenticationFailure, Text: "authentication failure"})
}

// Apply starts a worker per target and stops the ones of removed targets.
func (e *Engine) Apply() {
	c := e.o.Conf.Get()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx == nil {
		return
	}
	keep := map[string]bool{}
	for _, tg := range c.Traps.Targets {
		keep[tg.ID] = true
		if e.workers[tg.ID] == nil {
			ctx, cancel := context.WithCancel(e.ctx)
			w := &worker{id: tg.ID, signal: make(chan struct{}, 1), stop: cancel, snd: &sender{timeout: e.o.Timeout, retries: e.o.Retries, engine: e.o.Engine}}
			w.st.ID = tg.ID
			e.workers[tg.ID] = w
			go e.work(ctx, w)
		}
	}
	for id, w := range e.workers {
		if !keep[id] {
			w.stop()
			delete(e.workers, id)
		}
	}
}

// wants tells whether a target gets a notification.
func wants(tg config.Target, n Notification) bool {
	if !tg.Enabled {
		return false
	}
	if n.Rule == "" || len(tg.Rules) == 0 {
		return true
	}
	for _, r := range tg.Rules {
		if r == n.Rule {
			return true
		}
	}
	return false
}

func (e *Engine) dispatch(n Notification) {
	c := e.o.Conf.Get()
	e.mu.Lock()
	e.recent = append([]Recent{{At: time.Now(), Name: Names[n.OID.String()], Text: n.Text}}, e.recent...)
	if len(e.recent) > 20 {
		e.recent = e.recent[:20]
	}
	ws := e.workers
	e.mu.Unlock()
	for _, tg := range c.Traps.Targets {
		if w := ws[tg.ID]; w != nil && wants(tg, n) {
			e.enqueue(w, item{n: n})
		}
	}
	if n.OID.Equal(ColdStart) || n.OID.Equal(AuthenticationFailure) {
		return
	}
	e.o.Log("snmp: notification %s: %s", Names[n.OID.String()], n.Text)
}

func (e *Engine) enqueue(w *worker, it item) {
	w.mu.Lock()
	if len(w.queue) >= QueueSize {
		w.queue = w.queue[1:]
		w.st.Dropped++
		e.failed.Add(1)
	}
	w.queue = append(w.queue, it)
	w.mu.Unlock()
	select {
	case w.signal <- struct{}{}:
	default:
	}
}

func (e *Engine) target(id string) (config.Target, *agent.User, bool) {
	c := e.o.Conf.Get()
	for _, tg := range c.Traps.Targets {
		if tg.ID != id {
			continue
		}
		for _, u := range c.Users {
			if u.Name == tg.User {
				au := u.AgentUser()
				return tg, &au, true
			}
		}
		return tg, nil, true
	}
	return config.Target{}, nil, false
}

func (e *Engine) work(ctx context.Context, w *worker) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.signal:
		}
		for {
			w.mu.Lock()
			if len(w.queue) == 0 {
				w.mu.Unlock()
				break
			}
			it := w.queue[0]
			w.queue = w.queue[1:]
			w.mu.Unlock()
			tg, user, ok := e.target(w.id)
			if !ok {
				return
			}
			now := time.Now()
			// the rate limit: a test always goes out
			if it.done == nil {
				w.mu.Lock()
				cut := 0
				for cut < len(w.sent) && now.Sub(w.sent[cut]) >= time.Minute {
					cut++
				}
				w.sent = w.sent[cut:]
				over := len(w.sent) >= RatePerMinute
				if over {
					w.st.Dropped++
				} else {
					w.sent = append(w.sent, now)
				}
				w.mu.Unlock()
				if over {
					e.failed.Add(1)
					continue
				}
			}
			uptime := uint64(now.Sub(e.o.Started) / (10 * time.Millisecond))
			err := w.snd.send(tg, user, it.n.VarBinds(uptime), now)
			w.mu.Lock()
			w.st.Name = tg.Name
			if err != nil {
				w.st.Failed++
				w.st.LastError = err.Error()
			} else {
				w.st.Sent++
				w.st.LastSent = now
				w.st.LastError = ""
			}
			w.mu.Unlock()
			if err != nil {
				e.failed.Add(1)
				e.o.Log("snmp: notification to %s: %v", tg.Name, err)
			} else {
				e.sent.Add(1)
			}
			if it.done != nil {
				it.done <- err
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// Status answers the page's view.
func (e *Engine) Status() any {
	c := e.o.Conf.Get()
	e.mu.Lock()
	defer e.mu.Unlock()
	targets := []TargetStatus{}
	for _, tg := range c.Traps.Targets {
		st := TargetStatus{ID: tg.ID, Name: tg.Name}
		if w := e.workers[tg.ID]; w != nil {
			w.mu.Lock()
			st = w.st
			st.Name = tg.Name
			st.Queued = len(w.queue)
			w.mu.Unlock()
		}
		targets = append(targets, st)
	}
	recent := append([]Recent{}, e.recent...)
	return map[string]any{"sent": e.sent.Load(), "failed": e.failed.Load(), "targets": targets, "recent": recent}
}

// ErrUnknownTarget is a test of a target that does not exist.
var ErrUnknownTarget = errors.New("no such target")

// Test sends hmTestNotification to one target, now, and answers how it went (an inform's
// acknowledgement included).
func (e *Engine) Test(id string) error {
	e.mu.Lock()
	w := e.workers[id]
	e.mu.Unlock()
	if w == nil {
		return ErrUnknownTarget
	}
	done := make(chan error, 1)
	e.enqueue(w, item{n: Notification{OID: TestNotification, Text: "test", Vars: []snmp.VarBind{v(objText, snmp.String("lite-addon-snmp test notification"))}}, done: done})
	select {
	case err := <-done:
		return err
	case <-time.After(e.o.Timeout*time.Duration(e.o.Retries+1)*2 + 5*time.Second):
		return errors.New("the test is still queued")
	}
}
