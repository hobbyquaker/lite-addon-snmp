// Package mib is the agent's object tree: modules register a subtree each and answer its
// instances as a list of bindings, which the tree caches for the module's time to live, sorts and
// searches. So a walk reads a consistent snapshot and never waits on I/O: a module computes from
// what its sources keep in memory, or from /proc, at most once per TTL.
package mib

import (
	"sort"
	"sync"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
)

// Module answers one subtree.
type Module interface {
	// Root is the subtree's OID; no instance outside it is answered.
	Root() snmp.OID
	// TTL is how long an answer of Collect may be served; 0 collects on every request.
	TTL() time.Duration
	// Collect answers every instance of the subtree, in any order.
	Collect() []snmp.VarBind
}

// Func is a Module from a function.
type Func struct {
	OID     snmp.OID
	MaxAge  time.Duration
	Collect func() []snmp.VarBind
}

type funcModule struct{ f Func }

func (m funcModule) Root() snmp.OID          { return m.f.OID }
func (m funcModule) TTL() time.Duration      { return m.f.MaxAge }
func (m funcModule) Collect() []snmp.VarBind { return m.f.Collect() }

// FromFunc wraps a Func.
func FromFunc(f Func) Module { return funcModule{f} }

type entry struct {
	mod  Module
	mu   sync.Mutex
	at   time.Time
	vbs  []snmp.VarBind
	dgen uint64
}

// Tree is the registry.
type Tree struct {
	mu   sync.RWMutex
	mods []*entry // sorted by root
	now  func() time.Time
	// dirty generation: Invalidate bumps it so every module collects again
	gen uint64
}

// New makes an empty tree.
func New() *Tree { return &Tree{now: time.Now} }

// Register adds a module. Roots must not overlap.
func (t *Tree) Register(m Module) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mods = append(t.mods, &entry{mod: m})
	sort.Slice(t.mods, func(i, j int) bool { return t.mods[i].mod.Root().Compare(t.mods[j].mod.Root()) < 0 })
}

// Invalidate makes every module collect again at its next request.
func (t *Tree) Invalidate() {
	t.mu.Lock()
	t.gen++
	t.mu.Unlock()
}

func (t *Tree) snapshot(e *entry) []snmp.VarBind {
	t.mu.RLock()
	gen := t.gen
	t.mu.RUnlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	now := t.now()
	if e.vbs != nil && e.dgen == gen && e.mod.TTL() > 0 && now.Sub(e.at) < e.mod.TTL() {
		return e.vbs
	}
	vbs := e.mod.Collect()
	root := e.mod.Root()
	out := vbs[:0:0]
	for _, vb := range vbs {
		if vb.OID.HasPrefix(root) && len(vb.OID) > len(root) {
			out = append(out, vb)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OID.Compare(out[j].OID) < 0 })
	// a duplicate instance is a module's bug; keep the first
	dedup := out[:0]
	for i, vb := range out {
		if i > 0 && vb.OID.Equal(dedup[len(dedup)-1].OID) {
			continue
		}
		dedup = append(dedup, vb)
	}
	if dedup == nil {
		dedup = []snmp.VarBind{}
	}
	e.vbs, e.at, e.dgen = dedup, now, gen
	return dedup
}

func (t *Tree) modules() []*entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mods
}

// Get answers the value of an exact instance: noSuchObject when no module or no object of a
// module has the OID as a prefix, noSuchInstance when the object exists but not the instance.
func (t *Tree) Get(o snmp.OID) snmp.Value {
	for _, e := range t.modules() {
		root := e.mod.Root()
		if !o.HasPrefix(root) {
			continue
		}
		vbs := t.snapshot(e)
		i := sort.Search(len(vbs), func(i int) bool { return vbs[i].OID.Compare(o) >= 0 })
		if i < len(vbs) && vbs[i].OID.Equal(o) {
			return vbs[i].Value
		}
		// the object exists when an instance shares the request's parent (a scalar's .0, a row
		// of a table with a one-arc index); a deeper miss is answered as noSuchObject, which a
		// manager treats the same way
		if len(o) > len(root)+1 {
			parent := o[:len(o)-1]
			j := sort.Search(len(vbs), func(i int) bool { return vbs[i].OID.Compare(parent) >= 0 })
			if j < len(vbs) && vbs[j].OID.HasPrefix(parent) {
				return snmp.Exception(snmp.TagNoSuchInstance)
			}
		}
		return snmp.Exception(snmp.TagNoSuchObject)
	}
	return snmp.Exception(snmp.TagNoSuchObject)
}

// Next answers the first instance strictly after o (lexicographically), or ok false at the end
// of the tree.
func (t *Tree) Next(o snmp.OID) (snmp.VarBind, bool) {
	for _, e := range t.modules() {
		root := e.mod.Root()
		// a module wholly before o: its root sorts before o and o is not inside it
		if root.Compare(o) < 0 && !o.HasPrefix(root) {
			continue
		}
		vbs := t.snapshot(e)
		i := sort.Search(len(vbs), func(i int) bool { return vbs[i].OID.Compare(o) > 0 })
		if i < len(vbs) {
			return vbs[i], true
		}
	}
	return snmp.VarBind{}, false
}

// Walk answers every instance below a prefix, for tests and the UI's preview.
func (t *Tree) Walk(prefix snmp.OID) []snmp.VarBind {
	var out []snmp.VarBind
	cur := prefix
	for {
		vb, ok := t.Next(cur)
		if !ok || !vb.OID.HasPrefix(prefix) {
			return out
		}
		out = append(out, vb)
		cur = vb.OID
	}
}
