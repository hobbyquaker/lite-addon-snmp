// Package agent is the SNMP agent: it takes a datagram, checks the credential (an SNMPv1/v2c
// community from its sources, or an SNMPv3 user through the user-based security model), answers
// Get, GetNext and GetBulk from the MIB tree within the credential's view, refuses every Set, and
// encodes the response. It is read-only by construction: there is no code path that writes.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/mib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
)

// Engine is the agent's SNMPv3 identity.
type Engine struct {
	ID    []byte
	Boots int64
	// Start is when the engine's time began (the process start).
	Start time.Time
}

// Time is snmpEngineTime: seconds since Start.
func (e Engine) Time(now time.Time) int64 {
	t := int64(now.Sub(e.Start) / time.Second)
	if t > 2147483647 {
		t = 2147483647
	}
	return t
}

// Counters are the agent's statistics, as the standard MIBs name them.
type Counters struct {
	InPkts, InBadVersions, InBadCommunityNames, InBadCommunityUses, InASNParseErrs, SilentDrops atomic.Uint64
	UnknownSecurityModels, InvalidMsgs, UnknownPDUHandlers                                      atomic.Uint64
	UnsupportedSecLevels, NotInTimeWindows, UnknownUserNames, UnknownEngineIDs                  atomic.Uint64
	WrongDigests, DecryptionErrors                                                              atomic.Uint64
	Requests, AuthFailures, SetsRefused, RateLimited                                            atomic.Uint64
}

// Request describes one answered request, for the status page.
type Request struct {
	At         time.Time `json:"at"`
	Source     string    `json:"source"`
	Version    string    `json:"version"`
	Credential string    `json:"credential"`
	PDU        string    `json:"pdu"`
}

// Options configure an agent.
type Options struct {
	Tree *mib.Tree
	// Root is the Homematic tree's root (the "homematic" view's and the "standard" view's border).
	Root   snmp.OID
	Engine Engine
	// MaxBulkSize caps a GetBulk response (1472 by default: one Ethernet frame).
	MaxBulkSize int
	// RatePerSecond and Burst limit the requests per source (50/100 by default).
	RatePerSecond float64
	Burst         float64
	Log           func(format string, args ...any)
	Now           func() time.Time
	// OnAuthFailure is called for a wrong community or a failed v3 authentication (the trap
	// engine's authenticationFailure).
	OnAuthFailure func(source netip.Addr)
}

// Agent answers requests.
type Agent struct {
	o     Options
	views views
	C     Counters

	mu          sync.RWMutex
	users       map[string]*userKeys
	communities map[string]Community

	salt atomic.Uint64

	rl     *limiter
	recent recentRing
	perSec perSecond
}

type userKeys struct {
	u    User
	keys usm.Keys
}

// New makes an agent.
func New(o Options) *Agent {
	if o.MaxBulkSize <= 0 {
		o.MaxBulkSize = 1472
	}
	if o.RatePerSecond <= 0 {
		o.RatePerSecond = 50
	}
	if o.Burst <= 0 {
		o.Burst = 100
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	a := &Agent{o: o, views: views{root: o.Root}, users: map[string]*userKeys{}, communities: map[string]Community{}}
	a.rl = newLimiter(o.RatePerSecond, o.Burst)
	var b [8]byte
	_, _ = rand.Read(b[:])
	a.salt.Store(binary.BigEndian.Uint64(b[:]))
	return a
}

// Engine answers the agent's engine.
func (a *Agent) Engine() Engine { return a.o.Engine }

// SetCredentials replaces the users and communities; the users' keys are localised here.
func (a *Agent) SetCredentials(users []User, communities []Community) {
	um := make(map[string]*userKeys, len(users))
	for _, u := range users {
		um[u.Name] = &userKeys{u: u, keys: usm.LocalKeys(u.Auth, u.Priv, u.KuAuth, u.KuPriv, a.o.Engine.ID)}
	}
	cm := make(map[string]Community, len(communities))
	for _, c := range communities {
		cm[c.Name] = c
	}
	a.mu.Lock()
	a.users, a.communities = um, cm
	a.mu.Unlock()
}

// HasCredentials tells whether anybody can be answered: without a user or a community the agent
// answers nothing at all.
func (a *Agent) HasCredentials() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.users)+len(a.communities) > 0
}

// Recent answers the last requests, newest first.
func (a *Agent) Recent() []Request { return a.recent.list() }

// RequestsLastMinute answers how many requests were answered in the last 60 s.
func (a *Agent) RequestsLastMinute() uint64 { return a.perSec.sum(a.o.Now()) }

// Serve answers on the connections until ctx ends.
func (a *Agent) Serve(ctx context.Context, conns ...net.PacketConn) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, c := range conns {
		wg.Add(1)
		go func(c net.PacketConn) {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				n, addr, err := c.ReadFrom(buf)
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				ua, ok := addr.(*net.UDPAddr)
				if !ok {
					continue
				}
				pkt := append([]byte(nil), buf[:n]...)
				src := ua.AddrPort()
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					if out := a.Handle(pkt, src); out != nil {
						_, _ = c.WriteTo(out, addr)
					}
				}()
			}
		}(c)
	}
	go func() {
		<-ctx.Done()
		for _, c := range conns {
			c.Close()
		}
	}()
	wg.Wait()
}

// Handle answers one datagram; nil means no answer.
func (a *Agent) Handle(pkt []byte, src netip.AddrPort) []byte {
	a.C.InPkts.Add(1)
	now := a.o.Now()
	addr := src.Addr().Unmap()
	if !a.rl.allow(addr, now) {
		a.C.RateLimited.Add(1)
		a.C.SilentDrops.Add(1)
		return nil
	}
	if !a.HasCredentials() {
		return nil
	}
	v, err := snmp.MessageVersion(pkt)
	if err != nil {
		a.C.InASNParseErrs.Add(1)
		return nil
	}
	switch v {
	case snmp.Version1, snmp.Version2c:
		return a.handleCommunity(pkt, addr, now)
	case snmp.Version3:
		return a.handleV3(pkt, addr, now)
	}
	a.C.InBadVersions.Add(1)
	return nil
}

func (a *Agent) authFailed(addr netip.Addr, now time.Time, what string) {
	a.C.AuthFailures.Add(1)
	if a.rl.authFailure(addr, now) {
		a.o.Log("snmp: authentication failure from %s: %s (logged once a minute per source)", addr, what)
	}
	if a.o.OnAuthFailure != nil {
		a.o.OnAuthFailure(addr)
	}
}

func (a *Agent) handleCommunity(pkt []byte, addr netip.Addr, now time.Time) []byte {
	m, err := snmp.DecodeCommunity(pkt)
	if err != nil {
		a.C.InASNParseErrs.Add(1)
		return nil
	}
	a.mu.RLock()
	c, ok := a.communities[string(m.Community)]
	a.mu.RUnlock()
	if !ok || !allowedFrom(c.Sources, addr) {
		// RFC 3584 §4.1: an unknown community is dropped without an answer
		a.C.InBadCommunityNames.Add(1)
		a.authFailed(addr, now, "community")
		return nil
	}
	ver := "v2c"
	if m.Version == snmp.Version1 {
		ver = "v1"
	}
	resp, ok := a.process(m.PDU, c.View, m.Version == snmp.Version1, 65507-len(m.Community)-32)
	if !ok {
		return nil
	}
	a.answered(now, addr, ver, c.Name, m.PDU.Type)
	out := snmp.CommunityMessage{Version: m.Version, Community: m.Community, PDU: resp}.Encode()
	if len(out) > 65507 {
		return nil
	}
	return out
}

func (a *Agent) answered(now time.Time, addr netip.Addr, ver, cred string, t byte) {
	a.C.Requests.Add(1)
	a.perSec.add(now)
	a.recent.add(Request{At: now, Source: addr.String(), Version: ver, Credential: cred, PDU: pduName(t)})
}

func pduName(t byte) string {
	switch t {
	case snmp.GetRequest:
		return "get"
	case snmp.GetNextRequest:
		return "getnext"
	case snmp.GetBulkRequest:
		return "getbulk"
	case snmp.SetRequest:
		return "set"
	}
	return "other"
}

// process answers one request PDU; ok false drops it (a PDU type the agent does not take).
func (a *Agent) process(req snmp.PDU, view View, v1 bool, maxSize int) (snmp.PDU, bool) {
	resp := snmp.PDU{Type: snmp.Response, RequestID: req.RequestID}
	switch req.Type {
	case snmp.GetRequest:
		for i, vb := range req.VarBinds {
			val := a.get(vb.OID, view)
			if v1 && (val.IsException() || val.Tag == snmp.TagCounter64) {
				return v1Error(req, snmp.NoSuchName, i+1), true
			}
			resp.VarBinds = append(resp.VarBinds, snmp.VarBind{OID: vb.OID, Value: val})
		}
	case snmp.GetNextRequest:
		for i, vb := range req.VarBinds {
			n := a.next(vb.OID, view, v1)
			if v1 && n.Value.IsException() {
				return v1Error(req, snmp.NoSuchName, i+1), true
			}
			resp.VarBinds = append(resp.VarBinds, n)
		}
	case snmp.GetBulkRequest:
		if v1 {
			return snmp.PDU{}, false
		}
		return a.bulk(req, view, maxSize), true
	case snmp.SetRequest:
		a.C.SetsRefused.Add(1)
		if v1 {
			return v1Error(req, snmp.NoSuchName, 1), true
		}
		resp.ErrorStatus, resp.ErrorIndex = snmp.NoAccess, 1
		resp.VarBinds = req.VarBinds
		return resp, true
	default:
		a.C.UnknownPDUHandlers.Add(1)
		return snmp.PDU{}, false
	}
	if snmp.EncodedVarBindsLen(resp.VarBinds)+64 > maxSize {
		return snmp.PDU{Type: snmp.Response, RequestID: req.RequestID, ErrorStatus: snmp.TooBig, VarBinds: req.VarBinds}, true
	}
	return resp, true
}

func v1Error(req snmp.PDU, status, index int) snmp.PDU {
	return snmp.PDU{Type: snmp.Response, RequestID: req.RequestID, ErrorStatus: status, ErrorIndex: index, VarBinds: req.VarBinds}
}

func (a *Agent) get(o snmp.OID, view View) snmp.Value {
	if ok, _ := a.views.allowed(view, o); !ok {
		return snmp.Exception(snmp.TagNoSuchObject)
	}
	return a.o.Tree.Get(o)
}

// next answers the next instance within the view (v1 skips Counter64, RFC 3584 §4.2.2.1).
func (a *Agent) next(o snmp.OID, view View, v1 bool) snmp.VarBind {
	cur := o
	for range 100000 {
		vb, ok := a.o.Tree.Next(cur)
		if !ok {
			return snmp.VarBind{OID: o, Value: snmp.Exception(snmp.TagEndOfMibView)}
		}
		if ok, from := a.views.allowed(view, vb.OID); !ok {
			if from == nil || from.Compare(vb.OID) <= 0 {
				cur = vb.OID
			} else {
				cur = from
			}
			continue
		}
		if v1 && vb.Value.Tag == snmp.TagCounter64 {
			cur = vb.OID
			continue
		}
		return vb
	}
	return snmp.VarBind{OID: o, Value: snmp.Exception(snmp.TagEndOfMibView)}
}

const maxRepetitions = 50

func (a *Agent) bulk(req snmp.PDU, view View, maxSize int) snmp.PDU {
	resp := snmp.PDU{Type: snmp.Response, RequestID: req.RequestID}
	nonRep := max(0, min(req.ErrorStatus, len(req.VarBinds)))
	reps := max(0, min(req.ErrorIndex, maxRepetitions))
	size := 64
	add := func(vb snmp.VarBind) bool {
		n := len(vb.Encode())
		if size+n > maxSize {
			return false
		}
		size += n
		resp.VarBinds = append(resp.VarBinds, vb)
		return true
	}
	for _, vb := range req.VarBinds[:nonRep] {
		if !add(a.next(vb.OID, view, false)) {
			if len(resp.VarBinds) == 0 {
				return snmp.PDU{Type: snmp.Response, RequestID: req.RequestID, ErrorStatus: snmp.TooBig}
			}
			return resp
		}
	}
	rest := req.VarBinds[nonRep:]
	cur := make([]snmp.OID, len(rest))
	for i, vb := range rest {
		cur[i] = vb.OID
	}
	for r := 0; r < reps && len(rest) > 0; r++ {
		allEnd := true
		for i := range rest {
			n := a.next(cur[i], view, false)
			if n.Value.Tag != snmp.TagEndOfMibView {
				allEnd = false
				cur[i] = n.OID
			} else {
				n.OID = cur[i]
			}
			if !add(n) {
				if len(resp.VarBinds) == 0 {
					return snmp.PDU{Type: snmp.Response, RequestID: req.RequestID, ErrorStatus: snmp.TooBig}
				}
				return resp
			}
		}
		if allEnd {
			break
		}
	}
	return resp
}

// --- rate limiting and the status rings ---

type bucket struct {
	tokens   float64
	at       time.Time
	failures int
	failAt   time.Time
	loggedAt time.Time
	blocked  time.Time
}

type limiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	m     map[netip.Addr]*bucket
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, m: map[netip.Addr]*bucket{}}
}

func (l *limiter) get(a netip.Addr, now time.Time) *bucket {
	b := l.m[a]
	if b == nil {
		if len(l.m) > 4096 {
			for k, v := range l.m {
				if now.Sub(v.at) > time.Minute {
					delete(l.m, k)
				}
			}
		}
		b = &bucket{tokens: l.burst, at: now}
		l.m[a] = b
	}
	return b
}

func (l *limiter) allow(a netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(a, now)
	if now.Before(b.blocked) {
		return false
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.at).Seconds()*l.rate)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// authFailure counts one failure; it answers whether to log it (once a minute per source). A
// source with more than 20 failures in a minute is ignored for the next minute.
func (l *limiter) authFailure(a netip.Addr, now time.Time) (log bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(a, now)
	if now.Sub(b.failAt) > time.Minute {
		b.failures, b.failAt = 0, now
	}
	b.failures++
	if b.failures > 20 {
		b.blocked = now.Add(time.Minute)
	}
	if now.Sub(b.loggedAt) >= time.Minute {
		b.loggedAt = now
		return true
	}
	return false
}

type recentRing struct {
	mu sync.Mutex
	l  []Request
}

func (r *recentRing) add(q Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// one entry per source and credential, the newest first
	out := []Request{q}
	for _, e := range r.l {
		if e.Source == q.Source && e.Credential == q.Credential && e.Version == q.Version {
			continue
		}
		out = append(out, e)
		if len(out) == 10 {
			break
		}
	}
	r.l = out
}

func (r *recentRing) list() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Request{}, r.l...)
}

type perSecond struct {
	mu  sync.Mutex
	sec [60]int64
	cnt [60]uint64
}

func (p *perSecond) add(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := now.Unix()
	i := s % 60
	if p.sec[i] != s {
		p.sec[i], p.cnt[i] = s, 0
	}
	p.cnt[i]++
}

func (p *perSecond) sum(now time.Time) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := now.Unix()
	var n uint64
	for i := range p.sec {
		if s-p.sec[i] < 60 {
			n += p.cnt[i]
		}
	}
	return n
}
