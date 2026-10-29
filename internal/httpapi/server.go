// Package httpapi is the addon's own HTTP server: the Svelte app's files and the JSON API under
// /addons/snmp/, which lighttpd proxies to the loopback port. Every request carries the gate's
// session header, confirmed through addonkit, and the whole page is for administrators: it
// configures who may read the system over SNMP. Writes carry the kit's CSRF header.
// docs/api.md describes the routes.
package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit"

	"github.com/hobbyquaker/lite-addon-snmp/internal/agent"
	"github.com/hobbyquaker/lite-addon-snmp/internal/app"
	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/hmmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/hostmib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/inventory"
	"github.com/hobbyquaker/lite-addon-snmp/internal/selection"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
	"github.com/hobbyquaker/lite-addon-snmp/internal/usm"
	"github.com/hobbyquaker/lite-addon-snmp/mibs"
)

// Options configure the server.
type Options struct {
	BasePath string
	WWW      string
	App      *app.App
	Conf     *config.Store
	Source   *source.Source
	// Wrap is the session check; nil serves without one (development).
	Wrap    func(http.Handler) http.Handler
	Version string
	// Traps is the trap engine's API (0.2.0); nil without one.
	Traps TrapAPI
	// Port is the agent's UDP port, for the status page.
	Port int
}

// TrapAPI is what the trap engine offers the page.
type TrapAPI interface {
	Status() any
	Test(targetID string) error
}

// Routes lists every "METHOD /path" the API serves (docs/api.md names each).
var Routes []string

func handle(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	for _, r := range Routes {
		if r == pattern {
			mux.HandleFunc(pattern, h)
			return
		}
	}
	Routes = append(Routes, pattern)
	mux.HandleFunc(pattern, h)
}

// New builds the handler.
func New(o Options) http.Handler {
	o.BasePath = strings.TrimRight(o.BasePath, "/")
	api := http.NewServeMux()
	handle(api, "GET /api/v1/health", o.health)
	handle(api, "GET /api/v1/config", o.getConfig)
	handle(api, "PUT /api/v1/agent", o.putAgent)
	handle(api, "POST /api/v1/users", o.postUser)
	handle(api, "PUT /api/v1/users/{name}", o.putUser)
	handle(api, "DELETE /api/v1/users/{name}", o.deleteUser)
	handle(api, "POST /api/v1/communities", o.postCommunity)
	handle(api, "PUT /api/v1/communities/{id}", o.putCommunity)
	handle(api, "DELETE /api/v1/communities/{id}", o.deleteCommunity)
	handle(api, "GET /api/v1/catalog", o.catalog)
	handle(api, "POST /api/v1/selections", o.postSelection)
	handle(api, "PUT /api/v1/selections/{id}", o.putSelection)
	handle(api, "DELETE /api/v1/selections/{id}", o.deleteSelection)
	handle(api, "POST /api/v1/selections/preview", o.previewSelection)
	handle(api, "PUT /api/v1/tables", o.putTables)
	handle(api, "GET /api/v1/tables/devices", o.deviceRows)
	handle(api, "GET /api/v1/status", o.status)
	handle(api, "GET /api/v1/mib", o.mib)
	handle(api, "PUT /api/v1/traps", o.putTraps)
	handle(api, "POST /api/v1/traps/targets/{id}/test", o.testTarget)
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		addonkit.WriteError(w, http.StatusNotFound, "not-found", r.URL.Path)
	})

	root := http.NewServeMux()
	root.Handle("/api/", addonkit.CSRF(api))
	root.Handle("/", addonkit.AppFiles(o.WWW))

	var h http.Handler = http.StripPrefix(o.BasePath, root)
	if o.Wrap != nil {
		h = o.Wrap(h)
	}
	return guard(h)
}

// guard refuses a path that is not clean and marks API answers as not cacheable.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p != "/" && (path.Clean(p) != strings.TrimSuffix(p, "/") && path.Clean(p) != p) {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(v); err != nil {
		addonkit.WriteError(w, http.StatusBadRequest, "invalid", err.Error())
		return false
	}
	return true
}

var (
	errNotFound = errors.New("not found")
	errConflict = errors.New("conflict")
)

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotFound):
		addonkit.WriteError(w, http.StatusNotFound, "not-found", err.Error())
	case errors.Is(err, errConflict):
		addonkit.WriteError(w, http.StatusConflict, "conflict", err.Error())
	default:
		addonkit.WriteError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
	}
}

// update changes the configuration, applies it and answers the page's view of it.
func (o Options) update(w http.ResponseWriter, f func(*config.Config) error) {
	if _, err := o.Conf.Update(f); err != nil {
		fail(w, err)
		return
	}
	o.App.Apply()
	writeJSON(w, http.StatusOK, o.view())
}

func (o Options) health(w http.ResponseWriter, r *http.Request) {
	listening, lerr := o.App.Listening()
	var ready, stream bool
	o.Source.View(func(st *source.State) { ready, stream = st.Ready, st.StreamConnected })
	code := http.StatusOK
	// ?ready=1 answers 503 until the source has read the system (the end-to-end tests wait on it)
	if r.URL.Query().Get("ready") != "" && !(ready && stream) {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"ok": ready && stream, "version": o.Version, "listening": listening, "listen_error": lerr, "uptime_s": int(time.Since(o.App.Started).Seconds())})
}

// UserView is a user without its keys.
type UserView struct {
	Name string     `json:"name"`
	Auth usm.Auth   `json:"auth"`
	Priv usm.Priv   `json:"priv"`
	View agent.View `json:"view"`
}

// View is the page's configuration: everything but the keys.
type View struct {
	Enabled     bool                  `json:"enabled"`
	SysName     string                `json:"sys_name"`
	Hostname    string                `json:"hostname"`
	SysLocation string                `json:"sys_location"`
	SysContact  string                `json:"sys_contact"`
	IPv4        bool                  `json:"ipv4"`
	IPv6        bool                  `json:"ipv6"`
	Lang        string                `json:"lang"`
	Users       []UserView            `json:"users"`
	Communities []config.Community    `json:"communities"`
	Selections  []selection.Selection `json:"selections"`
	DeviceTable string                `json:"device_table"`
	AuthTraps   bool                  `json:"auth_traps"`
	Traps       config.Traps          `json:"traps"`
	EngineID    string                `json:"engine_id"`
	EngineBoots int64                 `json:"engine_boots"`
	Root        string                `json:"root"`
	Port        int                   `json:"port"`
	Auths       []usm.Auth            `json:"auths"`
	Privs       []usm.Priv            `json:"privs"`
	MinPassword int                   `json:"min_password"`
	// TrapsAvailable tells the page whether this build sends notifications.
	TrapsAvailable bool `json:"traps_available"`
}

func (o Options) view() View {
	c := o.Conf.Get()
	e := o.App.Agent.Engine()
	v := View{Enabled: c.Enabled, SysName: c.SysName, Hostname: hostname(), SysLocation: c.SysLocation, SysContact: c.SysContact, IPv4: c.IPv4, IPv6: c.IPv6, Lang: c.Lang,
		Users: []UserView{}, Communities: c.Communities, Selections: c.Selections, DeviceTable: c.DeviceTable, AuthTraps: c.AuthTraps, Traps: c.Traps,
		EngineID: hex.EncodeToString(e.ID), EngineBoots: e.Boots, Root: hmmib.Root.String(), Port: o.Port, Auths: usm.Auths, Privs: usm.Privs, MinPassword: config.MinPassword, TrapsAvailable: o.Traps != nil}
	for _, u := range c.Users {
		v.Users = append(v.Users, UserView{Name: u.Name, Auth: u.Auth, Priv: u.Priv, View: u.View})
	}
	return v
}

func (o Options) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, o.view())
}

func (o Options) putAgent(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled     *bool   `json:"enabled"`
		SysName     *string `json:"sys_name"`
		SysLocation *string `json:"sys_location"`
		SysContact  *string `json:"sys_contact"`
		IPv4        *bool   `json:"ipv4"`
		IPv6        *bool   `json:"ipv6"`
		Lang        *string `json:"lang"`
		AuthTraps   *bool   `json:"auth_traps"`
	}
	if !decode(w, r, &b) {
		return
	}
	o.update(w, func(c *config.Config) error {
		set := func(dst *string, src *string) {
			if src != nil {
				*dst = strings.TrimSpace(*src)
			}
		}
		if b.Enabled != nil {
			c.Enabled = *b.Enabled
		}
		set(&c.SysName, b.SysName)
		set(&c.SysLocation, b.SysLocation)
		set(&c.SysContact, b.SysContact)
		if b.IPv4 != nil {
			c.IPv4 = *b.IPv4
		}
		if b.IPv6 != nil {
			c.IPv6 = *b.IPv6
		}
		if b.Lang != nil {
			c.Lang = *b.Lang
		}
		if b.AuthTraps != nil {
			c.AuthTraps = *b.AuthTraps
		}
		return nil
	})
}

type userBody struct {
	Name         string `json:"name"`
	Auth         string `json:"auth"`
	Priv         string `json:"priv"`
	View         string `json:"view"`
	AuthPassword string `json:"auth_password"`
	PrivPassword string `json:"priv_password"`
}

func (o Options) postUser(w http.ResponseWriter, r *http.Request) {
	var b userBody
	if !decode(w, r, &b) {
		return
	}
	au, err := usm.ParseAuth(b.Auth)
	if err != nil {
		fail(w, err)
		return
	}
	pr, err := usm.ParsePriv(b.Priv)
	if err != nil {
		fail(w, err)
		return
	}
	u, err := config.NewUser(strings.TrimSpace(b.Name), au, pr, agent.View(b.View), b.AuthPassword, b.PrivPassword)
	if err != nil {
		fail(w, err)
		return
	}
	o.update(w, func(c *config.Config) error {
		c.Users = append(c.Users, u)
		return nil
	})
}

func (o Options) putUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var b userBody
	if !decode(w, r, &b) {
		return
	}
	o.update(w, func(c *config.Config) error {
		for i := range c.Users {
			u := &c.Users[i]
			if u.Name != name {
				continue
			}
			if b.View != "" {
				u.View = agent.View(b.View)
			}
			au, pr := u.Auth, u.Priv
			if b.Auth != "" {
				a, err := usm.ParseAuth(b.Auth)
				if err != nil {
					return err
				}
				au = a
			}
			if b.Priv != "" {
				p, err := usm.ParsePriv(b.Priv)
				if err != nil {
					return err
				}
				pr = p
			}
			// the keys are derived with the authentication protocol's hash: a new protocol needs
			// both passwords again; a new privacy protocol alone keeps the keys
			if b.AuthPassword != "" || b.PrivPassword != "" || au != u.Auth {
				if b.AuthPassword == "" || b.PrivPassword == "" {
					return errors.New("both passwords are needed to change them or the authentication protocol")
				}
				nu, err := config.NewUser(u.Name, au, pr, u.View, b.AuthPassword, b.PrivPassword)
				if err != nil {
					return err
				}
				*u = nu
				return nil
			}
			u.Priv = pr
			return nil
		}
		return errNotFound
	})
}

func (o Options) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	o.update(w, func(c *config.Config) error {
		for _, t := range c.Traps.Targets {
			if t.User == name {
				return errors.Join(errConflict, errors.New("a trap target sends as this user"))
			}
		}
		for i, u := range c.Users {
			if u.Name == name {
				c.Users = append(c.Users[:i], c.Users[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
}

func (o Options) postCommunity(w http.ResponseWriter, r *http.Request) {
	var b config.Community
	if !decode(w, r, &b) {
		return
	}
	b.ID = config.NewID()
	if b.Sources == nil {
		b.Sources = []string{"local"}
	}
	o.update(w, func(c *config.Config) error {
		c.Communities = append(c.Communities, b)
		return nil
	})
}

func (o Options) putCommunity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b config.Community
	if !decode(w, r, &b) {
		return
	}
	o.update(w, func(c *config.Config) error {
		for i := range c.Communities {
			if c.Communities[i].ID == id {
				b.ID = id
				if b.Sources == nil {
					b.Sources = []string{}
				}
				c.Communities[i] = b
				return nil
			}
		}
		return errNotFound
	})
}

func (o Options) deleteCommunity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	o.update(w, func(c *config.Config) error {
		for i, cm := range c.Communities {
			if cm.ID == id {
				c.Communities = append(c.Communities[:i], c.Communities[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
}

func (o Options) catalog(w http.ResponseWriter, r *http.Request) {
	lang := o.Conf.Get().Lang
	var c inventory.Catalog
	o.Source.View(func(st *source.State) { c = inventory.BuildCatalog(st, lang) })
	writeJSON(w, http.StatusOK, c)
}

func (o Options) postSelection(w http.ResponseWriter, r *http.Request) {
	var b selection.Selection
	if !decode(w, r, &b) {
		return
	}
	b.ID = config.NewID()
	o.update(w, func(c *config.Config) error {
		c.Selections = append(c.Selections, b)
		return nil
	})
}

func (o Options) putSelection(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b selection.Selection
	if !decode(w, r, &b) {
		return
	}
	o.update(w, func(c *config.Config) error {
		for i := range c.Selections {
			if c.Selections[i].ID == id {
				b.ID = id
				c.Selections[i] = b
				return nil
			}
		}
		return errNotFound
	})
}

func (o Options) deleteSelection(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	o.update(w, func(c *config.Config) error {
		if c.DeviceTable == id {
			return errors.Join(errConflict, errors.New("the device table uses this selection"))
		}
		for _, rl := range c.Traps.Rules {
			if rl.Selection == id {
				return errors.Join(errConflict, errors.New("a notification rule uses this selection"))
			}
		}
		for i, s := range c.Selections {
			if s.ID == id {
				c.Selections = append(c.Selections[:i], c.Selections[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
}

func (o Options) previewSelection(w http.ResponseWriter, r *http.Request) {
	var b selection.Selection
	if !decode(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Name) == "" {
		b.Name = "preview"
	}
	if err := b.Validate(); err != nil {
		fail(w, err)
		return
	}
	lang := o.Conf.Get().Lang
	var count inventory.Count
	var rows []inventory.Row
	o.Source.View(func(st *source.State) {
		count, rows = inventory.Preview(b, st, inventory.NewKeyIndex(st.Paramsets), lang, 20)
	})
	writeJSON(w, http.StatusOK, map[string]any{"count": count, "sample": rows, "recent": []any{}})
}

func (o Options) putTables(w http.ResponseWriter, r *http.Request) {
	var b struct {
		DeviceTable string `json:"device_table"`
	}
	if !decode(w, r, &b) {
		return
	}
	o.update(w, func(c *config.Config) error {
		c.DeviceTable = b.DeviceTable
		return nil
	})
}

// deviceRows answers the device table as the agent serves it: the rows with their index.
func (o Options) deviceRows(w http.ResponseWriter, r *http.Request) {
	col := hmmib.DeviceTbl.Append(1, 3)
	rows := []map[string]any{}
	for _, vb := range o.App.Tree.Walk(col) {
		idx := vb.OID[len(col):]
		parts, ok := snmp.DecodeStringsIndex(idx, 2)
		if !ok {
			continue
		}
		name := ""
		if v := o.App.Tree.Get(hmmib.DeviceTbl.Append(1, 5).Append(idx...)); v.Tag == snmp.TagOctetString {
			name = string(v.Bytes)
		}
		rows = append(rows, map[string]any{"interface": parts[0], "address": parts[1], "type": string(vb.Value.Bytes), "name": name, "index": snmp.OID(idx).String()})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["index"].(string) < rows[j]["index"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"column_prefix": hmmib.DeviceTbl.Append(1).String(), "rows": rows})
}

func (o Options) status(w http.ResponseWriter, r *http.Request) {
	a := o.App.Agent
	listening, lerr := o.App.Listening()
	out := map[string]any{
		"listening":       listening,
		"listen_error":    lerr,
		"has_credentials": a.HasCredentials(),
		"requests_minute": a.RequestsLastMinute(),
		"requests":        a.C.Requests.Load(),
		"auth_failures":   a.C.AuthFailures.Load(),
		"sets_refused":    a.C.SetsRefused.Load(),
		"rate_limited":    a.C.RateLimited.Load(),
		"recent":          a.Recent(),
	}
	o.Source.View(func(st *source.State) {
		age := -1
		if !st.SysAt.IsZero() {
			age = int(time.Since(st.SysAt).Seconds())
		}
		meta := int64(0)
		if st.Names != nil {
			meta = st.Names.Revision
		}
		out["source"] = map[string]any{
			"ready": st.Ready, "stream_connected": st.StreamConnected, "system_ready": st.SysReady, "system_age_s": age,
			"meta_revision": meta, "devices": len(st.Devices), "interfaces": len(st.Interfaces), "service_messages": len(st.ServiceMessages),
			"reconnects": st.Stats.StreamReconnects, "resyncs": st.Stats.Resyncs, "health": hmmib.Health(st, time.Now()),
		}
	})
	if o.Traps != nil {
		out["traps"] = o.Traps.Status()
	}
	writeJSON(w, http.StatusOK, out)
}

func (o Options) mib(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+mibs.FileName+`"`)
	w.Write(mibs.File)
}

func (o Options) putTraps(w http.ResponseWriter, r *http.Request) {
	var b config.Traps
	if !decode(w, r, &b) {
		return
	}
	o.update(w, func(c *config.Config) error {
		for i := range b.Targets {
			if b.Targets[i].ID == "" {
				b.Targets[i].ID = config.NewID()
			}
		}
		c.Traps = b
		return nil
	})
}

func (o Options) testTarget(w http.ResponseWriter, r *http.Request) {
	if o.Traps == nil {
		addonkit.WriteError(w, http.StatusNotImplemented, "unsupported", "this version sends no notifications")
		return
	}
	if err := o.Traps.Test(r.PathValue("id")); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func hostname() string { return hostmib.Hostname() }
