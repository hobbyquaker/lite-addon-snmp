// snmp is the lite-addon-snmp daemon: a read-only SNMP agent on UDP 161 with the standard MIBs
// of a Linux host and the Homematic side of openccu-lite under its own subtree, and the web page
// that configures it, served on the loopback behind lighttpd's proxy of /addons/snmp/.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit"
	"github.com/hobbyquaker/ccu-addon-kit/go/litesource"

	"github.com/hobbyquaker/lite-addon-snmp/internal/app"
	"github.com/hobbyquaker/lite-addon-snmp/internal/config"
	"github.com/hobbyquaker/lite-addon-snmp/internal/httpapi"
	"github.com/hobbyquaker/lite-addon-snmp/internal/source"
	"github.com/hobbyquaker/lite-addon-snmp/internal/trap"
)

// version is set by the build (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	log.SetFlags(0) // the journal adds the time
	addonDir := flag.String("addon-dir", "/usr/local/addons/snmp", "the addon's directory (app/)")
	confDir := flag.String("conf-dir", "/usr/local/etc/config/addons/snmp", "the configuration's directory (snmp.json, engine.json; mode 0700)")
	id := flag.String("id", "snmp", "the addon id (token file, base path)")
	port := flag.Int("port", 8296, "the loopback port lighttpd proxies to")
	snmpPort := flag.Int("snmp-port", 161, "the SNMP agent's UDP port")
	listen := flag.String("listen", "", "bind the agent to this IPv4 address only (development and tests)")
	base := flag.String("system", "http://127.0.0.1", "openccu-lite's URL")
	basePath := flag.String("base-path", "", "the path the app is served at (/addons/<id> by default)")
	www := flag.String("www", "", "the built web app (<addon-dir>/app by default)")
	tokenFile := flag.String("token-file", "", "a token file for the system's API (the addon's own token by default)")
	noSession := flag.Bool("no-session-check", false, "serve the page without the session check (development only)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *basePath == "" {
		*basePath = "/addons/" + *id
	}
	if *www == "" {
		*www = filepath.Join(*addonDir, "app")
	}
	if err := run(*confDir, *id, *port, *snmpPort, *listen, *base, *basePath, *www, *tokenFile, *noSession); err != nil {
		log.Fatalf("snmp: %v", err)
	}
}

func run(confDir, id string, port, snmpPort int, listen, base, basePath, www, tokenFile string, noSession bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conf, err := config.Open(confDir)
	if err != nil {
		return err
	}
	engine, err := config.LoadEngine(confDir)
	if err != nil {
		return err
	}
	engine.Start = time.Now()

	var token addonkit.TokenSource
	if tokenFile != "" {
		token = &addonkit.FileToken{Path: tokenFile}
	} else {
		token = addonkit.AddonToken(id)
	}
	logf := func(format string, args ...any) { log.Printf(format, args...) }
	lite := litesource.New(base, token)
	lite.Log = func(format string, args ...any) { log.Printf("snmp: "+format, args...) }
	// wait for the system: at boot its web server answers 503 "starting" until occulited is up
	if _, err := lite.Await(ctx, addonkit.IsOpenccuLite()); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("%s is not openccu-lite: this addon runs on openccu-lite only", base)
	}
	src := source.New(source.Options{Lite: lite, Sys: source.NewSysClient(base, token), Log: logf})
	go src.Run(ctx)

	a := app.New(app.Options{Conf: conf, Source: src, Engine: engine, Version: version, Port: snmpPort, Listen: listen, Log: logf})
	traps := trap.New(trap.Options{Conf: conf, Source: src, Engine: engine, Started: a.Started, Log: logf})
	a.TrapCounters, a.OnApply, a.OnAuthFailure = traps, traps.Apply, traps.AuthFailure
	go a.Run(ctx)
	go traps.Run(ctx)

	wrap := func(h http.Handler) http.Handler { return h }
	if !noSession {
		c := addonkit.NewChecker(addonkit.SessionOptions{Base: base, Need: addonkit.LevelAdmin, AddonID: id, OnRefused: func(r *http.Request, reason string) {
			log.Printf("snmp: refused %s %s: %s", r.Method, r.URL.Path, reason)
		}})
		wrap = c.Handler
	}
	h := httpapi.New(httpapi.Options{BasePath: basePath, WWW: www, App: a, Conf: conf, Source: src, Wrap: wrap, Version: version, Port: snmpPort, Traps: traps})
	l, err := addonkit.Listen(port, "")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	c := conf.Get()
	log.Printf("snmp %s: serving %s on %s; the agent on UDP %d (engine boots %d, %d users, %d communities)", version, basePath, l.Addr(), snmpPort, engine.Boots, len(c.Users), len(c.Communities))
	if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
		return err
	}
	log.Printf("snmp: stopping")
	os.Stdout.Sync()
	return nil
}
