// fakesystem runs a fake openccu-lite with a small demo system, for the page's development and
// its end-to-end tests: point the daemon's -system at it.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hobbyquaker/ccu-addon-kit/go/litesource/fakelite"

	"github.com/hobbyquaker/lite-addon-snmp/internal/fakesys"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "the address to answer on")
	flag.Parse()
	s := fakesys.NewOn(fakelite.New(), *addr)
	fakesys.Demo(s)
	log.Printf("fakesystem: %s", s.URL())
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	s.Close()
}
