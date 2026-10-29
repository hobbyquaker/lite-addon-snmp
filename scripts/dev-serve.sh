#!/bin/sh
#
#   Runs the daemon against the fake system, for the page's development and the Playwright tests:
#   the fake on 127.0.0.1:18080, the page on http://127.0.0.1:18296/addons/snmp/ (no session
#   check), the agent on UDP 127.0.0.1:16161. A fresh configuration directory each run unless
#   SNMP_CONF_DIR names one. The page is served from ui/dist (npm run build first).
#
set -e
cd "$(dirname "$0")/.."
DIR=${SNMP_CONF_DIR:-$(mktemp -d)}
mkdir -p build
go build -o build/fakesystem ./cmd/fakesystem
go build -o build/snmp-dev ./cmd/snmp
echo dev > "$DIR/token"
build/fakesystem -addr 127.0.0.1:18080 &
FAKE=$!
sleep 0.5
build/snmp-dev -system http://127.0.0.1:18080 -no-session-check -port 18296 -snmp-port 16161 -listen 127.0.0.1 -conf-dir "$DIR" -www ui/dist -token-file "$DIR/token" &
DAEMON=$!
trap 'kill $DAEMON $FAKE 2>/dev/null' EXIT INT TERM
wait $DAEMON
