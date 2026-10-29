#!/bin/bash
#
#   The interop test: the daemon against the fake system (scripts/dev-serve.sh's setup, on other
#   ports), queried with net-snmp's own tools in a Debian container (test/interop/Dockerfile):
#   smilint and snmptranslate on the MIB, snmpget/snmpwalk/snmpbulkwalk over v1, v2c and v3 with
#   SHA, SHA-256 and SHA-512 x AES-128 and AES-256, the refusals (wrong password, unknown user,
#   wrong community, a set), and every OID of the Homematic tree translated through the MIB.
#
#     test/interop/run.sh            # needs docker and go
#
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE=${IMAGE:-lite-addon-snmp-interop:test}
WORK=$(mktemp -d)
HTTP=18396
SNMP=16261
FAKE=18180
API=http://127.0.0.1:$HTTP/addons/snmp/api/v1
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok   $*"; }

docker build -q -t "$IMAGE" test/interop >/dev/null
mkdir -p "$WORK/mibs" "$WORK/conf"
cp mibs/LITE-SNMP-MIB.txt "$WORK/mibs/"
go build -o "$WORK/fakesystem" ./cmd/fakesystem
go build -o "$WORK/snmp" ./cmd/snmp
echo test > "$WORK/token"
"$WORK/fakesystem" -addr 127.0.0.1:$FAKE >"$WORK/fake.log" 2>&1 &
PIDS+=($!)
sleep 0.5
"$WORK/snmp" -system http://127.0.0.1:$FAKE -no-session-check -port $HTTP -snmp-port $SNMP -listen 127.0.0.1 -conf-dir "$WORK/conf" -www ui/dist -token-file "$WORK/token" >"$WORK/daemon.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do
    curl -fsS "$API/health?ready=1" >/dev/null 2>&1 && break
    sleep 0.2
done
curl -fsS "$API/health?ready=1" >/dev/null || { cat "$WORK/daemon.log"; fail "the daemon did not get ready"; }

post() { curl -fsS -X POST -H 'X-CCU-Addon-Request: 1' -H 'Content-Type: application/json' "$API/$1" -d "$2" >/dev/null; }

run() { docker run --rm --network host -v "$WORK/mibs:/mibs:ro" "$IMAGE" "$@"; }

# the MIB: smilint at level 6 reports nothing, snmptranslate parses it
out=$(run smilint -l 6 -s /mibs/LITE-SNMP-MIB.txt 2>&1)
[ -z "$out" ] || fail "smilint: $out"
ok "smilint -l 6: clean"
run snmptranslate -m +LITE-SNMP-MIB -On LITE-SNMP-MIB::hmDevName >/dev/null || fail "snmptranslate"
ok "snmptranslate parses LITE-SNMP-MIB"

# no credential: no answer at all
if run snmpget -v2c -c public -r 0 -t 1 127.0.0.1:$SNMP .1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then fail "answered without a credential"; fi
ok "no credential, no answer"

# the users, one per protocol pair, and a community
for a in SHA SHA-256 SHA-512; do
    for p in AES AES-256; do
        post users "{\"name\":\"u-$a-$p\",\"auth\":\"$a\",\"priv\":\"$p\",\"view\":\"all\",\"auth_password\":\"authpassword1\",\"priv_password\":\"privpassword1\"}"
    done
done
post users '{"name":"hmonly","auth":"SHA-256","priv":"AES","view":"homematic","auth_password":"authpassword1","priv_password":"privpassword1"}'
post communities '{"name":"interop-community","view":"all","sources":["127.0.0.1"]}'

for a in SHA SHA-256 SHA-512; do
    for p in AES AES-256; do
        v3="-v3 -l authPriv -u u-$a-$p -a $a -A authpassword1 -x $p -X privpassword1 -r 1 -t 2"
        # shellcheck disable=SC2086
        r=$(run snmpget $v3 -Ovn 127.0.0.1:$SNMP .1.3.6.1.2.1.1.2.0) || fail "v3 $a/$p get"
        case "$r" in *1.3.6.1.4.1.8072.9999.9999.47621.4.1*) ;; *) fail "v3 $a/$p sysObjectID: $r" ;; esac
        # shellcheck disable=SC2086
        n=$(run snmpbulkwalk $v3 -Cr20 127.0.0.1:$SNMP .1.3.6.1.4.1.8072.9999.9999.47621 | wc -l)
        [ "$n" -gt 80 ] || fail "v3 $a/$p bulkwalk: $n lines"
        ok "v3 authPriv $a/$p: get and bulkwalk ($n objects)"
    done
done

# v2c and v1
n=$(run snmpwalk -v2c -c interop-community 127.0.0.1:$SNMP .1.3.6.1.2.1.1 | wc -l)
[ "$n" -ge 8 ] || fail "v2c walk of the system group: $n"
ok "v2c walk of the system group ($n)"
r=$(run snmpget -v1 -c interop-community -Ov 127.0.0.1:$SNMP .1.3.6.1.2.1.1.5.0) || fail "v1 get"
ok "v1 get sysName: $r"
if run snmpget -v1 -c interop-community 127.0.0.1:$SNMP .1.3.6.1.2.1.31.1.1.1.6.1 2>&1 | grep -q Counter64; then fail "v1 answered a Counter64"; fi
ok "v1 refuses Counter64"

# the refusals
if run snmpget -v3 -l authPriv -u u-SHA-256-AES -a SHA-256 -A wrongpassword -x AES -X privpassword1 -r 0 -t 1 127.0.0.1:$SNMP .1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then fail "a wrong password was answered"; fi
ok "wrong password refused"
if run snmpget -v3 -l authPriv -u nosuchuser -a SHA-256 -A authpassword1 -x AES -X privpassword1 -r 0 -t 1 127.0.0.1:$SNMP .1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then fail "an unknown user was answered"; fi
ok "unknown user refused"
if run snmpget -v3 -l authNoPriv -u u-SHA-256-AES -a SHA-256 -A authpassword1 -r 0 -t 1 127.0.0.1:$SNMP .1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then fail "authNoPriv was answered"; fi
ok "authNoPriv refused"
if run snmpget -v2c -c wrong -r 0 -t 1 127.0.0.1:$SNMP .1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then fail "a wrong community was answered"; fi
ok "wrong community dropped"
r=$(run snmpset -v2c -c interop-community 127.0.0.1:$SNMP .1.3.6.1.2.1.1.5.0 s hacked 2>&1 || true)
case "$r" in *noAccess*|*"Not writable"*|*"no access"*) ;; *) fail "set: $r" ;; esac
ok "set refused (noAccess)"

# the views: the Homematic user sees the tree and the system group, no IF-MIB
n=$(run snmpwalk -m ALL -v3 -l authPriv -u hmonly -a SHA-256 -A authpassword1 -x AES -X privpassword1 127.0.0.1:$SNMP .1.3.6.1.2.1.2 | grep -c ifDescr || true)
[ "$n" -eq 0 ] || fail "the homematic view shows IF-MIB"
ok "the homematic view hides the standard MIBs"

# every OID of the Homematic tree has a name in the MIB, and the values read sensibly
run snmpwalk -v3 -l authPriv -u u-SHA-256-AES -a SHA-256 -A authpassword1 -x AES -X privpassword1 -m +LITE-SNMP-MIB 127.0.0.1:$SNMP .1.3.6.1.4.1.8072.9999.9999.47621 >"$WORK/walk.txt"
if grep -q 'NET-SNMP-MIB::netSnmpPlaypen\|iso.3.6' "$WORK/walk.txt"; then grep 'netSnmpPlaypen\|iso.3.6' "$WORK/walk.txt" | head; fail "OIDs the MIB does not name"; fi
grep -q 'hmDevName."HmIP-RF"."000A1B2C3D4E5F" = STRING: Thermostat Bad' "$WORK/walk.txt" || { head -40 "$WORK/walk.txt"; fail "hmDevName"; }
grep -q 'hmDevReachable."HmIP-RF"."000E1A2B3C4D5E" = INTEGER: false(2)' "$WORK/walk.txt" || fail "hmDevReachable"
grep -q 'hmSmCount.0 = Gauge32: 2' "$WORK/walk.txt" || fail "hmSmCount"
ok "the Homematic tree: $(wc -l <"$WORK/walk.txt") objects, all named by the MIB"

# the standard MIBs NMSs poll
for o in UCD-SNMP-MIB::memTotalReal.0 UCD-SNMP-MIB::laLoadInt.1 HOST-RESOURCES-MIB::hrSystemUptime.0 HOST-RESOURCES-MIB::hrStorageDescr.1 IF-MIB::ifNumber.0 UCD-SNMP-MIB::ssCpuRawIdle.0; do
    r=$(run snmpget -m ALL -v3 -l authPriv -u u-SHA-256-AES -a SHA-256 -A authpassword1 -x AES -X privpassword1 127.0.0.1:$SNMP "$o")
    case "$r" in *"No Such"*) fail "$o: $r" ;; esac
done
ok "the standard objects NMSs poll answer"
echo "interop: all passed"
