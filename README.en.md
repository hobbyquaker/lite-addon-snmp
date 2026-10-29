# lite-addon-snmp

*[Deutsch](README.md)*

An **SNMP agent** for [openccu-lite](https://github.com/hobbyquaker/openccu-lite): the standard MIBs of a Linux host
that LibreNMS, Zabbix, PRTG and Checkmk poll, and the **Homematic side** of the system in a tree of its own -
interfaces with duty cycle and radio state, service messages, devices with reachability, battery and signal
strength. Read-only, SNMPv3 with SHA-256 and AES by default.

> **Provisional OIDs.** For now the Homematic tree lives under net-snmp's experimental area
> (`NET-SNMP-MIB::netSnmpPlaypen`, `1.3.6.1.4.1.8072.9999.9999.47621`). It moves to an own IANA Private Enterprise
> Number once that is assigned, and its OIDs change then. For one version the agent will answer both trees, and the
> release notes will say when to replace the MIB in your monitoring system. The standard MIBs are not affected.

![Access](docs/screenshots/02-zugang.png)

## What it does

- **An SNMP agent on UDP 161**, in Go, without net-snmp: `Get`, `GetNext` and `GetBulk` over SNMPv1, v2c and v3.
  **Every write is refused** (`noAccess`); there is no code path that sets anything.
- **SNMPv3 authPriv**: authentication SHA-256 (default), SHA-1, SHA-224, SHA-384, SHA-512; privacy AES-128
  (default), AES-192, AES-256. Separate passwords for both, at least 12 characters each; only the derived keys are
  stored, in a file only the addon can read. **v1/v2c is off** until you add a community, and a community is only
  accepted from the networks listed (default: the local ones). **There is no default credential:** without a user or
  a community the agent answers nobody.
- **A view per credential:** everything, the standard MIBs only, or the Homematic tree only.
- **Standard MIBs**, computed from `/proc`, `/sys` and `statfs`, in the shape net-snmp gives on Linux: SNMPv2-MIB
  (system; `sysDescr` starts with `Linux`), IF-MIB (`ifTable`, `ifXTable` with 64-bit counters), EtherLike-MIB
  (duplex), HOST-RESOURCES-MIB (memory and filesystems in `hrStorageTable`, processors with `hrProcessorLoad`),
  UCD-SNMP-MIB (memory, load, `ssCpuRaw*`, `dskTable`), UCD-DISKIO-MIB and the temperature sensors
  (`lmTempSensorsTable`). No process list.
- **The Homematic tree** (`LITE-SNMP-MIB`, a download on the page and in every release):
  - `hmSystem`: the openccu-lite and OpenCCU versions, health (`ok`/`degraded`/`unknown`), Status warnings;
  - `hmInterfaceTable`: per interface the process running, the radio connected, duty cycle, carrier sense,
    threshold, module, firmware, devices, unreachable devices, low batteries, service messages, events;
  - `hmServiceMessages`: the count, per kind, and each message with device, name, rooms and since when;
  - `hmDeviceTable`: per device type, firmware, name, rooms, functions, reachable, battery, configuration pending,
    RSSI, operating voltage, duty cycle, service messages, last seen;
  - `hmStatistics`: the event stream, subscribers, requests, authentication failures.

  Every table is indexed by **strings** (interface, address, key): a row keeps its OID across restarts and
  re-pairing, and the history in the monitoring system stays with the device.
- **Selections** decide which devices the device table lists: tick or exclude devices and channels, plus rules by
  interface, device type, channel type, datapoint (with wildcards: `LOW*`, `*_TEMPERATURE`), room and function. The
  editor shows live how many devices, channels and datapoints match. It is the same model and the same editor as in
  [lite-addon-forwarder](https://github.com/hobbyquaker/lite-addon-forwarder).
- **No radio load:** the values come from the system's state store and event stream. An SNMP request reads only the
  agent's memory; the agent never calls `getValue` and never causes a radio transmission.
- **Status:** requests per minute, the last sources with their credential, authentication failures, the state of
  the data sources, and a ready `snmpwalk` line per user (without the passwords).

Notifications (traps and informs) follow in 0.2.0, a datapoint table in a later version.

## Installation

1. Install the package `snmp-<arch>-<version>.tar.gz` from the
   [releases page](https://github.com/hobbyquaker/lite-addon-snmp/releases) through the system's Addons page. The
   addon is not in the catalogue for now.
2. On the addon's page (*SNMP* in the addon menu, or *Settings* on the Addons page) add an SNMPv3 user under
   **Access**.
3. Open the port: **Addons → SNMP → Addon ports → UDP 161**. It is closed until you open it. Opened, it is reachable
   from everywhere: narrow the rule to your monitoring system's address on the **Firewall** page.
4. Test it from the monitoring system:

   ```sh
   snmpwalk -v3 -l authPriv -u nms -a SHA-256 -A '<password>' -x AES -X '<password>' <system> .1.3.6.1.2.1.1
   ```

The addon runs as its own user with exactly one extra privilege: `CAP_NET_BIND_SERVICE` for port 161. It reads with
the scopes `rpc:read`, `meta:read` and `system:read` and cannot switch or change anything.

## In the monitoring system

**LibreNMS** detects the system as Linux (`sysDescr`) and shows processors, memory, filesystems, network and
temperatures. Add the device with SNMPv3, *authPriv*, SHA-256 and AES. For the Homematic values put the MIB
(`LITE-SNMP-MIB.txt`) into `mibs/` and add, say, `hmIfDutyCycle` or `hmDevReachable` as custom sensors.

**Zabbix**: the template *Linux by SNMP* covers the standard MIBs. For the Homematic values, low-level discovery
over the tables works, for example:

- discovery `discovery[{#IFNAME},1.3.6.1.4.1.8072.9999.9999.47621.1.2.1.8]` (the module column of the interface
  table), item prototype `1.3.6.1.4.1.8072.9999.9999.47621.1.2.1.5.{#SNMPINDEX}` (duty cycle, %);
- discovery `discovery[{#DEVNAME},1.3.6.1.4.1.8072.9999.9999.47621.1.4.1.5]` (device name), item prototypes
  `….1.4.1.9.{#SNMPINDEX}` (reachable: 1 yes, 2 no, 3 unknown) and `….1.4.1.10.{#SNMPINDEX}` (low battery).

`{#SNMPINDEX}` is the index as a string in OID form (the length, then the characters). The *Tables* page shows it
for every row.

## Privacy and security

- Read-only; writes are refused and counted.
- No credential, no answer; SNMPv3 always encrypted; v1/v2c only on purpose and only from listed networks; a rate
  limit per source and a block after repeated failed logins.
- No outgoing connections (from 0.2.0 only to the trap targets you set up). No telemetry.
- The configuration lives in `/usr/local/etc/config/addons/snmp/` (mode 0600) and is part of the system backup. An
  uninstall leaves it for a reinstall.

## Development

```sh
go test -race ./...                         # the Go tests, with gosnmp as an independent client
(cd ui && npm ci && npm run check && npm test && npm run build)
(cd ui && npx playwright test)              # the page against the fake system (scripts/dev-serve.sh)
test/interop/run.sh                         # net-snmp and smilint in docker against the agent
VERSION=0.1.0 scripts/build.sh              # the packages for aarch64, x86_64 and armv7l
```

`scripts/dev-serve.sh` runs the daemon against a small demo system: the page at
`http://127.0.0.1:18296/addons/snmp/`, the agent on UDP `127.0.0.1:16161`.

## Licence

MIT. See [LICENSE](LICENSE).
