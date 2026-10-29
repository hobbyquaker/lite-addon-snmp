# Changelog

## [0.1.0] - 2026-10-30

The first release, for openccu-lite.

- **The agent:** SNMPv1, v2c and v3 on UDP 161 (IPv4 and IPv6), `Get`, `GetNext` and `GetBulk`, read-only (every set
  is refused with `noAccess`). SNMPv3 is always authPriv: SHA-256 (default), SHA-1, SHA-224, SHA-384, SHA-512 with
  AES-128 (default), AES-192, AES-256; the engine id is made once and kept, the boots counted. v1/v2c communities
  only when added, and only from the listed networks (default: the local ones). No default credential: without one
  the agent answers nobody. A view per credential (everything, the standard MIBs, the Homematic tree), a rate limit
  per source and a block after repeated authentication failures.
- **Standard MIBs** in net-snmp's Linux shape, from `/proc`, `/sys` and `statfs`: the system and snmp groups,
  IF-MIB with `ifXTable`, EtherLike duplex, HOST-RESOURCES (storage, processors and their load), UCD-SNMP (memory,
  load, CPU counters, disks), UCD-DISKIO and the temperature sensors.
- **LITE-SNMP-MIB** under a **provisional root** in net-snmp's experimental area
  (`1.3.6.1.4.1.8072.9999.9999.47621`): the system's version and health, the interface table (radio connected, duty
  cycle, carrier sense, device and message counts, events), the service messages, the device table (reachable,
  battery, configuration pending, RSSI, operating voltage, last seen) and statistics. String indices, so rows keep
  their OIDs. The root will move to an own IANA Private Enterprise Number; the agent will answer both trees for one
  version then, and the release notes will say when to replace the MIB.
- **Selections** choose the device table's rows: ticked or excluded devices and channels, rules by interface,
  device type, channel type, datapoint (wildcards), room and function, a live count and a preview. The model and the
  editor are lite-addon-forwarder's.
- **No radio load:** values come from the system's state store and event stream; a request reads only the agent's
  memory.
- **The page** (`/addons/snmp/`, administrators only): agent, access (users and communities, a `snmpwalk` hint per
  user), selections, tables, status; the MIB as a download. German and English, light and dark.
