# The page's API

The daemon serves the page and its API at `/addons/snmp/` (lighttpd proxies it to `127.0.0.1:8296`). Every request
carries the system's session; only administrators are admitted. Every write (`POST`, `PUT`, `DELETE`) needs the
header `X-CCU-Addon-Request`. Errors are `{"error": "<code>", "message": "…"}`: `invalid` (422), `not-found` (404),
`conflict` (409).

| Route | What |
| --- | --- |
| `GET api/v1/health` | `{ok, version, listening, listen_error, uptime_s}`; with `?ready=1` 503 until the system was read |
| `GET api/v1/config` | the configuration without any key: agent settings, users (name, protocols, view), communities, selections, the device table's selection, the notification targets and rules, the engine id and boots, the root |
| `PUT api/v1/agent` | `{enabled?, sys_name?, sys_location?, sys_contact?, ipv4?, ipv6?, lang?, auth_traps?}` |
| `POST api/v1/users` | `{name, auth, priv, view, auth_password, priv_password}`; the passwords at least 12 characters, stored as their derived keys only |
| `PUT api/v1/users/{name}` | `{view?, auth?, priv?, auth_password?, priv_password?}`; new passwords or a new authentication protocol need both passwords |
| `DELETE api/v1/users/{name}` | 409 while a trap target sends as the user |
| `POST api/v1/communities`, `PUT …/{id}`, `DELETE …/{id}` | `{name, view, sources}`; `sources` are addresses, prefixes or `local` |
| `GET api/v1/catalog` | the selection editor's inventory (lite-addon-forwarder's shape): interfaces, devices with channels, rooms, functions, types and keys with counts |
| `POST api/v1/selections`, `PUT …/{id}`, `DELETE …/{id}` | a selection (lite-addon-forwarder's JSON); delete answers 409 while the device table or a rule uses it |
| `POST api/v1/selections/preview` | a selection → `{count: {devices, channels, datapoints}, sample: [first 20 devices], recent: []}` |
| `PUT api/v1/tables` | `{device_table: "<selection id>" or ""}` |
| `GET api/v1/tables/devices` | the device table as the agent serves it: `{column_prefix, rows: [{interface, address, type, name, index}]}` |
| `GET api/v1/status` | requests (total, last minute), the last sources, authentication failures, refused sets, the data sources' state, and `traps: {sent, failed, targets: [{id, name, sent, failed, dropped, queued, last_error, last_sent}], recent: [{at, name, text}]}` |
| `GET api/v1/mib` | `LITE-SNMP-MIB.txt` |
| `PUT api/v1/traps` | `{targets: [{id, name, enabled, host, port, kind: v2c-trap\|v3-trap\|v3-inform, community?, user?, rules: []}], rules: [{kind, enabled, selection, threshold?}]}`; a target without an id gets one; `rules` empty sends every rule |
| `POST api/v1/traps/targets/{id}/test` | sends `hmTestNotification` now and answers how it went (an inform's acknowledgement included) |
