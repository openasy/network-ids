# network-ids

[![CI](https://github.com/openasy/network-ids/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/network-ids/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Network IDS product: **attacks seen on the wire** (ADR 0070). Some attacks
leave no trace on a host you watch: a scan from a compromised printer, malware calling home every minute, a database
dump sent out over DNS. They show in network traffic. [Suricata](https://suricata.io/) runs on a sensor that sees a
copy of the traffic; [network-ids-agent](https://github.com/openasy/network-ids-agent) next to it sends what Suricata
saw here, and writes the local rules and suppressions you keep here on every sensor. Network IDS detects; it never
blocks traffic.

```
mirror port or tap ──▶ Suricata ──eve.json──▶ network-ids-agent ──HTTPS──▶ network-ids ──▶ alerts, flows, protocol logs
                          ▲                         │  ▲                          │
                          └── reload-rules ◀── writes openasy.rules,    ◀── local rules, suppressions
                                                threshold.config
```

## What it keeps

- **Alerts**: a signature that matched traffic, with its sid, category and endpoints. Severity comes from ET's
  `signature_severity` metadata (Critical, Major, Minor, Informational), else from Suricata's severity: 1 high, 2
  medium, 3 and more low. Each alert links to the **flow** it was in and that flow's **protocol logs**, by Suricata's
  flow id, and shows the EVE event as the sensor sent it, without packet payloads.
- **Flows**: who talked to whom, for how long, how many packets and bytes each way, and how the flow ended. Search
  them with `ip:`, `src_ip:`, `dest_ip:`, `port:`, `dest_port:`, `proto:`, `app_proto:`, `state:`, `community_id:`,
  `sensor:` and `alerted:true`.
- **Protocol logs**: DNS questions and answers, HTTP requests, TLS handshakes with their server name and JA3, and SSH
  banners, with the names seen most. Encrypted traffic shows its metadata, not its content.
- **Sensor health**: traffic, packets dropped and rules loaded or failed, from Suricata's own counters. Above 1%
  dropped a sensor is degraded: rules miss traffic.

Alerts are kept 90 days, flows, protocol logs and counters 30, unless set otherwise. A batch an agent sends twice
counts once.

## Local rules and suppressions

- **Local rules** are written here in Suricata's syntax, with a sid from 9,000,000 to 9,999,999, and checked before
  they are kept: the action is `alert` or `pass` (Network IDS does not block, so `drop` and `reject` are refused), the
  header and options must read, and `lua`, `luajit`, `dataset` and `datarep`, which read or write files on the
  sensor, are refused. Suricata is the last check: rules it cannot load show on the sensor as failed.
- **Suppressions** keep known-good traffic from alerting: a signature for every address, or only from or to one
  address or network, with a reason and an end, as Suricata's `suppress` lines. Alerts a suppression covers that still
  come in are kept and marked suppressed, never dropped silently.
- Every agent asks for the enabled rules and active suppressions, checks every line again, writes them to its own two
  files and asks Suricata to reload its rules. Rules shows how many sensors have written the current set.
- Rulesets such as ET Open stay with `suricata-update` on each sensor, as before; their count shows under Rules loaded.

## Run

```bash
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs network-ids | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/. Agents call the same address:
put a TLS proxy in front and set `NETWORK_IDS_PUBLIC_URL` to its https:// address.

Then add a sensor under Sensors. It shows a one-time enrolment token and the command that starts network-ids-agent on
the sensor host, and Setup shows what Suricata needs in its `suricata.yaml`: EVE JSON with `alert`, `flow`, `dns`,
`http`, `tls`, `ssh` and `stats`, the agent's `openasy.rules` among its rule files, its `threshold.config` as the
threshold file, and the command socket on.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `NETWORK_IDS_PUBLIC_URL` | `http://localhost:8080` | The address people and agents open, with `https://` behind your TLS proxy |
| `NETWORK_IDS_ALERT_RETENTION_DAYS` | `90` | Alerts older than this are deleted |
| `NETWORK_IDS_FLOW_RETENTION_DAYS` | `30` | Flows, protocol logs and sensor counters older than this are deleted |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher |
| `NETWORK_IDS_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `NETWORK_IDS_DB` | `/data/network-ids.db` | SQLite file (WAL), on the `/data` volume |
| `NETWORK_IDS_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `NETWORK_IDS_HEADLESS` | `false` | `true` serves only the API |
| `NETWORK_IDS_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_network_ids_alerts_last_day` by severity, `openasy_network_ids_sensors` by status,
`openasy_network_ids_sensors_outdated`, `openasy_network_ids_sensor_drop_ratio` per sensor and
`openasy_network_ids_events_received_total` by kind. Watch the sensors from a system other than Network IDS: a sensor
that stops sending is the one thing it can only show as offline.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`. Agents enrol
once with a token that works for 7 days and then call with their own secret; Network IDS keeps only hashes of both,
never connects to a sensor and sends it no commands.

## Roles

Viewers see everything; editors also write local rules and suppressions; admins also add and remove sensors, and
manage members and API tokens (ADR 0003).

## Not yet

Zeek's flow and protocol logs, packet captures on demand, choosing rulesets such as ET Open here instead of with
`suricata-update`, sending alerts to SIEM as signals, and checking addresses and domains against Threat Intel are
planned. Flows are kept in SQLite: a sensor on a busy link sends millions a day, so 0.1.0 suits small and medium
networks.

## Develop

```bash
npm install
npm test        # EVE events, rules and suppressions, sensors and their counters, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
node scripts/openapi.ts   # after changing the API
```

## Licence

AGPL-3.0 (ADR 0008).
