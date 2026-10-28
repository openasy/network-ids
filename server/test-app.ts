// Starts the app on a random port for tests, with a clock the tests move, and builds EVE events as Suricata writes them.
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createAuth } from "@openasy/auth";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createIds, type IdsOptions } from "./ids.ts";

export const ADMIN_TOKEN = "test-admin-token";
export const T0 = Date.parse("2026-10-28T14:00:00Z");

/** Suricata's timestamp form: 2026-10-28T13:58:12.114231+0000. */
export const eveTs = (t: number) => new Date(t).toISOString().replace("Z", "000+0000");

export const alertEvent = (o: Record<string, unknown> = {}) => ({
  timestamp: eveTs(T0 - 60_000),
  flow_id: 1_234_567_890_123,
  in_iface: "eth1",
  event_type: "alert",
  src_ip: "192.0.2.17",
  src_port: 53122,
  dest_ip: "203.0.113.53",
  dest_port: 53,
  proto: "UDP",
  app_proto: "dns",
  community_id: "1:Yh5fXo0pY2Tz1u0Fo8Hc3JxB0kE=",
  alert: {
    action: "allowed",
    gid: 1,
    signature_id: 2027758,
    rev: 3,
    signature: "ET POLICY Possible data exfiltration via DNS tunnel",
    category: "Potential Corporate Privacy Violation",
    severity: 1,
    metadata: { signature_severity: ["Critical"] },
  },
  ...o,
});

export const flowEvent = (o: Record<string, unknown> = {}) => ({
  timestamp: eveTs(T0 - 30_000),
  flow_id: 1_234_567_890_123,
  event_type: "flow",
  src_ip: "192.0.2.17",
  src_port: 53122,
  dest_ip: "203.0.113.53",
  dest_port: 53,
  proto: "UDP",
  app_proto: "dns",
  community_id: "1:Yh5fXo0pY2Tz1u0Fo8Hc3JxB0kE=",
  flow: {
    pkts_toserver: 812,
    pkts_toclient: 790,
    bytes_toserver: 48_211_000,
    bytes_toclient: 3_904_000,
    start: eveTs(T0 - 2_500_000),
    end: eveTs(T0 - 40_000),
    age: 2466,
    state: "established",
    reason: "timeout",
    alerted: true,
  },
  ...o,
});

export const dnsEvent = (o: Record<string, unknown> = {}) => ({
  timestamp: eveTs(T0 - 59_000),
  flow_id: 1_234_567_890_123,
  event_type: "dns",
  src_ip: "192.0.2.17",
  src_port: 53122,
  dest_ip: "203.0.113.53",
  dest_port: 53,
  proto: "UDP",
  dns: { version: 2, type: "answer", id: 41873, rrname: "aGVsbG8.d2b1.tunnel.example.com", rrtype: "TXT", rcode: "NOERROR", answers: [] },
  ...o,
});

export const statsEvent = (t: number, o: { uptime: number; packets: number; drops: number; bytes: number }) => ({
  timestamp: eveTs(t),
  event_type: "stats",
  stats: {
    uptime: o.uptime,
    capture: { kernel_packets: o.packets, kernel_drops: o.drops },
    decoder: { pkts: o.packets, bytes: o.bytes },
    detect: { engines: [{ id: 0, last_reload: eveTs(T0 - 3_600_000), rules_loaded: 48_912, rules_failed: 0 }] },
  },
});

export async function startApp(opts: Partial<AppOptions> & { version: string; idsOptions?: Partial<IdsOptions> }) {
  const db = openDb(":memory:");
  let now = T0;
  const { idsOptions, ...appOptions } = opts;
  const ids = createIds(db, { version: opts.version, clock: () => now, ...idsOptions });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "network-ids", productName: "OpenAsy Network IDS", origin: base });
  handler = createApp({ db, ids, auth, adminToken: ADMIN_TOKEN, ...appOptions });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const send = (method: string, path: string, body?: unknown) => admin(path, { method, ...(body !== undefined && { body: JSON.stringify(body) }) });

  /** Adds a sensor and enrols it as its agent would; returns the agent's calls. */
  async function sensor(name = "nids-core-01", agentVersion = opts.version) {
    const added = (await (await send("POST", "/api/v1/sensors", { name, description: "Frankfurt DC, core switch SPAN" })).json()) as any;
    const report = { version: agentVersion, hostname: `${name}.example.com`, evePath: "/var/log/suricata/eve.json", configHash: null, configError: null };
    const enrolled = (await (
      await fetch(`${base}/api/v1/agent/enroll`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: added.enrollToken, ...report }),
      })
    ).json()) as any;
    const agent = as(enrolled.secret);
    return {
      id: added.sensor.id as string,
      secret: enrolled.secret as string,
      events: async (events: unknown[]) => (await agent("/api/v1/agent/events", { method: "POST", body: JSON.stringify({ events }) })).json() as Promise<any>,
      config: (extra: Record<string, unknown> = {}) => agent("/api/v1/agent/config", { method: "POST", body: JSON.stringify({ ...report, ...extra }) }),
    };
  }

  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, ids, auth, base, admin, get, send, sensor, close, later: (ms: number) => (now += ms) };
}
