import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { alertEvent, dnsEvent, flowEvent, startApp, statsEvent, T0 } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;

beforeEach(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterEach(() => app.close());

describe("sensors", () => {
  it("enrol once with their token, and then call with their own secret", async () => {
    const added = (await (await app.send("POST", "/api/v1/sensors", { name: "nids-edge-fra" })).json()) as any;
    expect(added.sensor.status).toBe("waiting-to-enrol");
    expect(added.enrollToken).toMatch(/^oie_/);
    const report = { version: "0.1.0", hostname: "fra", evePath: "/var/log/suricata/eve.json", configHash: null, configError: null };
    const enroll = () => fetch(`${app.base}/api/v1/agent/enroll`, { method: "POST", body: JSON.stringify({ token: added.enrollToken, ...report }) });
    const first = await enroll();
    expect(first.status).toBe(200);
    expect(((await first.json()) as any).secret).toMatch(/^oia_/);
    expect((await enroll()).status).toBe(401);
    // Neither the token nor the secret is kept, only their hashes.
    expect(JSON.stringify(app.db.prepare("SELECT * FROM sensors").all())).not.toContain("oia_");
    const [s] = (await app.get("/api/v1/sensors")).sensors;
    expect(s).toMatchObject({ name: "nids-edge-fra", status: "online", hostname: "fra", config: { upToDate: false } });
  });

  it("refuse an agent of another version, and an unknown secret", async () => {
    const s = await app.sensor("nids-core-02", "0.0.9");
    expect((await s.config()).status).toBe(409);
    expect((await app.get(`/api/v1/sensors/${s.id}`)).status).toBe("version-mismatch");
    const res = await fetch(`${app.base}/api/v1/agent/config`, { method: "POST", headers: { authorization: "Bearer oia_nope" }, body: "{}" });
    expect(res.status).toBe(401);
  });

  it("go offline when not heard from, and enrol again with a new token", async () => {
    const s = await app.sensor();
    app.later(5 * 60_000);
    expect((await app.get(`/api/v1/sensors/${s.id}`)).status).toBe("offline");
    const again = (await (await app.send("POST", `/api/v1/sensors/${s.id}/enroll-token`)).json()) as any;
    expect(again.sensor.status).toBe("waiting-to-enrol");
    expect((await s.config()).status).toBe(401);
  });

  it("show traffic and loss from Suricata's counters, and degrade above 1% dropped", async () => {
    const s = await app.sensor();
    await s.events([
      statsEvent(T0 - 120_000, { uptime: 100, packets: 10_000, drops: 0, bytes: 1_000_000 }),
      statsEvent(T0 - 110_000, { uptime: 110, packets: 11_000, drops: 0, bytes: 2_000_000 }),
      statsEvent(T0 - 60_000, { uptime: 160, packets: 20_000, drops: 180, bytes: 7_000_000 }),
    ]);
    const got = await app.get(`/api/v1/sensors/${s.id}`);
    // The middle row came within a minute of the first and is left out.
    expect(got.suricata).toMatchObject({ rulesLoaded: 48_912, bitsPerSecond: 800_000, packetsPerSecond: 167, dropRatio: 0.018 });
    expect(got.status).toBe("degraded");
    expect(got.lastDay).toHaveLength(24);
  });
});

describe("events in", () => {
  it("keep alerts, flows and protocol logs, linked by the flow, and a batch sent twice once", async () => {
    const s = await app.sensor();
    const batch = [alertEvent(), dnsEvent(), flowEvent(), { ...alertEvent(), event_type: "fileinfo" }];
    expect(await s.events(batch)).toMatchObject({ alert: 1, flow: 1, record: 1, ignored: 1, refused: 0, duplicate: 0 });
    expect(await s.events(batch)).toMatchObject({ duplicate: 3 });
    const { alerts, total } = await app.get("/api/v1/alerts");
    expect(total).toBe(1);
    expect(alerts[0]).toMatchObject({ severity: "critical", sensor: { name: "nids-core-01" }, srcIp: "192.0.2.17", sid: 2027758 });
    const detail = await app.get(`/api/v1/alerts/${alerts[0].id}`);
    expect(detail.flow).toMatchObject({ bytesToServer: 48_211_000, state: "established" });
    expect(detail.records[0]).toMatchObject({ kind: "dns", name: "aGVsbG8.d2b1.tunnel.example.com" });
    expect(detail.event.alert.signature_id).toBe(2027758);
    const flows = await app.get("/api/v1/flows?q=dest_port:53 app_proto:dns");
    expect(flows).toMatchObject({ total: 1, bytes: 52_115_000, longLived: 0 });
    expect((await app.get(`/api/v1/flows/${flows.flows[0].id}`)).alerts).toHaveLength(1);
    expect(await app.get("/api/v1/protocols/dns")).toMatchObject({ total: 1, clients: 1, top: [{ name: "aGVsbG8.d2b1.tunnel.example.com", count: 1 }] });
  });

  it("are taken gzipped, and refused without a sensor's secret", async () => {
    const s = await app.sensor();
    const res = await fetch(`${app.base}/api/v1/agent/events`, {
      method: "POST",
      headers: { authorization: `Bearer ${s.secret}`, "content-type": "application/json", "content-encoding": "gzip" },
      body: gzipSync(JSON.stringify({ events: [alertEvent()] })),
    });
    expect(((await res.json()) as any).alert).toBe(1);
    expect((await app.send("POST", "/api/v1/agent/events", { events: [] })).status).toBe(401);
  });

  it("count and name what is refused, and leave out what is past retention", async () => {
    const s = await app.sensor();
    const r = await s.events([alertEvent({ src_ip: "x" }), alertEvent({ timestamp: "2025-01-01T00:00:00.000000+0000" })]);
    expect(r).toMatchObject({ refused: 1, ignored: 1, refusals: ["src_ip and dest_ip must be addresses"] });
  });

  it("are searched by signature, address or sid, and filtered by severity and sensor", async () => {
    const s = await app.sensor();
    await s.events([
      alertEvent(),
      alertEvent({
        flow_id: 2,
        src_ip: "192.0.2.44",
        alert: { signature_id: 2024364, signature: "ET SCAN Possible Nmap User-Agent Observed", category: "Web Application Attack", severity: 2 },
      }),
    ]);
    expect((await app.get("/api/v1/alerts?q=nmap")).total).toBe(1);
    expect((await app.get("/api/v1/alerts?q=192.0.2.44")).total).toBe(1);
    expect((await app.get("/api/v1/alerts?q=2027758")).total).toBe(1);
    expect((await app.get("/api/v1/alerts?q=%25")).total).toBe(0);
    expect((await app.get("/api/v1/alerts?severity=medium&severity=critical")).total).toBe(2);
    expect((await app.get(`/api/v1/alerts?sensor=${s.id}&severity=low`)).total).toBe(0);
    expect((await app.send("GET", "/api/v1/alerts?severity=urgent")).status).toBe(422);
    expect((await app.send("GET", "/api/v1/flows?q=colour:blue")).status).toBe(422);
  });
});

describe("local rules and suppressions", () => {
  it("are what every sensor is given, and a sensor that wrote them is up to date", async () => {
    const s = await app.sensor();
    const rule = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Admin path probe"; http.uri; content:"/admin"; sid:9000104; rev:1;)';
    expect((await app.send("POST", "/api/v1/rules", { text: rule })).status).toBe(201);
    expect((await app.send("POST", "/api/v1/rules", { text: rule })).status).toBe(409);
    expect((await app.send("POST", "/api/v1/rules", { text: rule.replace("alert", "drop") })).status).toBe(422);
    expect((await app.send("POST", "/api/v1/suppressions", { sid: 2013028, track: "by_src", network: "192.0.2.9", reason: "Build runner" })).status).toBe(201);
    const config = (await (await s.config()).json()) as any;
    expect(config.rules).toEqual([rule]);
    expect(config.suppressions).toEqual(["suppress gen_id 1, sig_id 2013028, track by_src, ip 192.0.2.9"]);
    expect((await app.get("/api/v1/rules")).deployment).toMatchObject({ total: 1, outdated: 1 });
    await s.config({ configHash: config.hash });
    expect((await app.get("/api/v1/rules")).deployment).toMatchObject({ total: 1, outdated: 0 });
    expect((await app.get(`/api/v1/sensors/${s.id}`)).config.upToDate).toBe(true);
  });

  it("check a rule without keeping it", async () => {
    const check = async (text: string) => (await (await app.send("POST", "/api/v1/rules/check", { text })).json()) as any;
    expect(await check('alert tcp any any -> any 2222 (msg:"LOCAL SSH"; sid:9000101;)')).toMatchObject({ ok: true, sid: 9_000_101, rev: 1 });
    expect(await check('alert tcp any any -> any 2222 (msg:"LOCAL SSH"; lua:x.lua; sid:9000101;)')).toMatchObject({
      ok: false,
      error: expect.stringMatching(/files/),
    });
  });

  it("can be turned off, changed and deleted", async () => {
    const r = (await (await app.send("POST", "/api/v1/rules", { text: 'alert ip any any -> any any (msg:"LOCAL x"; sid:9000001;)' })).json()) as any;
    expect((await (await app.send("PUT", `/api/v1/rules/${r.id}`, { enabled: false })).json()) as any).toMatchObject({ enabled: false });
    expect(app.ids.config().rules).toEqual([]);
    const changed = (await (
      await app.send("PUT", `/api/v1/rules/${r.id}`, { text: 'alert ip any any -> any any (msg:"LOCAL y"; sid:9000002; rev:2;)' })
    ).json()) as any;
    expect(changed).toMatchObject({ sid: 9_000_002, rev: 2, msg: "LOCAL y", enabled: false });
    expect((await app.send("DELETE", `/api/v1/rules/${r.id}`)).status).toBe(204);
    expect((await app.send("DELETE", `/api/v1/rules/${r.id}`)).status).toBe(404);
  });

  it("mark the alerts they cover, which stay to be seen", async () => {
    const s = await app.sensor();
    const curl = { signature_id: 2013028, signature: "ET POLICY curl User-Agent Outbound", category: "Attempted Information Leak", severity: 3 };
    const sup = (await (
      await app.send("POST", "/api/v1/suppressions", { sid: 2013028, track: "by_src", network: "192.0.2.0/28", reason: "Build runners" })
    ).json()) as any;
    await s.events([alertEvent({ src_ip: "192.0.2.9", alert: curl }), alertEvent({ src_ip: "192.0.2.99", alert: curl })]);
    expect((await app.get("/api/v1/alerts")).alerts.map((a: any) => a.srcIp)).toEqual(["192.0.2.99"]);
    const hidden = (await app.get("/api/v1/alerts?suppressed=true")).alerts;
    expect(hidden).toHaveLength(1);
    expect((await app.get(`/api/v1/alerts/${hidden[0].id}`)).suppression).toMatchObject({ id: sup.id, reason: "Build runners" });
    expect((await app.get("/api/v1/summary")).alerts).toMatchObject({ lastDay: 1, suppressed: 1 });
    // Ended, it is kept for the alerts it covered, and no longer sent.
    expect((await app.send("DELETE", `/api/v1/suppressions/${sup.id}`)).status).toBe(204);
    expect((await app.get("/api/v1/suppressions")).suppressions[0].state).toBe("expired");
    expect(app.ids.config().suppressions).toEqual([]);
  });

  it("refuse suppressions that are not clear", async () => {
    const bad = async (b: unknown) => (await app.send("POST", "/api/v1/suppressions", b)).status;
    expect(await bad({ sid: 1, reason: "" })).toBe(422);
    expect(await bad({ sid: 1, track: "by_src", reason: "x" })).toBe(422);
    expect(await bad({ sid: 1, track: "by_src", network: "example.com", reason: "x" })).toBe(422);
    expect(await bad({ sid: 1, reason: "x", expiresAt: "2020-01-01T00:00:00Z" })).toBe(422);
    expect(await bad({ sid: 1, reason: "x", expiresAt: new Date(T0 + 86_400_000).toISOString() })).toBe(201);
  });
});

describe("the product", () => {
  it("names itself, sums up the day, and has metrics for Prometheus", async () => {
    const s = await app.sensor();
    await s.events([alertEvent(), flowEvent()]);
    expect(await (await fetch(`${app.base}/api/v1/version`)).json()).toEqual({ product: "network-ids", version: "0.1.0" });
    const summary = await app.get("/api/v1/summary");
    expect(summary.alerts).toMatchObject({ lastDay: 1, bySeverity: { critical: 1 }, lastHourCritical: 1 });
    expect(summary.alerts.perHour).toHaveLength(24);
    expect(summary.alerts.perHour[22].critical).toBe(1);
    expect(summary.talkers).toEqual([{ ip: "192.0.2.17", bytes: 52_115_000 }]);
    expect(summary.sensors).toMatchObject({ total: 1, online: 1 });
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="network-ids",version="0.1.0"} 1');
    expect(metrics).toContain('openasy_network_ids_alerts_last_day{severity="critical"} 1');
    expect(metrics).toContain('openasy_network_ids_sensors{status="online"} 1');
    expect(metrics).toContain('openasy_network_ids_events_received_total{kind="alert"} 1');
  });

  it("deletes what is past retention", async () => {
    const s = await app.sensor();
    await s.events([alertEvent(), flowEvent(), dnsEvent()]);
    app.later(31 * 86_400_000);
    app.ids.purge();
    expect((await app.get("/api/v1/flows?hours=2000")).total).toBe(0);
    expect((await app.get("/api/v1/alerts?hours=2000")).total).toBe(1);
    app.later(60 * 86_400_000);
    app.ids.purge();
    expect((await app.get("/api/v1/alerts?hours=3000")).total).toBe(0);
  });

  it("goes with what a deleted sensor sent", async () => {
    const s = await app.sensor();
    await s.events([alertEvent()]);
    expect((await app.send("DELETE", `/api/v1/sensors/${s.id}`)).status).toBe(204);
    expect((await app.get("/api/v1/alerts")).total).toBe(0);
  });
});
