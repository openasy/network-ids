// What the sensors saw and what was decided about it (ADR 0070): alerts, flows and protocol logs from Suricata's EVE
// events, and the local rules and suppressions every sensor is given. Network IDS detects and never blocks.
import { createHash, randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { bad, IdsError } from "./errors.ts";
import { readEvent, RECORD_KINDS, type AlertEvent, type Event, type RecordKind, type Severity } from "./eve.ts";
import { log } from "./log.ts";
import { inNetwork, parseNetwork, parseRule, RuleError, suppressLine } from "./rules.ts";
import { createSensors, type Sensors } from "./sensors.ts";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
/** Events in one batch from an agent; it sends more at once when more are waiting. */
export const MAX_EVENTS = 5_000;
/** The part of an alert's EVE event that is kept to show, without its payload. */
const MAX_EVENT_JSON = 32 * 1024;
const MAX_ROWS = 500;

interface AlertRow {
  id: number;
  sensor_id: string;
  time: string;
  flow_id: string | null;
  community_id: string | null;
  src_ip: string;
  src_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  proto: string;
  app_proto: string | null;
  gid: number;
  sid: number;
  rev: number;
  signature: string;
  category: string;
  severity: Severity;
  action: string;
  suppressed_by: string | null;
  event: string;
}

interface FlowRow {
  id: number;
  sensor_id: string;
  start: string;
  end: string;
  flow_id: string | null;
  community_id: string | null;
  src_ip: string;
  src_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  proto: string;
  app_proto: string | null;
  pkts_toserver: number;
  pkts_toclient: number;
  bytes_toserver: number;
  bytes_toclient: number;
  state: string | null;
  reason: string | null;
  alerted: number;
}

interface RecordRow {
  id: number;
  sensor_id: string;
  time: string;
  kind: RecordKind;
  flow_id: string | null;
  src_ip: string;
  src_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  name: string;
  detail: string;
}

interface RuleRow {
  id: string;
  sid: number;
  rev: number;
  msg: string;
  text: string;
  enabled: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

interface SuppressionRow {
  id: string;
  gid: number;
  sid: number;
  track: "by_src" | "by_dst" | null;
  network: string | null;
  reason: string;
  created_by: string;
  created_at: string;
  expires_at: string | null;
}

export interface IdsOptions {
  version: string;
  /** Alerts older than this are deleted. */
  alertRetentionDays?: number;
  /** Flows, protocol logs and sensor counters older than this are deleted. */
  flowRetentionDays?: number;
  clock?: () => number;
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const HOUR = 3_600_000;

/** `key:value` terms of the flow search; a bare term is an address or a name. */
const FLOW_TERMS: Record<string, (v: string) => [string, SQLInputValue[]]> = {
  ip: (v) => ["(src_ip = ? OR dest_ip = ?)", [v, v]],
  src_ip: (v) => ["src_ip = ?", [v]],
  dest_ip: (v) => ["dest_ip = ?", [v]],
  port: (v) => ["(src_port = ? OR dest_port = ?)", [Number(v), Number(v)]],
  src_port: (v) => ["src_port = ?", [Number(v)]],
  dest_port: (v) => ["dest_port = ?", [Number(v)]],
  proto: (v) => ["proto = ?", [v.toUpperCase()]],
  app_proto: (v) => ["app_proto = ?", [v.toLowerCase()]],
  state: (v) => ["state = ?", [v]],
  community_id: (v) => ["community_id = ?", [v]],
  sensor: (v) => ["sensor_id IN (SELECT id FROM sensors WHERE name = ?)", [v]],
  alerted: (v) => ["alerted = ?", [v === "true" ? 1 : 0]],
};
export const FLOW_KEYS = Object.keys(FLOW_TERMS);

/** The SQL of a flow search, or a refusal naming the term that is not understood. */
export function flowQuery(q: string): { where: string; params: SQLInputValue[] } {
  const clauses: string[] = [];
  const params: SQLInputValue[] = [];
  for (const term of q.trim().split(/\s+/).filter(Boolean).slice(0, 10)) {
    const at = term.indexOf(":");
    const key = at > 0 ? term.slice(0, at) : "ip";
    const value = at > 0 ? term.slice(at + 1) : term;
    const build = FLOW_TERMS[key];
    if (!build || !value) throw bad(`Search with ${FLOW_KEYS.map((k) => `${k}:`).join(", ")} or an address; ${term} is none of them.`);
    if (key.endsWith("port") && !/^\d{1,5}$/.test(value)) throw bad(`${key} is a port number.`);
    const [sql, p] = build(value);
    clauses.push(sql);
    params.push(...p);
  }
  return { where: clauses.length ? clauses.join(" AND ") : "1 = 1", params };
}

export function createIds(db: DatabaseSync, o: IdsOptions) {
  const now = o.clock ?? Date.now;
  const iso = (t = now()) => new Date(t).toISOString();
  const sensors: Sensors = createSensors(db, { version: o.version, clock: o.clock });
  const received = new Map<string, number>();
  let refusedTotal = 0;

  // ---- Local rules and suppressions --------------------------------------------------------------------------------

  const ruleRow = (id: string) => db.prepare("SELECT * FROM local_rules WHERE id = ?").get(id) as RuleRow | undefined;
  const toRule = (r: RuleRow) => ({
    id: r.id,
    sid: r.sid,
    rev: r.rev,
    msg: r.msg,
    text: r.text,
    enabled: r.enabled === 1,
    createdBy: r.created_by,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    alertsLastDay: (db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE gid = 1 AND sid = ? AND time > ?").get(r.sid, iso(now() - 86_400_000)) as { n: number })
      .n,
  });

  function checkRule(text: unknown) {
    if (typeof text !== "string") throw bad("text is the rule, in Suricata's syntax.");
    try {
      return parseRule(text);
    } catch (err) {
      if (err instanceof RuleError) throw bad(err.message);
      throw err;
    }
  }

  const activeSuppressions = () =>
    db.prepare("SELECT * FROM suppressions WHERE expires_at IS NULL OR expires_at > ? ORDER BY sid, created_at").all(iso()) as unknown as SuppressionRow[];

  const toSuppression = (s: SuppressionRow) => ({
    id: s.id,
    gid: s.gid,
    sid: s.sid,
    track: s.track,
    network: s.network,
    reason: s.reason,
    createdBy: s.created_by,
    createdAt: s.created_at,
    expiresAt: s.expires_at,
    state: (s.expires_at && s.expires_at <= iso() ? "expired" : "active") as "active" | "expired",
    line: suppressLine(s),
    signature:
      (db.prepare("SELECT signature FROM alerts WHERE gid = ? AND sid = ? ORDER BY time DESC LIMIT 1").get(s.gid, s.sid) as { signature: string } | undefined)
        ?.signature ?? null,
    suppressedLastDay: (db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE suppressed_by = ? AND time > ?").get(s.id, iso(now() - 86_400_000)) as { n: number })
      .n,
  });

  /** What every sensor is given: the enabled local rules and the active suppressions, and their hash. */
  function config() {
    const rules = (db.prepare("SELECT text FROM local_rules WHERE enabled = 1 ORDER BY sid").all() as Array<{ text: string }>).map((r) => r.text);
    const suppressions = activeSuppressions().map(suppressLine);
    return { hash: sha256(JSON.stringify({ rules, suppressions })), rules, suppressions };
  }

  /** The suppression that covers an alert, if any. */
  function suppressedBy(a: AlertEvent, active: SuppressionRow[]): string | null {
    const s = active.find(
      (s) =>
        s.sid === a.sid &&
        s.gid === a.gid &&
        (!s.track || !s.network || inNetwork(s.track === "by_src" ? a.srcIp : a.destIp, s.network)) &&
        (!s.expires_at || s.expires_at > a.time),
    );
    return s?.id ?? null;
  }

  // ---- Events in ---------------------------------------------------------------------------------------------------

  /** A batch of EVE events from one sensor's agent. A batch sent again counts once. */
  function ingest(sensor: { id: string; name: string }, body: unknown) {
    const events = (body as { events?: unknown })?.events;
    if (!Array.isArray(events)) throw bad("Expected { events: [...] }: Suricata's EVE events, as JSON objects.");
    if (events.length > MAX_EVENTS) throw new IdsError(413, "payload-too-large", `At most ${MAX_EVENTS} events in one batch.`);
    const oldest = iso(now() - (o.flowRetentionDays ?? 30) * 86_400_000);
    const oldestAlert = iso(now() - (o.alertRetentionDays ?? 90) * 86_400_000);
    const active = activeSuppressions();
    const insertAlert = db.prepare(
      `INSERT OR IGNORE INTO alerts (uid, sensor_id, time, flow_id, community_id, src_ip, src_port, dest_ip, dest_port, proto, app_proto, gid, sid, rev,
         signature, category, severity, action, suppressed_by, event) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const insertFlow = db.prepare(
      `INSERT OR IGNORE INTO flows (uid, sensor_id, start, end, flow_id, community_id, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
         pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, state, reason, alerted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const insertRecord = db.prepare(
      `INSERT OR IGNORE INTO records (uid, sensor_id, time, kind, flow_id, src_ip, src_port, dest_ip, dest_port, name, detail)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const counts = { alert: 0, flow: 0, record: 0, stats: 0, ignored: 0, refused: 0, suppressed: 0, duplicate: 0 };
    const refusals: string[] = [];
    const stats: Parameters<Sensors["received"]>[3] = [];
    let lastEventAt: string | null = null;
    db.exec("BEGIN");
    try {
      for (const raw of events) {
        const e: Event | null | string = readEvent(raw);
        if (e === null) {
          counts.ignored++;
          continue;
        }
        if (typeof e === "string") {
          counts.refused++;
          if (refusals.length < 5) refusals.push(e);
          continue;
        }
        if (!lastEventAt || e.time > lastEventAt) lastEventAt = e.time;
        if (e.type === "stats") {
          stats.push({
            time: e.time,
            uptime: e.uptime,
            packets: e.packets,
            drops: e.drops,
            bytes: e.bytes,
            rules_loaded: e.rulesLoaded,
            rules_failed: e.rulesFailed,
            last_reload: e.lastReload,
          });
          counts.stats++;
          continue;
        }
        if (e.time < (e.type === "alert" ? oldestAlert : oldest)) {
          counts.ignored++;
          continue;
        }
        const json = JSON.stringify(raw);
        const uid = sha256(`${sensor.id}\n${json}`);
        let changes = 0;
        if (e.type === "alert") {
          const by = suppressedBy(e, active);
          if (by) counts.suppressed++;
          const kept = json.length <= MAX_EVENT_JSON ? json : JSON.stringify({ ...e, truncated: true });
          changes = Number(
            insertAlert.run(
              uid,
              sensor.id,
              e.time,
              e.flowId,
              e.communityId,
              e.srcIp,
              e.srcPort,
              e.destIp,
              e.destPort,
              e.proto,
              e.appProto,
              e.gid,
              e.sid,
              e.rev,
              e.signature,
              e.category,
              e.severity,
              e.action,
              by,
              kept,
            ).changes,
          );
          counts.alert++;
        } else if (e.type === "flow") {
          changes = Number(
            insertFlow.run(
              uid,
              sensor.id,
              e.start,
              e.end,
              e.flowId,
              e.communityId,
              e.srcIp,
              e.srcPort,
              e.destIp,
              e.destPort,
              e.proto,
              e.appProto,
              e.pktsToServer,
              e.pktsToClient,
              e.bytesToServer,
              e.bytesToClient,
              e.state,
              e.reason,
              e.alerted ? 1 : 0,
            ).changes,
          );
          counts.flow++;
        } else {
          changes = Number(
            insertRecord.run(uid, sensor.id, e.time, e.kind, e.flowId, e.srcIp, e.srcPort, e.destIp, e.destPort, e.name, JSON.stringify(e.detail)).changes,
          );
          counts.record++;
        }
        if (!changes) counts.duplicate++;
      }
      sensors.received(sensor.id, events.length - counts.refused - counts.ignored, lastEventAt, stats);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    for (const k of ["alert", "flow", "record", "stats"] as const) received.set(k, (received.get(k) ?? 0) + counts[k]);
    refusedTotal += counts.refused;
    if (counts.refused) log("warn", "events refused", { sensor: sensor.name, refused: counts.refused, reasons: refusals });
    return { ...counts, refusals };
  }

  // ---- Reading -----------------------------------------------------------------------------------------------------

  const hoursParam = (v: string | null, fallback = 24) => {
    if (v === null || v === "") return fallback;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > 24 * 400) throw bad("hours is a whole number of hours, 1 or more.");
    return n;
  };

  const names = () => sensors.names();
  const endpointsOf = (r: {
    src_ip: string;
    src_port: number | null;
    dest_ip: string;
    dest_port: number | null;
    proto?: string;
    app_proto?: string | null;
  }) => ({
    srcIp: r.src_ip,
    srcPort: r.src_port,
    destIp: r.dest_ip,
    destPort: r.dest_port,
  });

  const toAlert = (a: AlertRow, sensorNames: Map<string, string>) => ({
    id: a.id,
    time: a.time,
    sensor: { id: a.sensor_id, name: sensorNames.get(a.sensor_id) ?? a.sensor_id },
    flowId: a.flow_id,
    communityId: a.community_id,
    ...endpointsOf(a),
    proto: a.proto,
    appProto: a.app_proto,
    gid: a.gid,
    sid: a.sid,
    rev: a.rev,
    signature: a.signature,
    category: a.category,
    severity: a.severity,
    action: a.action,
    suppressedBy: a.suppressed_by,
  });

  const toFlow = (f: FlowRow, sensorNames: Map<string, string>) => ({
    id: f.id,
    sensor: { id: f.sensor_id, name: sensorNames.get(f.sensor_id) ?? f.sensor_id },
    start: f.start,
    end: f.end,
    flowId: f.flow_id,
    communityId: f.community_id,
    ...endpointsOf(f),
    proto: f.proto,
    appProto: f.app_proto,
    pktsToServer: f.pkts_toserver,
    pktsToClient: f.pkts_toclient,
    bytesToServer: f.bytes_toserver,
    bytesToClient: f.bytes_toclient,
    state: f.state,
    reason: f.reason,
    alerted: f.alerted === 1,
  });

  const toRecord = (r: RecordRow, sensorNames: Map<string, string>) => ({
    id: r.id,
    sensor: { id: r.sensor_id, name: sensorNames.get(r.sensor_id) ?? r.sensor_id },
    time: r.time,
    kind: r.kind,
    flowId: r.flow_id,
    ...endpointsOf(r),
    name: r.name,
    detail: JSON.parse(r.detail) as Record<string, unknown>,
  });

  /** What else the sensor saw of the same flow: the flow itself, its protocol logs and its alerts. */
  function sameFlow(sensorId: string, flowId: string | null) {
    if (!flowId) return { flow: null, records: [], alerts: [] };
    const n = names();
    const flow = db.prepare("SELECT * FROM flows WHERE sensor_id = ? AND flow_id = ? ORDER BY end DESC LIMIT 1").get(sensorId, flowId) as FlowRow | undefined;
    const records = db
      .prepare("SELECT * FROM records WHERE sensor_id = ? AND flow_id = ? ORDER BY time LIMIT 100")
      .all(sensorId, flowId) as unknown as RecordRow[];
    const alerts = db
      .prepare("SELECT * FROM alerts WHERE sensor_id = ? AND flow_id = ? ORDER BY time LIMIT 100")
      .all(sensorId, flowId) as unknown as AlertRow[];
    return { flow: flow ? toFlow(flow, n) : null, records: records.map((r) => toRecord(r, n)), alerts: alerts.map((a) => toAlert(a, n)) };
  }

  function alerts(q: URLSearchParams) {
    const hours = hoursParam(q.get("hours"));
    const where = ["time > ?"];
    const params: SQLInputValue[] = [iso(now() - hours * HOUR)];
    const severities = q.getAll("severity").filter(Boolean);
    if (severities.some((s) => !SEVERITIES.includes(s as Severity))) throw bad(`severity is ${SEVERITIES.join(", ")}.`);
    if (severities.length) {
      where.push(`severity IN (${severities.map(() => "?").join(", ")})`);
      params.push(...severities);
    }
    const sensorIds = q.getAll("sensor").filter(Boolean);
    if (sensorIds.length) {
      where.push(`sensor_id IN (${sensorIds.map(() => "?").join(", ")})`);
      params.push(...sensorIds);
    }
    const suppressed = q.get("suppressed") ?? "false";
    if (!["true", "false", "all"].includes(suppressed)) throw bad("suppressed is true, false or all.");
    if (suppressed !== "all") where.push(suppressed === "true" ? "suppressed_by IS NOT NULL" : "suppressed_by IS NULL");
    const text = (q.get("q") ?? "").trim();
    if (text) {
      if (text.length > 200) throw bad("q is at most 200 characters.");
      where.push("(signature LIKE ? ESCAPE '\\' OR src_ip = ? OR dest_ip = ? OR CAST(sid AS TEXT) = ? OR community_id = ?)");
      params.push(`%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`, text, text, text, text);
    }
    const n = names();
    const rows = db
      .prepare(`SELECT * FROM alerts WHERE ${where.join(" AND ")} ORDER BY time DESC, id DESC LIMIT ${MAX_ROWS}`)
      .all(...params) as unknown as AlertRow[];
    const total = (db.prepare(`SELECT COUNT(*) AS n FROM alerts WHERE ${where.join(" AND ")}`).get(...params) as { n: number }).n;
    return { alerts: rows.map((a) => toAlert(a, n)), total };
  }

  function alert(id: string) {
    const a = /^\d+$/.test(id) ? (db.prepare("SELECT * FROM alerts WHERE id = ?").get(Number(id)) as AlertRow | undefined) : undefined;
    if (!a) throw new IdsError(404, "not-found", "No such alert.");
    const s = a.suppressed_by ? (db.prepare("SELECT * FROM suppressions WHERE id = ?").get(a.suppressed_by) as SuppressionRow | undefined) : undefined;
    const related = sameFlow(a.sensor_id, a.flow_id);
    return {
      ...toAlert(a, names()),
      event: JSON.parse(a.event) as Record<string, unknown>,
      suppression: s ? toSuppression(s) : null,
      flow: related.flow,
      records: related.records,
      otherAlerts: related.alerts.filter((x) => x.id !== a.id),
    };
  }

  function flows(q: URLSearchParams) {
    const hours = hoursParam(q.get("hours"));
    const query = (q.get("q") ?? "").trim();
    if (query.length > 300) throw bad("q is at most 300 characters.");
    const { where, params } = flowQuery(query);
    const since = iso(now() - hours * HOUR);
    const n = names();
    const rows = db
      .prepare(`SELECT * FROM flows WHERE end > ? AND ${where} ORDER BY end DESC, id DESC LIMIT ${MAX_ROWS}`)
      .all(since, ...params) as unknown as FlowRow[];
    const agg = db
      .prepare(
        `SELECT COUNT(*) AS n, COALESCE(SUM(bytes_toserver + bytes_toclient), 0) AS bytes,
           SUM(CASE WHEN state IN ('new', 'closed') AND pkts_toclient = 0 THEN 1 ELSE 0 END) AS unanswered,
           SUM(CASE WHEN julianday(end) - julianday(start) > 1.0 / 24 THEN 1 ELSE 0 END) AS long_lived
         FROM flows WHERE end > ? AND ${where}`,
      )
      .get(since, ...params) as { n: number; bytes: number; unanswered: number | null; long_lived: number | null };
    return {
      flows: rows.map((f) => toFlow(f, n)),
      total: agg.n,
      bytes: agg.bytes,
      unanswered: agg.unanswered ?? 0,
      longLived: agg.long_lived ?? 0,
    };
  }

  function flow(id: string) {
    const f = /^\d+$/.test(id) ? (db.prepare("SELECT * FROM flows WHERE id = ?").get(Number(id)) as FlowRow | undefined) : undefined;
    if (!f) throw new IdsError(404, "not-found", "No such flow.");
    const related = sameFlow(f.sensor_id, f.flow_id);
    return { ...toFlow(f, names()), records: related.records, alerts: related.alerts };
  }

  function records(kind: string, q: URLSearchParams) {
    if (!RECORD_KINDS.includes(kind as RecordKind)) throw new IdsError(404, "not-found", `Protocol logs are ${RECORD_KINDS.join(", ")}.`);
    const hours = hoursParam(q.get("hours"));
    const since = iso(now() - hours * HOUR);
    const text = (q.get("q") ?? "").trim();
    if (text.length > 255) throw bad("q is at most 255 characters.");
    const where = ["kind = ?", "time > ?"];
    const params: SQLInputValue[] = [kind, since];
    if (text) {
      where.push("(name LIKE ? ESCAPE '\\' OR src_ip = ? OR dest_ip = ?)");
      params.push(`%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`, text, text);
    }
    const n = names();
    const rows = db
      .prepare(`SELECT * FROM records WHERE ${where.join(" AND ")} ORDER BY time DESC, id DESC LIMIT ${MAX_ROWS}`)
      .all(...params) as unknown as RecordRow[];
    const total = (db.prepare(`SELECT COUNT(*) AS n FROM records WHERE ${where.join(" AND ")}`).get(...params) as { n: number }).n;
    const top = db
      .prepare(`SELECT name, COUNT(*) AS count FROM records WHERE ${where.join(" AND ")} AND name != '' GROUP BY name ORDER BY count DESC LIMIT 10`)
      .all(...params) as Array<{ name: string; count: number }>;
    const clients = (db.prepare(`SELECT COUNT(DISTINCT src_ip) AS n FROM records WHERE ${where.join(" AND ")}`).get(...params) as { n: number }).n;
    return { records: rows.map((r) => toRecord(r, n)), total, clients, top };
  }

  function summary() {
    const since = iso(now() - 86_400_000);
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const r of db.prepare("SELECT severity, COUNT(*) AS n FROM alerts WHERE time > ? AND suppressed_by IS NULL GROUP BY severity").all(since) as Array<{
      severity: Severity;
      n: number;
    }>)
      bySeverity[r.severity] = r.n;
    const start = Math.floor(now() / HOUR) * HOUR - 23 * HOUR;
    const perHour = Array.from({ length: 24 }, (_, i) => ({ hour: iso(start + i * HOUR), ...Object.fromEntries(SEVERITIES.map((s) => [s, 0])) })) as Array<
      { hour: string } & Record<Severity, number>
    >;
    for (const r of db.prepare("SELECT time, severity FROM alerts WHERE time >= ? AND suppressed_by IS NULL").all(iso(start)) as Array<{
      time: string;
      severity: Severity;
    }>) {
      const i = Math.floor((Date.parse(r.time) - start) / HOUR);
      if (perHour[i]) perHour[i][r.severity]++;
    }
    const lastHourCritical = (
      db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE time > ? AND severity = 'critical' AND suppressed_by IS NULL").get(iso(now() - HOUR)) as { n: number }
    ).n;
    const suppressed = (db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE time > ? AND suppressed_by IS NOT NULL").get(since) as { n: number }).n;
    const talkers = db
      .prepare("SELECT src_ip AS ip, SUM(bytes_toserver + bytes_toclient) AS bytes FROM flows WHERE end > ? GROUP BY src_ip ORDER BY bytes DESC LIMIT 6")
      .all(since) as Array<{ ip: string; bytes: number }>;
    const signatures = db
      .prepare(
        "SELECT gid, sid, signature, severity, COUNT(*) AS count FROM alerts WHERE time > ? AND suppressed_by IS NULL GROUP BY gid, sid ORDER BY count DESC LIMIT 6",
      )
      .all(since) as Array<{ gid: number; sid: number; signature: string; severity: Severity; count: number }>;
    const c = config();
    const all = sensors.list(c.hash);
    const latest = all.flatMap((s) => (s.suricata?.dropRatio !== null && s.suricata ? [s.suricata] : []));
    return {
      alerts: { lastDay: Object.values(bySeverity).reduce((a, b) => a + b, 0), bySeverity, lastHourCritical, suppressed, perHour },
      sensors: { hash: c.hash, ...sensors.counts(c.hash), names: all.map((s) => ({ id: s.id, name: s.name })) },
      inspected: {
        bitsPerSecond: latest.reduce((a, s) => a + (s.bitsPerSecond ?? 0), 0),
        dropRatio: latest.length ? Math.max(...latest.map((s) => s.dropRatio ?? 0)) : null,
      },
      talkers,
      signatures,
      rules: {
        local: (db.prepare("SELECT COUNT(*) AS n FROM local_rules WHERE enabled = 1").get() as { n: number }).n,
        suppressions: c.suppressions.length,
        loaded: all.reduce((a, s) => a + (s.suricata?.rulesLoaded ?? 0), 0),
        failed: all.reduce((a, s) => a + (s.suricata?.rulesFailed ?? 0), 0),
      },
    };
  }

  return {
    sensors,
    config,
    ingest,
    alerts,
    alert,
    flows,
    flow,
    records,
    summary,

    rules() {
      const c = config();
      return {
        rules: (db.prepare("SELECT * FROM local_rules ORDER BY sid").all() as unknown as RuleRow[]).map(toRule),
        deployment: { hash: c.hash, ...sensors.counts(c.hash) },
      };
    },

    /** Checks a rule without keeping it: what it is, and whether its SID is taken. */
    checkRule(b: Record<string, unknown>) {
      try {
        const r = parseRule(typeof b.text === "string" ? b.text : "");
        const taken = db.prepare("SELECT id FROM local_rules WHERE sid = ?").get(r.sid) as { id: string } | undefined;
        if (taken && taken.id !== b.id) return { ok: false, error: `sid ${r.sid} is taken by another local rule.`, sid: r.sid, rev: r.rev, msg: r.msg };
        return { ok: true, error: null, sid: r.sid, rev: r.rev, msg: r.msg };
      } catch (err) {
        if (err instanceof RuleError) return { ok: false, error: err.message, sid: null, rev: null, msg: null };
        throw err;
      }
    },

    createRule(b: Record<string, unknown>, actor: string) {
      if (Object.keys(b).some((k) => k !== "text" && k !== "enabled")) throw bad("Expected { text, enabled }.");
      if (b.enabled !== undefined && typeof b.enabled !== "boolean") throw bad("enabled is true or false.");
      const r = checkRule(b.text);
      if (db.prepare("SELECT 1 FROM local_rules WHERE sid = ?").get(r.sid)) throw new IdsError(409, "conflict", `sid ${r.sid} is taken by another local rule.`);
      const id = randomUUID();
      db.prepare("INSERT INTO local_rules (id, sid, rev, msg, text, enabled, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
        id,
        r.sid,
        r.rev,
        r.msg,
        (b.text as string).trim(),
        b.enabled === false ? 0 : 1,
        actor,
        iso(),
        iso(),
      );
      log("info", "local rule added", { sid: r.sid, by: actor });
      return toRule(ruleRow(id)!);
    },

    updateRule(id: string, b: Record<string, unknown>, actor: string) {
      const before = ruleRow(id);
      if (!before) throw new IdsError(404, "not-found", "No such rule.");
      if (Object.keys(b).some((k) => k !== "text" && k !== "enabled")) throw bad("Expected { text, enabled }.");
      if (b.enabled !== undefined && typeof b.enabled !== "boolean") throw bad("enabled is true or false.");
      const r = b.text === undefined ? null : checkRule(b.text);
      if (r && r.sid !== before.sid && db.prepare("SELECT 1 FROM local_rules WHERE sid = ?").get(r.sid))
        throw new IdsError(409, "conflict", `sid ${r.sid} is taken by another local rule.`);
      db.prepare("UPDATE local_rules SET sid = ?, rev = ?, msg = ?, text = ?, enabled = ?, updated_at = ? WHERE id = ?").run(
        r?.sid ?? before.sid,
        r?.rev ?? before.rev,
        r?.msg ?? before.msg,
        r ? (b.text as string).trim() : before.text,
        b.enabled === undefined ? before.enabled : b.enabled ? 1 : 0,
        iso(),
        id,
      );
      log("info", "local rule changed", { sid: r?.sid ?? before.sid, by: actor });
      return toRule(ruleRow(id)!);
    },

    deleteRule(id: string, actor: string) {
      const r = ruleRow(id);
      if (!r) throw new IdsError(404, "not-found", "No such rule.");
      db.prepare("DELETE FROM local_rules WHERE id = ?").run(id);
      log("info", "local rule deleted", { sid: r.sid, by: actor });
    },

    suppressions() {
      return (db.prepare("SELECT * FROM suppressions ORDER BY created_at DESC").all() as unknown as SuppressionRow[]).map(toSuppression);
    },

    createSuppression(b: Record<string, unknown>, actor: string) {
      const allowed = ["gid", "sid", "track", "network", "reason", "expiresAt"];
      if (Object.keys(b).some((k) => !allowed.includes(k))) throw bad(`Expected { ${allowed.join(", ")} }.`);
      const sid = b.sid;
      if (!Number.isInteger(sid) || (sid as number) < 1 || (sid as number) > 4_294_967_295) throw bad("sid is the signature's id, a whole number.");
      const gid = b.gid ?? 1;
      if (!Number.isInteger(gid) || (gid as number) < 1 || (gid as number) > 65_535) throw bad("gid is a whole number, 1 for rules.");
      const track = b.track ?? null;
      if (track !== null && track !== "by_src" && track !== "by_dst") throw bad("track is by_src, by_dst or null for every address.");
      const network = b.network ?? null;
      if ((track === null) !== (network === null)) throw bad("A suppression for some addresses needs both track and network; for all, neither.");
      if (network !== null && (typeof network !== "string" || !parseNetwork(network)))
        throw bad("network is an address or a network, such as 192.0.2.9 or 10.0.0.0/8.");
      if (typeof b.reason !== "string" || !b.reason.trim() || b.reason.length > 500)
        throw bad("reason says why this traffic is known to be good, up to 500 characters.");
      let expiresAt: string | null = null;
      if (b.expiresAt !== undefined && b.expiresAt !== null) {
        const t = typeof b.expiresAt === "string" ? Date.parse(b.expiresAt) : Number.NaN;
        if (Number.isNaN(t) || t <= now() || t > now() + 366 * 86_400_000) throw bad("expiresAt is a time in the next year, or null for no end.");
        expiresAt = iso(t);
      }
      const id = randomUUID();
      const n = network === null ? null : (network as string).trim();
      db.prepare("INSERT INTO suppressions (id, gid, sid, track, network, reason, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
        id,
        gid as number,
        sid as number,
        track,
        n,
        b.reason.trim(),
        actor,
        iso(),
        expiresAt,
      );
      log("info", "suppression added", { sid, track, network: n, by: actor });
      return toSuppression(db.prepare("SELECT * FROM suppressions WHERE id = ?").get(id) as unknown as SuppressionRow);
    },

    /** Ends a suppression now. Alerts it covered stay marked with it. */
    deleteSuppression(id: string, actor: string) {
      const s = db.prepare("SELECT * FROM suppressions WHERE id = ?").get(id) as SuppressionRow | undefined;
      if (!s) throw new IdsError(404, "not-found", "No such suppression.");
      if (db.prepare("SELECT 1 FROM alerts WHERE suppressed_by = ? LIMIT 1").get(id)) {
        if (!s.expires_at || s.expires_at > iso()) db.prepare("UPDATE suppressions SET expires_at = ? WHERE id = ?").run(iso(), id);
      } else db.prepare("DELETE FROM suppressions WHERE id = ?").run(id);
      log("info", "suppression ended", { sid: s.sid, by: actor });
    },

    /** Deletes what is past its retention (ADR 0070): alerts after their days, flows, protocol logs and counters after theirs. */
    purge() {
      const alertsBefore = iso(now() - (o.alertRetentionDays ?? 90) * 86_400_000);
      const flowsBefore = iso(now() - (o.flowRetentionDays ?? 30) * 86_400_000);
      const a = db.prepare("DELETE FROM alerts WHERE time < ?").run(alertsBefore).changes;
      const f = db.prepare("DELETE FROM flows WHERE end < ?").run(flowsBefore).changes;
      const r = db.prepare("DELETE FROM records WHERE time < ?").run(flowsBefore).changes;
      sensors.purge(flowsBefore);
      db.prepare("DELETE FROM suppressions WHERE expires_at < ? AND id NOT IN (SELECT suppressed_by FROM alerts WHERE suppressed_by IS NOT NULL)").run(
        alertsBefore,
      );
      if (a || f || r) log("info", "purged", { alerts: a, flows: f, records: r });
    },

    gauges() {
      const s = summary();
      return {
        alertsLastDay: s.alerts.bySeverity,
        sensors: s.sensors,
        received: Object.fromEntries(received),
        refused: refusedTotal,
        drops: sensors.list(config().hash).flatMap((x) => (x.suricata?.dropRatio != null ? [{ sensor: x.name, ratio: x.suricata.dropRatio }] : [])),
      };
    },
  };
}

export type Ids = ReturnType<typeof createIds>;
