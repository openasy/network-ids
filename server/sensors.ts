// Sensors and their agents (ADR 0070, 0023). A sensor is added here and gets a one-time enrolment token; the
// network-ids-agent next to its Suricata enrols with it and then calls with its own secret. Network IDS never connects
// to a sensor and sends it no commands: the agent asks for the local rules and suppressions, checks them, writes them
// and reloads Suricata itself, and sends the EVE events it reads.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { bad, IdsError } from "./errors.ts";
import { log } from "./log.ts";

interface SensorRow {
  id: string;
  name: string;
  description: string;
  enroll_token_hash: string | null;
  enroll_expires_at: string | null;
  secret_hash: string | null;
  version: string | null;
  hostname: string | null;
  eve_path: string | null;
  config_hash: string | null;
  config_applied_at: string | null;
  config_error: string | null;
  events_in: number;
  last_event_at: string | null;
  last_seen_at: string | null;
  last_error: string | null;
  created_at: string;
}

interface StatsRow {
  time: string;
  uptime: number;
  packets: number;
  drops: number;
  bytes: number;
  rules_loaded: number | null;
  rules_failed: number | null;
  last_reload: string | null;
}

export type SensorStatus = "waiting-to-enrol" | "online" | "degraded" | "offline" | "version-mismatch";

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const ENROLL_TTL_MS = 7 * 86_400_000;
/** The agent calls every few seconds; a sensor not heard from for this long is offline. */
const OFFLINE_MS = 2 * 60_000;
/** A drop rate from here up means rules miss traffic. */
export const DROP_DEGRADED = 0.01;
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** What an agent says about itself on every call. */
export interface Report {
  version: string;
  hostname: string;
  evePath: string;
  /** The hash of the rules and suppressions it last wrote, and why the last write or reload failed. */
  configHash: string | null;
  configError: string | null;
}

export interface SensorsOptions {
  /** Network IDS's version: an agent of another version is refused (ADR 0019). */
  version: string;
  clock?: () => number;
}

/** The traffic and loss between two stats rows of the same Suricata run, or null across a restart. */
function rate(prev: StatsRow, cur: StatsRow) {
  const seconds = (Date.parse(cur.time) - Date.parse(prev.time)) / 1000;
  if (seconds <= 0 || cur.uptime < prev.uptime || cur.packets < prev.packets || cur.drops < prev.drops || cur.bytes < prev.bytes) return null;
  const packets = cur.packets - prev.packets;
  return {
    time: cur.time,
    bitsPerSecond: Math.round(((cur.bytes - prev.bytes) * 8) / seconds),
    packetsPerSecond: Math.round(packets / seconds),
    // kernel_packets counts what was dropped too.
    dropRatio: packets > 0 ? (cur.drops - prev.drops) / packets : 0,
  };
}

export function createSensors(db: DatabaseSync, o: SensorsOptions) {
  const now = o.clock ?? Date.now;
  const iso = (t = now()) => new Date(t).toISOString();

  const row = (id: string) => db.prepare("SELECT * FROM sensors WHERE id = ?").get(id) as SensorRow | undefined;
  const requireSensor = (id: string) => {
    const s = row(id);
    if (!s) throw new IdsError(404, "not-found", "No such sensor.");
    return s;
  };

  /** Rates over the last day, newest last, and the latest counters. */
  function statsOf(id: string) {
    const rows = db
      .prepare("SELECT * FROM sensor_stats WHERE sensor_id = ? AND time > ? ORDER BY time")
      .all(id, iso(now() - 86_400_000)) as unknown as StatsRow[];
    const rates = rows.slice(1).flatMap((r, i) => rate(rows[i]!, r) ?? []);
    return { latest: rows.at(-1), rates };
  }

  function toSensor(s: SensorRow, configHash: string) {
    const online = !!s.last_seen_at && Date.parse(s.last_seen_at) + OFFLINE_MS > now();
    const { latest, rates } = statsOf(s.id);
    const current = rates.at(-1);
    const degraded = (current?.dropRatio ?? 0) >= DROP_DEGRADED || !!s.config_error || (latest?.rules_failed ?? 0) > 0;
    const status: SensorStatus = !s.secret_hash
      ? "waiting-to-enrol"
      : !online
        ? "offline"
        : s.version !== o.version
          ? "version-mismatch"
          : degraded
            ? "degraded"
            : "online";
    return {
      id: s.id,
      name: s.name,
      description: s.description,
      status,
      version: s.version,
      hostname: s.hostname,
      evePath: s.eve_path,
      config: { upToDate: !!s.config_hash && s.config_hash === configHash, appliedAt: s.config_applied_at, error: s.config_error },
      eventsIn: s.events_in,
      lastEventAt: s.last_event_at,
      lastSeenAt: s.last_seen_at,
      lastError: s.last_error,
      suricata: latest
        ? {
            at: latest.time,
            uptimeSeconds: latest.uptime,
            rulesLoaded: latest.rules_loaded,
            rulesFailed: latest.rules_failed,
            lastReload: latest.last_reload,
            bitsPerSecond: current?.bitsPerSecond ?? null,
            packetsPerSecond: current?.packetsPerSecond ?? null,
            dropRatio: current?.dropRatio ?? null,
          }
        : null,
      // One point an hour: the highest drop rate and the mean traffic of that hour.
      lastDay: Array.from({ length: 24 }, (_, i) => {
        const from = now() - (24 - i) * 3_600_000;
        const inHour = rates.filter((r) => Date.parse(r.time) > from && Date.parse(r.time) <= from + 3_600_000);
        return {
          hour: iso(from + 3_600_000),
          dropRatio: inHour.length ? Math.max(...inHour.map((r) => r.dropRatio)) : null,
          bitsPerSecond: inHour.length ? Math.round(inHour.reduce((a, r) => a + r.bitsPerSecond, 0) / inHour.length) : null,
        };
      }),
      createdAt: s.created_at,
    };
  }

  function newEnrollToken(id: string) {
    const token = `oie_${randomBytes(24).toString("base64url")}`;
    db.prepare("UPDATE sensors SET enroll_token_hash = ?, enroll_expires_at = ? WHERE id = ?").run(sha256(token), iso(now() + ENROLL_TTL_MS), id);
    return { enrollToken: token, enrollExpiresAt: iso(now() + ENROLL_TTL_MS) };
  }

  function checkReport(b: Record<string, unknown>): Report {
    const short = (v: unknown, name: string, max = 255) => {
      if (typeof v !== "string" || v.length > max) throw bad(`${name} is required, at most ${max} characters.`);
      return v;
    };
    const hash = b.configHash;
    if (hash !== null && hash !== undefined && (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)))
      throw bad("configHash is a SHA-256 in hex, or null.");
    const error = b.configError;
    if (error !== null && error !== undefined && typeof error !== "string") throw bad("configError is a string, or null.");
    return {
      version: short(b.version, "version", 32),
      hostname: short(b.hostname, "hostname"),
      evePath: short(b.evePath, "evePath", 1024),
      configHash: (hash as string | null | undefined) ?? null,
      configError: typeof error === "string" ? error.slice(0, 1000) : null,
    };
  }

  return {
    list(configHash: string) {
      return (db.prepare("SELECT * FROM sensors ORDER BY name").all() as unknown as SensorRow[]).map((s) => toSensor(s, configHash));
    },

    get(id: string, configHash: string) {
      return toSensor(requireSensor(id), configHash);
    },

    names(): Map<string, string> {
      return new Map((db.prepare("SELECT id, name FROM sensors").all() as Array<{ id: string; name: string }>).map((s) => [s.id, s.name]));
    },

    create(b: Record<string, unknown>, configHash: string) {
      if (Object.keys(b).some((k) => k !== "name" && k !== "description")) throw bad("Expected { name, description }.");
      if (typeof b.name !== "string" || !NAME.test(b.name)) throw bad("name is letters, digits, dots, dashes and underscores, up to 63.");
      if (b.description !== undefined && (typeof b.description !== "string" || b.description.length > 200))
        throw bad("description is where it listens, at most 200 characters.");
      if (db.prepare("SELECT 1 FROM sensors WHERE name = ?").get(b.name)) throw new IdsError(409, "conflict", `A sensor named ${b.name} exists.`);
      const id = randomUUID();
      db.prepare("INSERT INTO sensors (id, name, description, created_at) VALUES (?, ?, ?, ?)").run(id, b.name, (b.description as string) ?? "", iso());
      log("info", "sensor added", { sensor: b.name });
      return { sensor: toSensor(requireSensor(id), configHash), ...newEnrollToken(id) };
    },

    /** A new one-time token; the agent's secret is forgotten, so it enrols again. */
    reEnroll(id: string, configHash: string) {
      requireSensor(id);
      db.prepare("UPDATE sensors SET secret_hash = NULL WHERE id = ?").run(id);
      return { sensor: toSensor(requireSensor(id), configHash), ...newEnrollToken(id) };
    },

    /** The sensor goes with everything it sent. */
    delete(id: string) {
      const s = requireSensor(id);
      db.prepare("DELETE FROM sensors WHERE id = ?").run(id);
      log("info", "sensor deleted", { sensor: s.name });
    },

    enroll(b: Record<string, unknown>) {
      const token = typeof b.token === "string" ? b.token : "";
      const s = db.prepare("SELECT * FROM sensors WHERE enroll_token_hash = ?").get(sha256(token)) as SensorRow | undefined;
      if (!s || !s.enroll_expires_at || s.enroll_expires_at <= iso())
        throw new IdsError(401, "invalid-token", "The enrolment token is unknown, used or expired. Create a new one under Sensors.");
      const r = checkReport(b);
      const secret = `oia_${randomBytes(32).toString("base64url")}`;
      db.prepare(
        "UPDATE sensors SET enroll_token_hash = NULL, enroll_expires_at = NULL, secret_hash = ?, version = ?, hostname = ?, eve_path = ?, last_seen_at = ?, last_error = NULL WHERE id = ?",
      ).run(sha256(secret), r.version, r.hostname, r.evePath, iso(), s.id);
      log("info", "sensor enrolled", { sensor: s.name, version: r.version, hostname: r.hostname });
      return { sensorId: s.id, name: s.name, secret };
    },

    /** The sensor whose agent sent this secret. */
    bySecret(header: string | undefined): { id: string; name: string } {
      const secret = header?.startsWith("Bearer oia_") ? header.slice(7) : "";
      const s = secret ? (db.prepare("SELECT id, name FROM sensors WHERE secret_hash = ?").get(sha256(secret)) as SensorRow | undefined) : undefined;
      if (!s) throw new IdsError(401, "invalid-token", "Unknown agent secret. Enrol the agent again under Sensors.");
      return { id: s.id, name: s.name };
    },

    /** Keeps what the agent says about itself; refuses an agent of another version (ADR 0019). */
    report(id: string, b: Record<string, unknown>) {
      const r = checkReport(b);
      const t = iso();
      if (r.version !== o.version) {
        const error = `network-ids-agent ${r.version} does not match network-ids ${o.version}; install network-ids-agent ${o.version}`;
        db.prepare("UPDATE sensors SET version = ?, last_seen_at = ?, last_error = ? WHERE id = ?").run(r.version, t, error, id);
        throw new IdsError(409, "conflict", error);
      }
      const before = requireSensor(id);
      const applied = r.configHash && r.configHash !== before.config_hash ? t : before.config_applied_at;
      db.prepare(
        "UPDATE sensors SET version = ?, hostname = ?, eve_path = ?, config_hash = ?, config_applied_at = ?, config_error = ?, last_seen_at = ?, last_error = NULL WHERE id = ?",
      ).run(r.version, r.hostname, r.evePath, r.configHash, applied, r.configError, t, id);
      if (r.configError && r.configError !== before.config_error) log("warn", "sensor could not apply rules", { sensor: before.name, error: r.configError });
    },

    /** Counts what a batch brought, and keeps Suricata's counters at most once a minute. */
    received(id: string, events: number, lastEventAt: string | null, stats: Array<Omit<StatsRow, "time"> & { time: string }>) {
      db.prepare("UPDATE sensors SET events_in = events_in + ?, last_event_at = COALESCE(?, last_event_at) WHERE id = ?").run(events, lastEventAt, id);
      const last = db.prepare("SELECT time FROM sensor_stats WHERE sensor_id = ? ORDER BY time DESC LIMIT 1").get(id) as { time: string } | undefined;
      let lastAt = last ? Date.parse(last.time) : 0;
      const insert = db.prepare(
        "INSERT INTO sensor_stats (sensor_id, time, uptime, packets, drops, bytes, rules_loaded, rules_failed, last_reload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      );
      for (const s of stats) {
        const at = Date.parse(s.time);
        if (at < lastAt + 55_000) continue;
        insert.run(id, s.time, s.uptime, s.packets, s.drops, s.bytes, s.rules_loaded, s.rules_failed, s.last_reload);
        lastAt = at;
      }
    },

    purge(before: string) {
      db.prepare("DELETE FROM sensor_stats WHERE time < ?").run(before);
    },

    counts(configHash: string) {
      const all = this.list(configHash);
      const by = (s: SensorStatus) => all.filter((x) => x.status === s).length;
      return {
        total: all.length,
        online: by("online"),
        degraded: by("degraded"),
        offline: by("offline"),
        versionMismatch: by("version-mismatch"),
        waiting: by("waiting-to-enrol"),
        outdated: all.filter((x) => x.status !== "waiting-to-enrol" && !x.config.upToDate).length,
      };
    },
  };
}

export type Sensors = ReturnType<typeof createSensors>;
