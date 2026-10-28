import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `-- A sensor: one Suricata on a copy of the traffic, and the network-ids-agent next to it that sends its EVE events
   -- and writes the local rules and suppressions it is given (ADR 0070). It enrols once with a one-time token and then
   -- calls with its own secret; only hashes of both are kept.
   CREATE TABLE sensors (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     description TEXT NOT NULL DEFAULT '',
     enroll_token_hash TEXT UNIQUE,
     enroll_expires_at TEXT,
     secret_hash TEXT UNIQUE,
     version TEXT,
     hostname TEXT,
     eve_path TEXT,
     -- The rules and suppressions the agent last wrote, by hash, and why the last write or reload failed.
     config_hash TEXT,
     config_applied_at TEXT,
     config_error TEXT,
     events_in INTEGER NOT NULL DEFAULT 0,
     last_event_at TEXT,
     last_seen_at TEXT,
     last_error TEXT,
     created_at TEXT NOT NULL
   );
   -- Suricata's counters from its stats events, at most one a minute per sensor. They count from Suricata's start, so
   -- rates come from two rows of the same uptime.
   CREATE TABLE sensor_stats (
     sensor_id TEXT NOT NULL REFERENCES sensors (id) ON DELETE CASCADE,
     time TEXT NOT NULL,
     uptime INTEGER NOT NULL,
     packets INTEGER NOT NULL,
     drops INTEGER NOT NULL,
     bytes INTEGER NOT NULL,
     rules_loaded INTEGER,
     rules_failed INTEGER,
     last_reload TEXT
   );
   CREATE INDEX sensor_stats_time ON sensor_stats (sensor_id, time);
   -- An alert: a signature that matched traffic. uid makes a batch sent twice count once. suppressed_by names the
   -- suppression that covers it: such alerts are kept and shown as suppressed, never dropped.
   CREATE TABLE alerts (
     id INTEGER PRIMARY KEY,
     uid TEXT NOT NULL UNIQUE,
     sensor_id TEXT NOT NULL REFERENCES sensors (id) ON DELETE CASCADE,
     time TEXT NOT NULL,
     flow_id TEXT,
     community_id TEXT,
     src_ip TEXT NOT NULL,
     src_port INTEGER,
     dest_ip TEXT NOT NULL,
     dest_port INTEGER,
     proto TEXT NOT NULL,
     app_proto TEXT,
     gid INTEGER NOT NULL,
     sid INTEGER NOT NULL,
     rev INTEGER NOT NULL,
     signature TEXT NOT NULL,
     category TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
     action TEXT NOT NULL,
     suppressed_by TEXT,
     event TEXT NOT NULL
   );
   CREATE INDEX alerts_time ON alerts (time);
   CREATE INDEX alerts_flow ON alerts (sensor_id, flow_id);
   -- A flow as Suricata ends it: who talked to whom, how long and how much.
   CREATE TABLE flows (
     id INTEGER PRIMARY KEY,
     uid TEXT NOT NULL UNIQUE,
     sensor_id TEXT NOT NULL REFERENCES sensors (id) ON DELETE CASCADE,
     start TEXT NOT NULL,
     end TEXT NOT NULL,
     flow_id TEXT,
     community_id TEXT,
     src_ip TEXT NOT NULL,
     src_port INTEGER,
     dest_ip TEXT NOT NULL,
     dest_port INTEGER,
     proto TEXT NOT NULL,
     app_proto TEXT,
     pkts_toserver INTEGER NOT NULL,
     pkts_toclient INTEGER NOT NULL,
     bytes_toserver INTEGER NOT NULL,
     bytes_toclient INTEGER NOT NULL,
     state TEXT,
     reason TEXT,
     alerted INTEGER NOT NULL DEFAULT 0
   );
   CREATE INDEX flows_end ON flows (end);
   CREATE INDEX flows_flow ON flows (sensor_id, flow_id);
   -- Protocol logs: a DNS query or answer, an HTTP request, a TLS handshake, an SSH banner. name is what is searched
   -- and counted: the DNS name, the HTTP host, the TLS server name.
   CREATE TABLE records (
     id INTEGER PRIMARY KEY,
     uid TEXT NOT NULL UNIQUE,
     sensor_id TEXT NOT NULL REFERENCES sensors (id) ON DELETE CASCADE,
     time TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('dns', 'http', 'tls', 'ssh')),
     flow_id TEXT,
     src_ip TEXT NOT NULL,
     src_port INTEGER,
     dest_ip TEXT NOT NULL,
     dest_port INTEGER,
     name TEXT NOT NULL DEFAULT '',
     detail TEXT NOT NULL
   );
   CREATE INDEX records_time ON records (kind, time);
   CREATE INDEX records_flow ON records (sensor_id, flow_id);
   -- Rules written here, in Suricata's syntax, sent to every sensor as one rules file.
   CREATE TABLE local_rules (
     id TEXT PRIMARY KEY,
     sid INTEGER NOT NULL UNIQUE,
     rev INTEGER NOT NULL,
     msg TEXT NOT NULL,
     text TEXT NOT NULL,
     enabled INTEGER NOT NULL DEFAULT 1,
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   -- Known-good traffic that should not alert: a signature, for every address or for a source or destination network,
   -- with a reason and an optional end. Sent to every sensor as Suricata suppress lines.
   CREATE TABLE suppressions (
     id TEXT PRIMARY KEY,
     gid INTEGER NOT NULL DEFAULT 1,
     sid INTEGER NOT NULL,
     track TEXT CHECK (track IN ('by_src', 'by_dst')),
     network TEXT,
     reason TEXT NOT NULL,
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL,
     expires_at TEXT
   )`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
