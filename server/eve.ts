// Suricata's EVE JSON, read into what Network IDS keeps (ADR 0070). network-ids-agent sends the events as Suricata
// wrote them, but for the fields it leaves out (packet payloads); everything is checked here again, because a sensor
// is only trusted to say what it saw.
import { isIP } from "node:net";

export type Severity = "critical" | "high" | "medium" | "low";
export type RecordKind = "dns" | "http" | "tls" | "ssh";
export const RECORD_KINDS: RecordKind[] = ["dns", "http", "tls", "ssh"];
/** The event types the agent sends; others are counted and left out. */
export const EVENT_TYPES = ["alert", "flow", "stats", ...RECORD_KINDS];

type Obj = Record<string, unknown>;

export interface Endpoints {
  time: string;
  flowId: string | null;
  communityId: string | null;
  srcIp: string;
  srcPort: number | null;
  destIp: string;
  destPort: number | null;
  proto: string;
  appProto: string | null;
}

export interface AlertEvent extends Endpoints {
  type: "alert";
  gid: number;
  sid: number;
  rev: number;
  signature: string;
  category: string;
  severity: Severity;
  action: string;
}

export interface FlowEvent extends Endpoints {
  type: "flow";
  start: string;
  end: string;
  pktsToServer: number;
  pktsToClient: number;
  bytesToServer: number;
  bytesToClient: number;
  state: string | null;
  reason: string | null;
  alerted: boolean;
}

export interface RecordEvent extends Endpoints {
  type: "record";
  kind: RecordKind;
  /** What is searched and counted: the DNS name, the HTTP host, the TLS server name, the SSH client. */
  name: string;
  detail: Obj;
}

export interface StatsEvent {
  type: "stats";
  time: string;
  uptime: number;
  packets: number;
  drops: number;
  bytes: number;
  rulesLoaded: number | null;
  rulesFailed: number | null;
  lastReload: string | null;
}

export type Event = AlertEvent | FlowEvent | RecordEvent | StatsEvent;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 512): string | null => (typeof v === "string" && v.length > 0 ? v.slice(0, max) : null);
const count = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const port = (v: unknown): number | null => (Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 65_535 ? (v as number) : null);

/** Suricata writes 2026-10-28T13:58:12.114231+0000; this is that instant in ISO form, or null. */
export function eveTime(v: unknown): string | null {
  if (typeof v !== "string" || v.length > 40) return null;
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:?\d\d)$/.exec(v);
  if (!m) return null;
  const zone = m[3] === "Z" ? "Z" : `${m[3]!.slice(0, 3)}:${m[3]!.slice(-2)}`;
  const t = Date.parse(`${m[1]}${(m[2] ?? "").slice(0, 4)}${zone}`);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

function endpoints(e: Obj, time: string): Endpoints | string {
  const srcIp = text(e.src_ip, 64);
  const destIp = text(e.dest_ip, 64);
  if (!srcIp || !destIp || !isIP(srcIp) || !isIP(destIp)) return "src_ip and dest_ip must be addresses";
  const flowId = typeof e.flow_id === "number" && Number.isSafeInteger(e.flow_id) ? String(e.flow_id) : text(e.flow_id, 32);
  return {
    time,
    flowId: flowId && /^\d+$/.test(flowId) ? flowId : null,
    communityId: text(e.community_id, 64),
    srcIp,
    srcPort: port(e.src_port),
    destIp,
    destPort: port(e.dest_port),
    proto: text(e.proto, 16)?.toUpperCase() ?? "UNKNOWN",
    appProto: text(e.app_proto, 32),
  };
}

const SIGNATURE_SEVERITY: Record<string, Severity> = { critical: "critical", major: "high", minor: "medium", informational: "low" };

/**
 * ET rules name their weight in metadata (signature_severity Critical, Major, Minor, Informational); otherwise
 * Suricata's severity, 1 the highest, from the rule's priority or classtype.
 */
export function severityOf(alert: Obj): Severity {
  const meta = isObj(alert.metadata) ? alert.metadata.signature_severity : undefined;
  const named = Array.isArray(meta) && typeof meta[0] === "string" ? SIGNATURE_SEVERITY[meta[0].toLowerCase()] : undefined;
  if (named) return named;
  const s = alert.severity;
  return s === 1 ? "high" : s === 2 ? "medium" : "low";
}

/** The fields of a protocol log that are kept, by kind; the rest of Suricata's record is left out. */
function recordOf(kind: RecordKind, e: Obj): { name: string; detail: Obj } {
  const r = isObj(e[kind]) ? (e[kind] as Obj) : {};
  const pick = (o: Obj, keys: string[]) => Object.fromEntries(keys.filter((k) => o[k] !== undefined && typeof o[k] !== "object").map((k) => [k, o[k]]));
  if (kind === "dns") {
    // EVE's DNS records come in two forms: version 2 answers with rrname at the top, and queries with the question
    // under queries (Suricata 8) or at the top (Suricata 7).
    const q = Array.isArray(r.queries) && isObj(r.queries[0]) ? (r.queries[0] as Obj) : r;
    const answers = Array.isArray(r.answers)
      ? r.answers
          .filter(isObj)
          .slice(0, 16)
          .map((a) => pick(a, ["rrname", "rrtype", "rdata", "ttl"]))
      : [];
    return { name: text(q.rrname, 255) ?? "", detail: { ...pick(r, ["type", "id", "rcode"]), ...pick(q, ["rrname", "rrtype"]), answers } };
  }
  if (kind === "http") {
    return {
      name: text(r.hostname, 255) ?? "",
      detail: pick(r, ["hostname", "url", "http_method", "http_user_agent", "http_content_type", "status", "length", "protocol", "http_refer"]),
    };
  }
  if (kind === "tls") {
    const ja3 = isObj(r.ja3) ? text(r.ja3.hash, 64) : null;
    const ja3s = isObj(r.ja3s) ? text(r.ja3s.hash, 64) : null;
    const ja4 = text(r.ja4, 64);
    return {
      name: text(r.sni, 255) ?? "",
      detail: { ...pick(r, ["sni", "version", "subject", "issuerdn", "fingerprint", "notbefore", "notafter"]), ja3, ja3s, ja4 },
    };
  }
  const client = isObj(r.client) ? r.client : {};
  const server = isObj(r.server) ? r.server : {};
  return {
    name: text(client.software_version, 255) ?? "",
    detail: { client: pick(client, ["proto_version", "software_version"]), server: pick(server, ["proto_version", "software_version"]) },
  };
}

function statsOf(e: Obj, time: string): StatsEvent {
  const s = isObj(e.stats) ? e.stats : {};
  const capture = isObj(s.capture) ? s.capture : {};
  const decoder = isObj(s.decoder) ? s.decoder : {};
  const detect = isObj(s.detect) ? s.detect : {};
  const engine = Array.isArray(detect.engines) && isObj(detect.engines[0]) ? (detect.engines[0] as Obj) : undefined;
  return {
    type: "stats",
    time,
    uptime: count(s.uptime),
    // A live capture counts what the kernel saw and dropped; reading a capture file has only the decoder's count.
    packets: count(capture.kernel_packets) || count(decoder.pkts),
    drops: count(capture.kernel_drops),
    bytes: count(decoder.bytes),
    rulesLoaded: engine ? count(engine.rules_loaded) : null,
    rulesFailed: engine ? count(engine.rules_failed) : null,
    lastReload: engine ? eveTime(engine.last_reload) : null,
  };
}

/** One EVE event in the form kept, null for event types left out, or a reason it is refused. */
export function readEvent(e: unknown): Event | null | string {
  if (!isObj(e)) return "an event is an object";
  const type = e.event_type;
  if (typeof type !== "string") return "event_type is missing";
  if (!EVENT_TYPES.includes(type)) return null;
  const time = eveTime(e.timestamp);
  if (!time) return "timestamp is not Suricata's form, such as 2026-10-28T13:58:12.114231+0000";
  if (type === "stats") return statsOf(e, time);
  const ends = endpoints(e, time);
  if (typeof ends === "string") return ends;
  if (type === "alert") {
    const a = isObj(e.alert) ? e.alert : null;
    if (!a || !Number.isInteger(a.signature_id)) return "alert.signature_id is missing";
    return {
      type: "alert",
      ...ends,
      gid: Number.isInteger(a.gid) ? (a.gid as number) : 1,
      sid: a.signature_id as number,
      rev: Number.isInteger(a.rev) ? (a.rev as number) : 0,
      signature: text(a.signature, 512) ?? `sid:${a.signature_id}`,
      category: text(a.category, 256) ?? "",
      severity: severityOf(a),
      action: text(a.action, 16) ?? "allowed",
    };
  }
  if (type === "flow") {
    const f = isObj(e.flow) ? e.flow : {};
    const start = eveTime(f.start) ?? time;
    return {
      type: "flow",
      ...ends,
      start,
      end: eveTime(f.end) ?? time,
      pktsToServer: count(f.pkts_toserver),
      pktsToClient: count(f.pkts_toclient),
      bytesToServer: count(f.bytes_toserver),
      bytesToClient: count(f.bytes_toclient),
      state: text(f.state, 16),
      reason: text(f.reason, 16),
      alerted: f.alerted === true,
    };
  }
  return { type: "record", kind: type as RecordKind, ...ends, ...recordOf(type as RecordKind, e) };
}
