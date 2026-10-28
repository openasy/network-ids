// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Severity = "critical" | "high" | "medium" | "low";
export type RecordKind = "dns" | "http" | "tls" | "ssh";
export type SensorStatus = "waiting-to-enrol" | "online" | "degraded" | "offline" | "version-mismatch";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
export const RECORD_KINDS: RecordKind[] = ["dns", "http", "tls", "ssh"];

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface SensorRef {
  id: string;
  name: string;
}

interface Endpoints {
  srcIp: string;
  srcPort: number | null;
  destIp: string;
  destPort: number | null;
}

export interface Alert extends Endpoints {
  id: number;
  time: string;
  sensor: SensorRef;
  flowId: string | null;
  communityId: string | null;
  proto: string;
  appProto: string | null;
  gid: number;
  sid: number;
  rev: number;
  signature: string;
  category: string;
  severity: Severity;
  action: string;
  suppressedBy: string | null;
}

export interface Flow extends Endpoints {
  id: number;
  sensor: SensorRef;
  start: string;
  end: string;
  flowId: string | null;
  communityId: string | null;
  proto: string;
  appProto: string | null;
  pktsToServer: number;
  pktsToClient: number;
  bytesToServer: number;
  bytesToClient: number;
  state: string | null;
  reason: string | null;
  alerted: boolean;
}

export interface NetRecord extends Endpoints {
  id: number;
  sensor: SensorRef;
  time: string;
  kind: RecordKind;
  flowId: string | null;
  name: string;
  detail: Record<string, unknown>;
}

export interface Suppression {
  id: string;
  gid: number;
  sid: number;
  track: "by_src" | "by_dst" | null;
  network: string | null;
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  state: "active" | "expired";
  line: string;
  signature: string | null;
  suppressedLastDay: number;
}

export interface AlertDetail extends Alert {
  event: Record<string, unknown>;
  suppression: Suppression | null;
  flow: Flow | null;
  records: NetRecord[];
  otherAlerts: Alert[];
}

export interface FlowDetail extends Flow {
  records: NetRecord[];
  alerts: Alert[];
}

export interface Rule {
  id: string;
  sid: number;
  rev: number;
  msg: string;
  text: string;
  enabled: boolean;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  alertsLastDay: number;
}

export interface Deployment {
  hash: string;
  total: number;
  online: number;
  degraded: number;
  offline: number;
  versionMismatch: number;
  waiting: number;
  outdated: number;
}

export interface RuleCheck {
  ok: boolean;
  error: string | null;
  sid: number | null;
  rev: number | null;
  msg: string | null;
}

export interface Sensor {
  id: string;
  name: string;
  description: string;
  status: SensorStatus;
  version: string | null;
  hostname: string | null;
  evePath: string | null;
  config: { upToDate: boolean; appliedAt: string | null; error: string | null };
  eventsIn: number;
  lastEventAt: string | null;
  lastSeenAt: string | null;
  lastError: string | null;
  suricata: {
    at: string;
    uptimeSeconds: number;
    rulesLoaded: number | null;
    rulesFailed: number | null;
    lastReload: string | null;
    bitsPerSecond: number | null;
    packetsPerSecond: number | null;
    dropRatio: number | null;
  } | null;
  lastDay: Array<{ hour: string; dropRatio: number | null; bitsPerSecond: number | null }>;
  createdAt: string;
}

export interface SensorEnrollment {
  sensor: Sensor;
  enrollToken: string;
  enrollExpiresAt: string;
}

export interface Summary {
  alerts: {
    lastDay: number;
    bySeverity: Record<Severity, number>;
    lastHourCritical: number;
    suppressed: number;
    perHour: Array<{ hour: string } & Record<Severity, number>>;
  };
  sensors: Deployment & { names: SensorRef[] };
  inspected: { bitsPerSecond: number; dropRatio: number | null };
  talkers: Array<{ ip: string; bytes: number }>;
  signatures: Array<{ gid: number; sid: number; signature: string; severity: Severity; count: number }>;
  rules: { local: number; suppressions: number; loaded: number; failed: number };
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
