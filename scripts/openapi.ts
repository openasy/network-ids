// Writes openapi.json (ADR 0014, 0024). Run `node scripts/openapi.ts` after changing the API; a test fails when the
// file is out of date. Sign-in routes come from @openasy/auth and are merged in when the description is served.
import { writeFileSync } from "node:fs";

type S = Record<string, unknown>;
const ref = (n: string) => ({ $ref: `#/components/schemas/${n}` });
const str = { type: "string" };
const int = { type: "integer" };
const num = { type: "number" };
const bool = { type: "boolean" };
const dt = { type: "string", format: "date-time" };
const nul = (s: S) => ({ anyOf: [s, { type: "null" }] });
const arr = (s: S) => ({ type: "array", items: s });
const obj = (properties: Record<string, S>, required = Object.keys(properties)) => ({ type: "object", required, properties });

const problem = { $ref: "#/components/responses/Problem" };
const ok = (schema: S, description = "OK") => ({ description, content: { "application/json": { schema } } });
const VIEWER = [{ session: [] }, { apiToken: [] }, { adminToken: [] }];
const id = (what: string) => [{ name: "id", in: "path", required: true, description: `The ${what}'s id.`, schema: str }];
const query = (name: string, description: string, schema: S = str) => ({ name, in: "query", required: false, description, schema });
const HOURS = query("hours", "How far back, in hours: 24 unless set.", { type: "integer", minimum: 1, maximum: 9600 });
const body = (schema: S) => ({ required: true, content: { "application/json": { schema } } });

/** An operation that needs a role (ADR 0003), with the refusals every such operation can answer. */
function op(role: "viewer" | "editor" | "admin", o: S & { responses: Record<string, unknown> }) {
  return {
    ...o,
    security: VIEWER,
    "x-openasy-role": role,
    description: [`Needs the ${role} role.`, o.description].filter(Boolean).join(" "),
    responses: { ...o.responses, "401": problem, "403": problem, "503": problem },
  };
}

/** An operation of network-ids-agent, with its own secret. */
function agent(o: S & { responses: Record<string, unknown> }) {
  return { ...o, tags: ["Agent"], security: [{ agentSecret: [] }], responses: { ...o.responses, "400": problem, "401": problem, "422": problem } };
}

const SEVERITY = { type: "string", enum: ["critical", "high", "medium", "low"] };
const SENSOR_REF = obj({ id: str, name: str });
const port = nul({ type: "integer", minimum: 0, maximum: 65535 });
const ENDPOINTS = { srcIp: str, srcPort: port, destIp: str, destPort: port };

const schemas: Record<string, S> = {
  Problem: obj(
    {
      type: { type: "string", format: "uri" },
      title: str,
      status: int,
      code: {
        type: "string",
        enum: [
          "invalid-token",
          "invalid-json",
          "invalid-body",
          "conflict",
          "not-found",
          "payload-too-large",
          "internal-error",
          "unauthenticated",
          "invalid-credentials",
          "mfa-required",
          "mfa-setup-required",
          "forbidden",
          "cross-site",
          "rate-limited",
        ],
        description: "Stable; match on this.",
      },
      detail: str,
    },
    ["type", "title", "status", "code"],
  ),
  Status: obj({ status: str }),
  Version: obj({ product: { const: "network-ids" }, version: str }),
  ProductLink: obj({
    id: { type: "string", description: "The product, as OpenAsy names it.", examples: ["siem"] },
    url: { type: "string", format: "uri", description: "The address people open it at.", examples: ["https://siem.example.com"] },
  }),
  ProductList: obj({ products: arr(ref("ProductLink")) }),

  Alert: obj({
    id: int,
    time: dt,
    sensor: SENSOR_REF,
    flowId: { ...nul(str), description: "Suricata's flow id on that sensor; the flow and protocol logs of the alert share it." },
    communityId: { ...nul(str), description: "The Community ID of the flow, when Suricata writes it: the same flow in Zeek and other tools." },
    ...ENDPOINTS,
    proto: { type: "string", examples: ["TCP"] },
    appProto: nul(str),
    gid: int,
    sid: int,
    rev: int,
    signature: str,
    category: str,
    severity: { ...SEVERITY, description: "From ET's signature_severity metadata, or Suricata's severity: 1 high, 2 medium, 3 and more low." },
    action: { type: "string", description: "What Suricata did: allowed, as an IDS does." },
    suppressedBy: { ...nul(str), description: "The suppression that covers it; such alerts are kept and left out of counts." },
  }),
  AlertList: obj({ alerts: arr(ref("Alert")), total: { type: "integer", description: "All that match; at most 500 are listed, newest first." } }),
  AlertDetail: {
    allOf: [
      ref("Alert"),
      obj({
        event: { type: "object", description: "The EVE event as the sensor sent it, without packet payloads." },
        suppression: nul(ref("Suppression")),
        flow: nul(ref("Flow")),
        records: arr(ref("Record")),
        otherAlerts: arr(ref("Alert")),
      }),
    ],
  },
  Flow: obj({
    id: int,
    sensor: SENSOR_REF,
    start: dt,
    end: dt,
    flowId: nul(str),
    communityId: nul(str),
    ...ENDPOINTS,
    proto: str,
    appProto: nul(str),
    pktsToServer: int,
    pktsToClient: int,
    bytesToServer: int,
    bytesToClient: int,
    state: { ...nul(str), description: "How Suricata saw it end: new, established, closed, bypassed." },
    reason: { ...nul(str), description: "Why the flow record was written: timeout, forced, shutdown." },
    alerted: bool,
  }),
  FlowList: obj({
    flows: arr(ref("Flow")),
    total: int,
    bytes: { type: "integer", description: "Both ways, of every flow that matches." },
    unanswered: { type: "integer", description: "Flows the other side sent nothing back on." },
    longLived: { type: "integer", description: "Flows of more than an hour: check those for beacons." },
  }),
  FlowDetail: { allOf: [ref("Flow"), obj({ records: arr(ref("Record")), alerts: arr(ref("Alert")) })] },
  Record: obj({
    id: int,
    sensor: SENSOR_REF,
    time: dt,
    kind: { type: "string", enum: ["dns", "http", "tls", "ssh"] },
    flowId: nul(str),
    ...ENDPOINTS,
    name: { type: "string", description: "The DNS name, the HTTP host, the TLS server name or the SSH client." },
    detail: { type: "object", description: "The fields kept of Suricata's record: rrtype and rcode, url and user agent, version, subject and JA3." },
  }),
  RecordList: obj({
    records: arr(ref("Record")),
    total: int,
    clients: { type: "integer", description: "Source addresses among them." },
    top: arr(obj({ name: str, count: int })),
  }),

  Rule: obj({
    id: str,
    sid: int,
    rev: int,
    msg: str,
    text: { type: "string", description: "The rule, in Suricata's syntax." },
    enabled: bool,
    createdBy: str,
    createdAt: dt,
    updatedAt: dt,
    alertsLastDay: int,
  }),
  Deployment: obj({
    hash: { type: "string", description: "Of the enabled local rules and active suppressions: what an up-to-date sensor wrote." },
    total: int,
    online: int,
    degraded: int,
    offline: int,
    versionMismatch: int,
    waiting: int,
    outdated: { type: "integer", description: "Enrolled sensors that have not written the current rules and suppressions." },
  }),
  RuleList: obj({ rules: arr(ref("Rule")), deployment: ref("Deployment") }),
  NewRule: obj(
    {
      text: {
        type: "string",
        maxLength: 8192,
        description:
          "One rule: alert or pass, a header and options with a msg in quotes and a sid from 9000000 to 9999999. lua, luajit, dataset and datarep are refused.",
        examples: ['alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Admin path probe"; http.uri; content:"/admin"; sid:9000104; rev:1;)'],
      },
      enabled: { type: "boolean", default: true },
    },
    ["text"],
  ),
  RuleChange: obj({ text: { type: "string", maxLength: 8192 }, enabled: bool }, []),
  RuleCheck: obj({ ok: bool, error: nul(str), sid: nul(int), rev: nul(int), msg: nul(str) }),
  Suppression: obj({
    id: str,
    gid: int,
    sid: int,
    track: nul({ type: "string", enum: ["by_src", "by_dst"] }),
    network: nul(str),
    reason: str,
    createdBy: str,
    createdAt: dt,
    expiresAt: nul(dt),
    state: { type: "string", enum: ["active", "expired"] },
    line: {
      type: "string",
      description: "As written in the sensors' threshold file.",
      examples: ["suppress gen_id 1, sig_id 2013028, track by_src, ip 192.0.2.9"],
    },
    signature: { ...nul(str), description: "The signature, from the last alert of that sid." },
    suppressedLastDay: int,
  }),
  SuppressionList: obj({ suppressions: arr(ref("Suppression")) }),
  NewSuppression: obj(
    {
      sid: { type: "integer", minimum: 1 },
      gid: { type: "integer", default: 1 },
      track: { ...nul({ type: "string", enum: ["by_src", "by_dst"] }), description: "With network: only alerts from (by_src) or to (by_dst) it." },
      network: { ...nul(str), description: "An address or a network in CIDR form.", examples: ["192.0.2.9", "10.0.0.0/8"] },
      reason: { type: "string", maxLength: 500 },
      expiresAt: { ...nul(dt), description: "Within a year; null for no end." },
    },
    ["sid", "reason"],
  ),

  Sensor: obj({
    id: str,
    name: str,
    description: str,
    status: {
      type: "string",
      enum: ["waiting-to-enrol", "online", "degraded", "offline", "version-mismatch"],
      description: "degraded: it drops 1% of packets or more, Suricata failed to load rules, or the agent could not write them.",
    },
    version: nul(str),
    hostname: nul(str),
    evePath: nul(str),
    config: obj({ upToDate: bool, appliedAt: nul(dt), error: nul(str) }),
    eventsIn: int,
    lastEventAt: nul(dt),
    lastSeenAt: nul(dt),
    lastError: nul(str),
    suricata: nul(
      obj({
        at: dt,
        uptimeSeconds: int,
        rulesLoaded: nul(int),
        rulesFailed: nul(int),
        lastReload: nul(dt),
        bitsPerSecond: nul(int),
        packetsPerSecond: nul(int),
        dropRatio: { ...nul(num), description: "0 to 1, over the last minute of counters." },
      }),
    ),
    lastDay: arr(obj({ hour: dt, dropRatio: nul(num), bitsPerSecond: nul(int) })),
    createdAt: dt,
  }),
  SensorList: obj({ sensors: arr(ref("Sensor")) }),
  NewSensor: obj(
    {
      name: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$" },
      description: { type: "string", maxLength: 200, description: "Where it listens." },
    },
    ["name"],
  ),
  SensorEnrollment: obj({
    sensor: ref("Sensor"),
    enrollToken: { type: "string", description: "One-time, for 7 days: start network-ids-agent with it. Shown once." },
    enrollExpiresAt: dt,
  }),

  AgentReport: obj(
    {
      version: { type: "string", description: "The agent's version; it must be Network IDS's (ADR 0019)." },
      hostname: str,
      evePath: str,
      configHash: { ...nul(str), description: "The hash of the rules and suppressions the agent last wrote." },
      configError: { ...nul(str), description: "Why the last write or reload failed." },
    },
    ["version", "hostname", "evePath"],
  ),
  AgentEnroll: { allOf: [ref("AgentReport"), obj({ token: str })] },
  AgentEnrolled: obj({ sensorId: str, name: str, secret: { type: "string", description: "The agent's own secret from now on. Shown once." } }),
  AgentConfig: obj({
    hash: str,
    rules: { ...arr(str), description: "The enabled local rules, one per line of the agent's rules file." },
    suppressions: { ...arr(str), description: "Suricata suppress lines, for the agent's threshold file." },
  }),
  EventBatch: obj({
    events: { ...arr({ type: "object" }), maxItems: 5000, description: "EVE events as Suricata wrote them: alert, flow, dns, http, tls, ssh, stats." },
  }),
  EventsResult: obj({
    alert: int,
    flow: int,
    record: int,
    stats: int,
    ignored: { type: "integer", description: "Other event types, and events past retention." },
    refused: int,
    suppressed: int,
    duplicate: { type: "integer", description: "Events already kept: a batch sent again." },
    refusals: arr(str),
  }),

  Summary: obj({
    alerts: obj({
      lastDay: int,
      bySeverity: obj({ critical: int, high: int, medium: int, low: int }),
      lastHourCritical: int,
      suppressed: int,
      perHour: arr(obj({ hour: dt, critical: int, high: int, medium: int, low: int })),
    }),
    sensors: { allOf: [ref("Deployment"), obj({ names: arr(SENSOR_REF) })] },
    inspected: obj({ bitsPerSecond: int, dropRatio: nul(num) }),
    talkers: arr(obj({ ip: str, bytes: int })),
    signatures: arr(obj({ gid: int, sid: int, signature: str, severity: SEVERITY, count: int })),
    rules: obj({ local: int, suppressions: int, loaded: int, failed: int }),
  }),
};

const spec = {
  openapi: "3.1.1",
  info: {
    title: "OpenAsy Network IDS API",
    version: "0.1.0",
    summary: "Suricata alerts, flows and protocol logs from sensors on a copy of your traffic, with local rules and suppressions.",
    description:
      "Every screen of Network IDS uses this API, and so can your scripts (ADR 0014). Within `/api/v1` changes are additive only; anything removed is deprecated first (ADR 0024). Errors use Problem Details (RFC 9457).\n\nSensors send their events through network-ids-agent, which enrols once with a token from `POST /api/v1/sensors` and then calls `/api/v1/agent/*` with its own secret. Everything else takes the session of a signed-in person or an API token, and each operation names the role it needs (`x-openasy-role`: viewer, editor, admin; ADR 0003).\n\nSign-in, members and API tokens are under `/api/v1/auth`, provided by [@openasy/auth](https://github.com/openasy/auth#routes).",
    license: { name: "AGPL-3.0-only", identifier: "AGPL-3.0-only" },
  },
  servers: [{ url: "/", description: "This Network IDS" }],
  tags: [
    { name: "Alerts", description: "Signatures that matched traffic." },
    { name: "Flows", description: "Who talked to whom, when and how much." },
    { name: "Protocols", description: "DNS, HTTP, TLS and SSH logs." },
    { name: "Rules", description: "Local rules and suppressions, sent to every sensor." },
    { name: "Sensors", description: "Where Suricata listens, and its health." },
    { name: "Agent", description: "For network-ids-agent only." },
    { name: "Product", description: "Version and overview of this Network IDS." },
  ],
  paths: {
    "/api/v1/alerts": {
      get: op("viewer", {
        operationId: "listAlerts",
        tags: ["Alerts"],
        summary: "Alerts",
        description: "Newest first. Suppressed alerts are left out unless asked for.",
        parameters: [
          HOURS,
          query("severity", "One or more severities.", SEVERITY),
          query("sensor", "One or more sensor ids."),
          query("q", "A word of the signature, an address, a sid or a Community ID."),
          query("suppressed", "false (the default), true or all.", { type: "string", enum: ["true", "false", "all"] }),
        ],
        responses: { "200": ok(ref("AlertList")), "422": problem },
      }),
    },
    "/api/v1/alerts/{id}": {
      get: op("viewer", {
        operationId: "getAlert",
        tags: ["Alerts"],
        summary: "An alert, with its flow",
        description: "With the EVE event, the flow it was in, that flow's protocol logs and other alerts, and the suppression that covers it.",
        parameters: id("alert"),
        responses: { "200": ok(ref("AlertDetail")), "404": problem },
      }),
    },
    "/api/v1/flows": {
      get: op("viewer", {
        operationId: "listFlows",
        tags: ["Flows"],
        summary: "Flows",
        description:
          "Newest first. q is terms joined by and: ip, src_ip, dest_ip, port, src_port, dest_port, proto, app_proto, state, community_id, sensor and alerted, as key:value; a bare term is an address.",
        parameters: [HOURS, query("q", "Such as `app_proto:dns src_ip:192.0.2.17`.")],
        responses: { "200": ok(ref("FlowList")), "422": problem },
      }),
    },
    "/api/v1/flows/{id}": {
      get: op("viewer", {
        operationId: "getFlow",
        tags: ["Flows"],
        summary: "A flow, with its logs and alerts",
        parameters: id("flow"),
        responses: { "200": ok(ref("FlowDetail")), "404": problem },
      }),
    },
    "/api/v1/protocols/{kind}": {
      get: op("viewer", {
        operationId: "listRecords",
        tags: ["Protocols"],
        summary: "Protocol logs of one kind",
        description: "Newest first, with the names seen most.",
        parameters: [
          { name: "kind", in: "path", required: true, schema: { type: "string", enum: ["dns", "http", "tls", "ssh"] } },
          HOURS,
          query("q", "A part of the name, or an address."),
        ],
        responses: { "200": ok(ref("RecordList")), "404": problem, "422": problem },
      }),
    },
    "/api/v1/rules": {
      get: op("viewer", {
        operationId: "listRules",
        tags: ["Rules"],
        summary: "Local rules",
        description: "With how many sensors have written the current rules and suppressions.",
        responses: { "200": ok(ref("RuleList")) },
      }),
      post: op("editor", {
        operationId: "createRule",
        tags: ["Rules"],
        summary: "Add a local rule",
        description: "Every sensor writes it at its next call and reloads Suricata.",
        requestBody: body(ref("NewRule")),
        responses: { "201": ok(ref("Rule"), "Added."), "400": problem, "409": problem, "422": problem },
      }),
    },
    "/api/v1/rules/check": {
      post: op("viewer", {
        operationId: "checkRule",
        tags: ["Rules"],
        summary: "Check a rule",
        description: "Reads it as it would be kept, without keeping it. Pass the rule's id to check a change to it.",
        requestBody: body(obj({ text: str, id: str }, ["text"])),
        responses: { "200": ok(ref("RuleCheck")), "400": problem },
      }),
    },
    "/api/v1/rules/{id}": {
      put: op("editor", {
        operationId: "updateRule",
        tags: ["Rules"],
        summary: "Change a local rule, or turn it off",
        parameters: id("rule"),
        requestBody: body(ref("RuleChange")),
        responses: { "200": ok(ref("Rule")), "400": problem, "404": problem, "409": problem, "422": problem },
      }),
      delete: op("editor", {
        operationId: "deleteRule",
        tags: ["Rules"],
        summary: "Delete a local rule",
        parameters: id("rule"),
        responses: { "204": { description: "Deleted." }, "404": problem },
      }),
    },
    "/api/v1/suppressions": {
      get: op("viewer", { operationId: "listSuppressions", tags: ["Rules"], summary: "Suppressions", responses: { "200": ok(ref("SuppressionList")) } }),
      post: op("editor", {
        operationId: "createSuppression",
        tags: ["Rules"],
        summary: "Suppress a signature",
        description: "For every address, or from or to one network. Sensors stop alerting on it; alerts that still come are kept, marked suppressed.",
        requestBody: body(ref("NewSuppression")),
        responses: { "201": ok(ref("Suppression"), "Added."), "400": problem, "422": problem },
      }),
    },
    "/api/v1/suppressions/{id}": {
      delete: op("editor", {
        operationId: "deleteSuppression",
        tags: ["Rules"],
        summary: "End a suppression",
        description: "It is kept as ended while alerts it covered are.",
        parameters: id("suppression"),
        responses: { "204": { description: "Ended." }, "404": problem },
      }),
    },
    "/api/v1/sensors": {
      get: op("viewer", { operationId: "listSensors", tags: ["Sensors"], summary: "Sensors and their health", responses: { "200": ok(ref("SensorList")) } }),
      post: op("admin", {
        operationId: "createSensor",
        tags: ["Sensors"],
        summary: "Add a sensor",
        description: "Returns the one-time token its agent enrols with.",
        requestBody: body(ref("NewSensor")),
        responses: { "201": ok(ref("SensorEnrollment"), "Added."), "400": problem, "409": problem, "422": problem },
      }),
    },
    "/api/v1/sensors/{id}": {
      get: op("viewer", {
        operationId: "getSensor",
        tags: ["Sensors"],
        summary: "A sensor",
        parameters: id("sensor"),
        responses: { "200": ok(ref("Sensor")), "404": problem },
      }),
      delete: op("admin", {
        operationId: "deleteSensor",
        tags: ["Sensors"],
        summary: "Delete a sensor",
        description: "With everything it sent.",
        parameters: id("sensor"),
        responses: { "204": { description: "Deleted." }, "404": problem },
      }),
    },
    "/api/v1/sensors/{id}/enroll-token": {
      post: op("admin", {
        operationId: "reEnrollSensor",
        tags: ["Sensors"],
        summary: "A new enrolment token",
        description: "The agent's secret stops working; start the agent with the new token.",
        parameters: id("sensor"),
        responses: { "200": ok(ref("SensorEnrollment")), "404": problem },
      }),
    },
    "/api/v1/agent/enroll": {
      post: {
        operationId: "agentEnroll",
        tags: ["Agent"],
        summary: "Enrol an agent",
        description: "Once, with the sensor's enrolment token; the answer holds the agent's own secret.",
        security: [],
        requestBody: body(ref("AgentEnroll")),
        responses: { "200": ok(ref("AgentEnrolled")), "400": problem, "401": problem, "422": problem },
      },
    },
    "/api/v1/agent/config": {
      post: agent({
        operationId: "agentConfig",
        summary: "What the sensor writes",
        description: "The agent says what it last wrote; the answer is the local rules and suppressions to write now. An agent of another version is refused.",
        requestBody: body(ref("AgentReport")),
        responses: { "200": ok(ref("AgentConfig")), "409": problem },
      }),
    },
    "/api/v1/agent/events": {
      post: agent({
        operationId: "agentEvents",
        summary: "Send EVE events",
        description: "JSON, gzipped with Content-Encoding: gzip, at most 32 MiB unpacked. A batch sent again counts once.",
        requestBody: body(ref("EventBatch")),
        responses: { "200": ok(ref("EventsResult")), "413": problem },
      }),
    },
    "/api/v1/summary": {
      get: op("viewer", {
        operationId: "getSummary",
        tags: ["Product"],
        summary: "Overview",
        description: "The last 24 hours: alerts by severity and hour, top talkers and signatures, sensors and rules.",
        responses: { "200": ok(ref("Summary")) },
      }),
    },
    "/api/v1/products": {
      get: op("viewer", {
        operationId: "listProducts",
        tags: ["Product"],
        summary: "Other products of this install",
        responses: { "200": ok(ref("ProductList"), "From OPENASY_PRODUCTS, for the product switcher.") },
      }),
    },
    "/api/v1/version": {
      get: { operationId: "getVersion", tags: ["Product"], summary: "Version", security: [], responses: { "200": ok(ref("Version"), "The running version.") } },
    },
    "/healthz": {
      get: {
        operationId: "liveness",
        tags: ["Product"],
        summary: "Liveness",
        security: [],
        responses: { "200": ok(ref("Status"), "The process is running.") },
      },
    },
    "/readyz": {
      get: {
        operationId: "readiness",
        tags: ["Product"],
        summary: "Readiness",
        description: "Ready while the database answers.",
        security: [],
        responses: { "200": ok(ref("Status"), "Ready to serve."), "503": ok(ref("Status"), "The database is unavailable.") },
      },
    },
    "/metrics": {
      get: {
        operationId: "metrics",
        tags: ["Product"],
        summary: "Prometheus metrics",
        security: [],
        responses: { "200": { description: "Metrics in the Prometheus text format.", content: { "text/plain": { schema: str } } } },
      },
    },
  },
  components: {
    securitySchemes: {
      session: {
        type: "apiKey",
        in: "cookie",
        name: "__Host-openasy-session",
        description:
          "The browser session after signing in (`openasy-session` when Network IDS runs on plain http://localhost). Requests that change something must come from the Network IDS origin.",
      },
      apiToken: {
        type: "http",
        scheme: "bearer",
        description: "An API token created under Settings → API tokens (`oa_network-ids_...`): one role, always an expiry (ADR 0003).",
      },
      adminToken: {
        type: "http",
        scheme: "bearer",
        description:
          "Only when Network IDS is started by its tests or a local script: one shared token with the admin role. A production install does not have it.",
      },
      agentSecret: {
        type: "http",
        scheme: "bearer",
        description: "The secret network-ids-agent got when it enrolled (`oia_...`). It reads the sensor's rules and sends its events, nothing else.",
      },
    },
    responses: { Problem: { description: "An error, as RFC 9457 Problem Details.", content: { "application/problem+json": { schema: ref("Problem") } } } },
    schemas,
  },
};

export const OPENAPI = spec;
if (import.meta.url === `file://${process.argv[1]}`) writeFileSync(new URL("../openapi.json", import.meta.url), JSON.stringify(spec, null, 2) + "\n");
