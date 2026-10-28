import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { IdsError, type ProblemCode } from "./errors.ts";
import type { Ids } from "./ids.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";

export interface AppOptions {
  db: DatabaseSync;
  ids: Ids;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(ids: Ids, version: string) {
  return renderMetrics(version, ids.gauges());
}

/** Serves only /metrics, for a port that is not exposed with the rest (NETWORK_IDS_METRICS_PORT). */
export function createMetricsHandler(ids: Ids, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(ids, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": `default-src 'self'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'`,
};

/** Largest batch of EVE events accepted from an agent, after decompression: 5,000 events without their payloads. */
const EVENTS_LIMIT = 32 * 1024 * 1024;

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) =>
  send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/** Reads the whole body, gunzipping it when sent with `Content-Encoding: gzip`, up to limit bytes. */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new IdsError(400, "invalid-body", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) throw new IdsError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024 / 1024)} MiB.`);
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof IdsError) throw err;
    throw new IdsError(400, "invalid-body", "The gzip body could not be read.");
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBody(req, limit).catch((err: unknown) => {
    if (err instanceof IdsError && err.code === "payload-too-large")
      throw new IdsError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    throw err;
  });
  try {
    const body = JSON.parse(raw.toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new IdsError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003), or "agent" for a sensor's network-ids-agent calling with its own secret. */
type Access = "none" | "agent" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the record of a decision. */
  actor: () => string;
  /** The sensor whose agent made the request, on agent routes. */
  sensor: () => { id: string; name: string };
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

export function createApp({ db, ids, version, auth, adminToken, webDir, docsDir, openapi, serveMetrics = true, products = [] }: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const hash = () => ids.config().hash;

  /** A batch of EVE events: JSON, gzipped as the agent sends it. */
  const eventsBody = async (req: IncomingMessage) => {
    try {
      return JSON.parse((await readBody(req, EVENTS_LIMIT)).toString("utf8")) as unknown;
    } catch (err) {
      if (err instanceof IdsError) throw err;
      throw new IdsError(400, "invalid-json", "The body must be JSON: { events: [...] }.");
    }
  };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "network-ids", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => ids.summary() },

    // What the sensors saw.
    { method: "GET", path: "/api/v1/alerts", auth: "viewer", handle: ({ url }) => ids.alerts(url.searchParams) },
    { method: "GET", path: "/api/v1/alerts/:id", auth: "viewer", handle: ({ params }) => ids.alert(params[0]!) },
    { method: "GET", path: "/api/v1/flows", auth: "viewer", handle: ({ url }) => ids.flows(url.searchParams) },
    { method: "GET", path: "/api/v1/flows/:id", auth: "viewer", handle: ({ params }) => ids.flow(params[0]!) },
    { method: "GET", path: "/api/v1/protocols/:kind", auth: "viewer", handle: ({ params, url }) => ids.records(params[0]!, url.searchParams) },

    // What every sensor is given: local rules and suppressions.
    { method: "GET", path: "/api/v1/rules", auth: "viewer", handle: () => ids.rules() },
    { method: "POST", path: "/api/v1/rules", auth: "editor", handle: async ({ res, body, actor }) => json(res, 201, ids.createRule(await body(), actor())) },
    { method: "POST", path: "/api/v1/rules/check", auth: "viewer", handle: async ({ body }) => ids.checkRule(await body()) },
    { method: "PUT", path: "/api/v1/rules/:id", auth: "editor", handle: async ({ params, body, actor }) => ids.updateRule(params[0]!, await body(), actor()) },
    { method: "DELETE", path: "/api/v1/rules/:id", auth: "editor", handle: ({ res, params, actor }) => (ids.deleteRule(params[0]!, actor()), noContent(res)) },
    { method: "GET", path: "/api/v1/suppressions", auth: "viewer", handle: () => ({ suppressions: ids.suppressions() }) },
    {
      method: "POST",
      path: "/api/v1/suppressions",
      auth: "editor",
      handle: async ({ res, body, actor }) => json(res, 201, ids.createSuppression(await body(), actor())),
    },
    {
      method: "DELETE",
      path: "/api/v1/suppressions/:id",
      auth: "editor",
      handle: ({ res, params, actor }) => (ids.deleteSuppression(params[0]!, actor()), noContent(res)),
    },

    // Sensors, added by admins and enrolled with a one-time token.
    { method: "GET", path: "/api/v1/sensors", auth: "viewer", handle: () => ({ sensors: ids.sensors.list(hash()) }) },
    { method: "POST", path: "/api/v1/sensors", auth: "admin", handle: async ({ res, body }) => json(res, 201, ids.sensors.create(await body(), hash())) },
    { method: "GET", path: "/api/v1/sensors/:id", auth: "viewer", handle: ({ params }) => ids.sensors.get(params[0]!, hash()) },
    { method: "DELETE", path: "/api/v1/sensors/:id", auth: "admin", handle: ({ res, params }) => (ids.sensors.delete(params[0]!), noContent(res)) },
    { method: "POST", path: "/api/v1/sensors/:id/enroll-token", auth: "admin", handle: ({ params }) => ids.sensors.reEnroll(params[0]!, hash()) },

    // network-ids-agent: enrols once, then asks for what to write and sends what Suricata saw (ADR 0023).
    { method: "POST", path: "/api/v1/agent/enroll", auth: "none", handle: async ({ body }) => ids.sensors.enroll(await body()) },
    {
      method: "POST",
      path: "/api/v1/agent/config",
      auth: "agent",
      handle: async ({ body, sensor }) => {
        ids.sensors.report(sensor().id, await body());
        return ids.config();
      },
    },
    { method: "POST", path: "/api/v1/agent/events", auth: "agent", handle: async ({ req, sensor }) => ids.ingest(sensor(), await eventsBody(req)) },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[A-Za-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, and the sensor for agent routes. */
  function authorize(req: IncomingMessage, access: Access): { who: string | null; sensor?: { id: string; name: string } } {
    if (access === "none") return { who: null };
    if (access === "agent") {
      const sensor = ids.sensors.bySecret(req.headers.authorization);
      return { who: `sensor ${sensor.name}`, sensor };
    }
    if (tokenMatches(req.headers.authorization, adminToken)) return { who: "admin token" };
    const p = auth.authorize(req, access);
    return { who: p.kind === "session" ? p.user.name : `API token ${p.name}` };
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to take events as long as the database answers.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(ids, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const { who, sensor } = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({
          req,
          res,
          url,
          params,
          body: () => readJson(req),
          actor: () => who ?? "unknown",
          sensor: () => sensor ?? { id: "", name: "" },
        });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof IdsError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
