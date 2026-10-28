import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OPENAPI } from "../scripts/openapi.ts";
import { ADMIN_TOKEN, alertEvent, dnsEvent, flowEvent, startApp, statsEvent, T0 } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "network-ids-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1").replaceAll("{", "%7B").replaceAll("}", "%7D")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate, `no schema at ${schema}`).toBeDefined();
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));

describe("openapi.json", () => {
  it("is what scripts/openapi.ts writes", () => {
    expect(spec).toEqual(JSON.parse(JSON.stringify(OPENAPI)));
  });

  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // Network IDS's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let sensor = "";
  let secret = "";
  let alert = 0;
  let flow = 0;
  let rule = "";
  let suppression = "";
  const report = { version, hostname: "nids-core-01", evePath: "/var/log/suricata/eve.json", configHash: null, configError: null };
  const asAgent = (b: unknown) => auth(secret, typeof b === "string" ? b : JSON.stringify(b));

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("sensors and their agent", async () => {
    const added = (await call("POST", "/api/v1/sensors", admin({ name: "nids-core-01", description: "Core switch SPAN" }))).body as any;
    sensor = added.sensor.id;
    await call("POST", "/api/v1/sensors", admin({ name: "nids-core-01" }));
    await call("POST", "/api/v1/sensors", admin({ name: "bad name" }));
    await call("POST", "/api/v1/sensors", admin("nope"));
    await call("POST", "/api/v1/sensors", { method: "POST" });
    await call("POST", "/api/v1/agent/enroll", admin({ token: "oie_nope", ...report }));
    await call("POST", "/api/v1/agent/enroll", admin({ token: added.enrollToken, version: 1 }));
    await call("POST", "/api/v1/agent/enroll", admin("nope"));
    secret = ((await call("POST", "/api/v1/agent/enroll", admin({ token: added.enrollToken, ...report }))).body as any).secret;
    await call("POST", "/api/v1/agent/config", asAgent(report));
    await call("POST", "/api/v1/agent/config", asAgent({ ...report, version: "0.0.1" }));
    await call("POST", "/api/v1/agent/config", asAgent({ ...report, configHash: "nope" }));
    await call("POST", "/api/v1/agent/config", asAgent("nope"));
    await call("POST", "/api/v1/agent/config", admin(report));
    await call("POST", "/api/v1/agent/config", asAgent(report));
    await call(
      "POST",
      "/api/v1/agent/events",
      asAgent({
        events: [
          alertEvent(),
          flowEvent(),
          dnsEvent(),
          statsEvent(T0 - 120_000, { uptime: 10, packets: 100, drops: 0, bytes: 1000 }),
          statsEvent(T0 - 60_000, { uptime: 70, packets: 200, drops: 1, bytes: 9000 }),
        ],
      }),
    );
    await call("POST", "/api/v1/agent/events", asAgent({ events: [{ event_type: "alert" }] }));
    await call("POST", "/api/v1/agent/events", asAgent({ events: Array.from({ length: 5001 }, () => ({})) }));
    await call("POST", "/api/v1/agent/events", asAgent({ events: "nope" }));
    await call("POST", "/api/v1/agent/events", asAgent("{nope"));
    await call("POST", "/api/v1/agent/events", admin({ events: [] }));
    await call("GET", "/api/v1/sensors", admin());
    await call("GET", "/api/v1/sensors", {});
    await call("GET", "/api/v1/sensors/{id}", admin(), `/api/v1/sensors/${sensor}`);
    await call("GET", "/api/v1/sensors/{id}", admin(), "/api/v1/sensors/missing");
    await call("GET", "/api/v1/sensors/{id}", {}, `/api/v1/sensors/${sensor}`);
  });

  it("alerts, flows and protocol logs", async () => {
    alert = ((await call("GET", "/api/v1/alerts", admin())).body as any).alerts[0].id;
    await call("GET", "/api/v1/alerts", admin(), "/api/v1/alerts?severity=critical&q=dns&suppressed=all&hours=48");
    await call("GET", "/api/v1/alerts", admin(), "/api/v1/alerts?severity=urgent");
    await call("GET", "/api/v1/alerts", {});
    await call("GET", "/api/v1/alerts/{id}", admin(), `/api/v1/alerts/${alert}`);
    await call("GET", "/api/v1/alerts/{id}", admin(), "/api/v1/alerts/999");
    await call("GET", "/api/v1/alerts/{id}", {}, `/api/v1/alerts/${alert}`);
    flow = ((await call("GET", "/api/v1/flows", admin(), "/api/v1/flows?q=192.0.2.17 app_proto:dns")).body as any).flows[0].id;
    await call("GET", "/api/v1/flows", admin(), "/api/v1/flows?q=port:x");
    await call("GET", "/api/v1/flows", {});
    await call("GET", "/api/v1/flows/{id}", admin(), `/api/v1/flows/${flow}`);
    await call("GET", "/api/v1/flows/{id}", admin(), "/api/v1/flows/999");
    await call("GET", "/api/v1/flows/{id}", {}, `/api/v1/flows/${flow}`);
    await call("GET", "/api/v1/protocols/{kind}", admin(), "/api/v1/protocols/dns?q=tunnel");
    await call("GET", "/api/v1/protocols/{kind}", admin(), "/api/v1/protocols/smtp");
    await call("GET", "/api/v1/protocols/{kind}", admin(), "/api/v1/protocols/tls?hours=0");
    await call("GET", "/api/v1/protocols/{kind}", {}, "/api/v1/protocols/dns");
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("local rules", async () => {
    const text = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Admin path probe"; http.uri; content:"/admin"; sid:9000104; rev:1;)';
    rule = ((await call("POST", "/api/v1/rules", admin({ text }))).body as any).id;
    await call("POST", "/api/v1/rules", admin({ text }));
    await call("POST", "/api/v1/rules", admin({ text: "alert" }));
    await call("POST", "/api/v1/rules", admin("nope"));
    await call("POST", "/api/v1/rules", { method: "POST" });
    await call("POST", "/api/v1/rules/check", admin({ text }));
    await call("POST", "/api/v1/rules/check", admin({ text: "drop" }));
    await call("POST", "/api/v1/rules/check", admin("nope"));
    await call("POST", "/api/v1/rules/check", { method: "POST" });
    await call("GET", "/api/v1/rules", admin());
    await call("GET", "/api/v1/rules", {});
    const r = "/api/v1/rules/{id}";
    await call("PUT", r, admin({ enabled: false }), `/api/v1/rules/${rule}`);
    await call("PUT", r, admin({ text: "alert" }), `/api/v1/rules/${rule}`);
    await call("PUT", r, admin("nope"), `/api/v1/rules/${rule}`);
    await call("PUT", r, admin({ enabled: true }), "/api/v1/rules/missing");
    await call("PUT", r, { method: "PUT" }, `/api/v1/rules/${rule}`);
    const other = ((await call("POST", "/api/v1/rules", admin({ text: text.replace("9000104", "9000105") }))).body as any).id;
    await call("PUT", r, admin({ text }), `/api/v1/rules/${other}`);
    await call("DELETE", r, admin(), `/api/v1/rules/${rule}`);
    await call("DELETE", r, admin(), "/api/v1/rules/missing");
    await call("DELETE", r, { method: "DELETE" }, `/api/v1/rules/${other}`);
  });

  it("suppressions", async () => {
    suppression = (
      (await call("POST", "/api/v1/suppressions", admin({ sid: 2027758, track: "by_src", network: "192.0.2.0/24", reason: "Lab resolver" }))).body as any
    ).id;
    await call("POST", "/api/v1/suppressions", admin({ sid: 1, reason: "" }));
    await call("POST", "/api/v1/suppressions", admin("nope"));
    await call("POST", "/api/v1/suppressions", { method: "POST" });
    await call("GET", "/api/v1/suppressions", admin());
    await call("GET", "/api/v1/suppressions", {});
    await call("POST", "/api/v1/agent/events", asAgent({ events: [alertEvent({ flow_id: 99 })] }));
    await call("GET", "/api/v1/alerts/{id}", admin(), `/api/v1/alerts/${alert + 1}`);
    await call("DELETE", "/api/v1/suppressions/{id}", admin(), `/api/v1/suppressions/${suppression}`);
    await call("DELETE", "/api/v1/suppressions/{id}", admin(), "/api/v1/suppressions/missing");
    await call("DELETE", "/api/v1/suppressions/{id}", { method: "DELETE" }, `/api/v1/suppressions/${suppression}`);
  });

  it("enrolment again, and deleting a sensor", async () => {
    await call("POST", "/api/v1/sensors/{id}/enroll-token", admin(), `/api/v1/sensors/${sensor}/enroll-token`);
    await call("POST", "/api/v1/sensors/{id}/enroll-token", admin(), "/api/v1/sensors/missing/enroll-token");
    await call("POST", "/api/v1/sensors/{id}/enroll-token", { method: "POST" }, `/api/v1/sensors/${sensor}/enroll-token`);
    await call("DELETE", "/api/v1/sensors/{id}", admin(), `/api/v1/sensors/${sensor}`);
    await call("DELETE", "/api/v1/sensors/{id}", admin(), "/api/v1/sensors/missing");
    await call("DELETE", "/api/v1/sensors/{id}", {}, `/api/v1/sensors/${sensor}`);
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
