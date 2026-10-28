import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { createIds } from "./ids.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.NETWORK_IDS_DB ?? "/data/network-ids.db";
const days = (name: string, fallback: number) => {
  const v = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(v) || v < 1 || v > 3650) throw new Error(`${name} must be a whole number of days, 1 to 3650`);
  return v;
};
const alertRetentionDays = days("NETWORK_IDS_ALERT_RETENTION_DAYS", 90);
const flowRetentionDays = days("NETWORK_IDS_FLOW_RETENTION_DAYS", 30);
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.NETWORK_IDS_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.NETWORK_IDS_METRICS_PORT ? Number(process.env.NETWORK_IDS_METRICS_PORT) : undefined;

const db = openDb(dbPath);
// The address people open Network IDS at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.NETWORK_IDS_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.NETWORK_IDS_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const auth = createAuth({
  db,
  product: "network-ids",
  productName: "OpenAsy Network IDS",
  origin: publicUrl,
  // Locally the same Network IDS is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.NETWORK_IDS_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "NETWORK_IDS_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

const ids = createIds(db, { version, alertRetentionDays, flowRetentionDays });
const server = createServer(
  createApp({
    db,
    ids,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(ids, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "network-ids started", { version, port, db: dbPath, headless, alertRetentionDays, flowRetentionDays }));
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log(
    "warn",
    "NETWORK_IDS_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys, and agents send their secret in the clear. Put network-ids behind TLS (ADR 0026)",
    {
      url: publicUrl,
    },
  );
}
if (!secretsKey)
  log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", {
    file: secretsKeyFile,
  });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

ids.purge();
const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000), setInterval(() => ids.purge(), 3_600_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
