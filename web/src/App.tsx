import {
  AppShell,
  Badge,
  BarList,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  EntityChip,
  FacetFilter,
  FilterBar,
  formatBytes,
  KpiCard,
  KpiGrid,
  navigate,
  OverviewGrid,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  QueryBar,
  SearchInput,
  SelectField,
  SEVERITY_META,
  SeverityBadge,
  Sparkline,
  StackedBarChart,
  StatusBadge,
  Switch,
  Tabs,
  TextField,
  TONE_COLORS,
  toLocale,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
  type Tone,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import {
  ArrowRight,
  BookOpen,
  KeyRound,
  Layers,
  LogIn,
  LogOut,
  Plus,
  Radio,
  RotateCcw,
  ShieldAlert,
  ShieldOff,
  Trash2,
  UserRound,
  Users,
  Waypoints,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  RECORD_KINDS,
  SEVERITIES,
  Unauthorized,
  type Alert,
  type AlertDetail,
  type Deployment,
  type Flow,
  type FlowDetail,
  type NetRecord,
  type ProductLink,
  type RecordKind,
  type Rule,
  type RuleCheck,
  type Sensor,
  type SensorEnrollment,
  type SensorStatus,
  type Summary,
  type Suppression,
} from "./api.ts";
import { useT } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["alerts", "flows", "protocols", "rules", "sensors", "setup", "account", "members", "signin", "tokens", "about"] as const;
type Page = (typeof PAGES)[number];
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = [...PAGES];
function parsePage(path: string): Page {
  const page = path.replace(/^\//, "").split("/")[0] ?? "";
  return (PAGES as readonly string[]).includes(page) ? (page as Page) : "alerts";
}

/** A query parameter of the address. */
const param = (name: string) => new URLSearchParams(window.location.search).get(name);

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

/** Loads once, and again on demand or when the path changes. */
function useLoad<T>(call: Call, path: string | null) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const load = useCallback(() => {
    if (!path) return;
    void call<T>(path).then(
      (r) => (setData(r), setError(undefined)),
      (err: Error) => setError(err.message),
    );
  }, [call, path]);
  useEffect(load, [load]);
  return [data, load, error] as const;
}

/** Runs a change and reports its error, the way every form here does. */
function useAction(after: () => void) {
  const [error, setError] = useState<string>();
  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        setError(undefined);
        after();
        return true;
      } catch (err) {
        setError((err as Error).message);
        return false;
      }
    },
    [after],
  );
  return [run, error, setError] as const;
}

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
const hour = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
const hostPort = (ip: string, port: number | null) => (port === null ? ip : ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);
const bits = (bps: number) => (bps >= 1e9 ? `${(bps / 1e9).toFixed(2)} Gbps` : bps >= 1e6 ? `${(bps / 1e6).toFixed(1)} Mbps` : `${Math.round(bps / 1e3)} kbps`);
const percent = (ratio: number) => `${(ratio * 100).toFixed(ratio < 0.01 ? 2 : 1)}%`;
const seconds = (from: string, to: string) => Math.max(0, (Date.parse(to) - Date.parse(from)) / 1000);
function duration(s: number) {
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 0)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} m ${String(Math.round(s % 60)).padStart(2, "0")} s`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")} m`;
  return `${Math.floor(s / 86_400)} d ${Math.floor((s % 86_400) / 3600)} h`;
}

const SENSOR_TONE: Record<SensorStatus, Tone> = {
  online: "success",
  degraded: "warning",
  offline: "danger",
  "version-mismatch": "danger",
  "waiting-to-enrol": "neutral",
};

function SensorBadge({ status }: { status: SensorStatus }) {
  const t = useT();
  return <StatusBadge tone={SENSOR_TONE[status]}>{t(`sensorStates.${status}`)}</StatusBadge>;
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap text-fg">{children}</pre>;
}

function ErrorText({ message }: { message?: string }) {
  return message ? <p className="m-0 text-xs text-danger">{message}</p> : null;
}

/** Facts as a list of label, then value. */
function Facts({ items, label }: { items: Array<[string, ReactNode]>; label: string }) {
  return (
    <dl className="nids-facts text-sm" aria-label={label}>
      {items.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-fg-muted">{k}</dt>
          <dd className="font-mono text-xs">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Endpoints({ r }: { r: { srcIp: string; srcPort: number | null; destIp: string; destPort: number | null } }) {
  return (
    <span className="flex items-center gap-1 whitespace-nowrap">
      <EntityChip kind="ip" hideKind value={hostPort(r.srcIp, r.srcPort)} />
      <ArrowRight aria-hidden className="size-3 shrink-0 text-fg-muted" />
      <EntityChip kind="ip" hideKind value={hostPort(r.destIp, r.destPort)} />
    </span>
  );
}

/** One line of a protocol log, the way people read it. */
function recordLine(r: NetRecord): string {
  const d = r.detail as Record<string, string | number | undefined | null>;
  if (r.kind === "dns") return [d.type, d.rrname, d.rrtype, d.rcode].filter(Boolean).join("  ");
  if (r.kind === "http") return [d.http_method, d.hostname, d.url, d.status, d.http_user_agent && `"${d.http_user_agent}"`].filter(Boolean).join("  ");
  if (r.kind === "tls") return [d.version, d.sni, d.ja3 && `ja3=${d.ja3}`, d.subject].filter(Boolean).join("  ");
  const c = (r.detail.client ?? {}) as Record<string, string>;
  const s = (r.detail.server ?? {}) as Record<string, string>;
  return [c.software_version, "→", s.software_version].filter(Boolean).join("  ");
}

function Records({ records }: { records: NetRecord[] }) {
  const t = useT();
  if (!records.length) return <p className="m-0 text-xs text-fg-muted">{t("alertsPage.noRecords")}</p>;
  return (
    <Code>
      {records
        .map((r) => `${r.kind.padEnd(5)} ${hour(r.time)}  ${hostPort(r.srcIp, r.srcPort)} → ${hostPort(r.destIp, r.destPort)}  ${recordLine(r)}`)
        .join("\n")}
    </Code>
  );
}

// ---------------------------------------------------------------- Alerts

function useAlertColumns(): Column<Alert>[] {
  const t = useT();
  return [
    {
      id: "sev",
      header: t("alertsPage.severity"),
      width: "100px",
      sortValue: (a) => SEVERITY_META[a.severity].rank,
      cell: (a) => <SeverityBadge severity={a.severity} />,
    },
    {
      id: "sig",
      header: t("alertsPage.signature"),
      width: "32%",
      sortValue: (a) => a.signature,
      cell: (a) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium" title={a.signature}>
            {a.signature}
          </span>
          <span className="font-mono text-2xs text-fg-muted">
            sid:{a.sid} · {a.category || "–"}
            {a.suppressedBy && ` · ${t("alertsPage.suppressed")}`}
          </span>
        </span>
      ),
    },
    { id: "flow", header: t("alertsPage.flow"), cell: (a) => <Endpoints r={a} /> },
    { id: "proto", header: t("alertsPage.protocol"), mono: true, cell: (a) => [a.appProto?.toUpperCase(), a.proto].filter(Boolean).join("/") },
    { id: "sensor", header: t("alertsPage.sensor"), mono: true, sortValue: (a) => a.sensor.name, cell: (a) => a.sensor.name },
    {
      id: "time",
      header: t("alertsPage.time"),
      align: "right",
      mono: true,
      sortValue: (a) => a.time,
      cell: (a) => <span className="whitespace-nowrap">{when(a.time)}</span>,
    },
  ];
}

function AlertDetailPanel({ call, id, onSuppress }: { call: Call; id: number; onSuppress: (a: AlertDetail) => void }) {
  const t = useT();
  const { can } = useAuth();
  const [a] = useLoad<AlertDetail>(call, `/api/v1/alerts/${id}`);
  const [raw, setRaw] = useState(false);
  if (!a || a.id !== id) return <p className="py-6 text-center text-sm text-fg-muted">{t("product.loading")}</p>;
  const f = a.flow;
  const tls = a.records.find((r) => r.kind === "tls");
  return (
    <div className="flex flex-col gap-2.5">
      <span className="font-medium">{a.signature}</span>
      {a.suppression && (
        <Callout tone="info" title={t("alertsPage.suppressedBy", { reason: a.suppression.reason })}>
          {a.suppression.line}
        </Callout>
      )}
      <Facts
        label={t("alertsPage.flowDetail")}
        items={[
          [t("alertsPage.bytesOut"), f ? formatBytes(f.bytesToServer) : "–"],
          [t("alertsPage.bytesIn"), f ? formatBytes(f.bytesToClient) : "–"],
          [t("alertsPage.duration"), f ? duration(seconds(f.start, f.end)) : "–"],
          [t("alertsPage.protocol"), [a.appProto, a.proto].filter(Boolean).join("/")],
          [t("alertsPage.sensor"), a.sensor.name],
          ["JA3", (tls?.detail.ja3 as string | null) ?? "–"],
          ["Community ID", a.communityId ?? "–"],
          [t("alertsPage.rule"), `${a.gid}:${a.sid}:${a.rev}`],
        ]}
      />
      {!f && <p className="m-0 text-xs text-fg-muted">{t("alertsPage.flowLater")}</p>}
      <div className="flex flex-col gap-1">
        <h3 className="m-0 text-2xs font-medium tracking-wider text-fg-muted uppercase">{t("alertsPage.records")}</h3>
        <Records records={a.records} />
      </div>
      {a.otherAlerts.length > 0 && (
        <div className="flex flex-col gap-1">
          <h3 className="m-0 text-2xs font-medium tracking-wider text-fg-muted uppercase">{t("alertsPage.otherAlerts")}</h3>
          <ul className="nids-list flex flex-col gap-1 text-xs">
            {a.otherAlerts.map((o) => (
              <li key={o.id}>
                <a href={`/alerts?alert=${o.id}`}>{o.signature}</a>
              </li>
            ))}
          </ul>
        </div>
      )}
      {raw && <Code>{JSON.stringify(a.event, null, 2)}</Code>}
      <div className="flex flex-wrap gap-1.5 border-t border-line pt-2">
        {f && (
          <Button size="sm" onClick={() => navigate(`/flows?flow=${f.id}`)}>
            {t("alertsPage.openFlow")}
          </Button>
        )}
        {can("editor") && !a.suppressedBy && (
          <Button size="sm" icon={<ShieldOff aria-hidden />} onClick={() => onSuppress(a)}>
            {t("alertsPage.suppress")}
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={() => setRaw(!raw)}>
          {raw ? t("alertsPage.hideEvent") : t("alertsPage.showEvent")}
        </Button>
      </div>
    </div>
  );
}

/** Suppress a signature: for every address, or from one source or to one destination. */
function SuppressDialog({
  call,
  alert,
  onClose,
}: {
  call: Call;
  alert: { sid: number; gid: number; signature: string; srcIp?: string } | null;
  onClose: () => void;
}) {
  const t = useT();
  const [sid, setSid] = useState("");
  const [scope, setScope] = useState<"all" | "by_src" | "by_dst">("by_src");
  const [network, setNetwork] = useState("");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("30");
  const [run, error, setError] = useAction(onClose);
  useEffect(() => {
    setSid(alert?.sid ? String(alert.sid) : "");
    setNetwork(alert?.srcIp ?? "");
    setScope(alert?.srcIp ? "by_src" : "all");
    setReason("");
    setError(undefined);
  }, [alert, setError]);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(() =>
      call("/api/v1/suppressions", {
        method: "POST",
        body: JSON.stringify({
          sid: Number(sid),
          gid: alert?.gid ?? 1,
          track: scope === "all" ? null : scope,
          network: scope === "all" ? null : network.trim(),
          reason,
          expiresAt: days === "0" ? null : new Date(Date.now() + Number(days) * 86_400_000).toISOString(),
        }),
      }),
    );
  };
  return (
    <Dialog
      open={alert !== null}
      onOpenChange={(o) => !o && onClose()}
      title={t("suppress.title")}
      description={alert?.signature || t("suppress.description")}
      onSubmit={submit}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary">
            {t("suppress.save")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-2.5">
        <TextField label="SID" mono required inputMode="numeric" value={sid} onChange={(e) => setSid(e.target.value)} />
        <SelectField
          label={t("suppress.scope")}
          value={scope}
          onChange={(e) => setScope(e.target.value as typeof scope)}
          options={[
            { value: "by_src", label: t("suppress.bySrc") },
            { value: "by_dst", label: t("suppress.byDst") },
            { value: "all", label: t("suppress.all") },
          ]}
        />
        {scope !== "all" && (
          <TextField
            label={t("suppress.network")}
            hint={t("suppress.networkHint")}
            mono
            required
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
          />
        )}
        <TextField label={t("suppress.reason")} hint={t("suppress.reasonHint")} required value={reason} onChange={(e) => setReason(e.target.value)} />
        <SelectField
          label={t("suppress.until")}
          value={days}
          onChange={(e) => setDays(e.target.value)}
          options={[
            { value: "1", label: t("suppress.days", { count: 1 }) },
            { value: "7", label: t("suppress.days", { count: 7 }) },
            { value: "30", label: t("suppress.days", { count: 30 }) },
            { value: "90", label: t("suppress.days", { count: 90 }) },
            { value: "0", label: t("suppress.noEnd") },
          ]}
        />
        <ErrorText message={error} />
      </div>
    </Dialog>
  );
}

function WelcomePage() {
  const t = useT();
  const { can } = useAuth();
  return (
    <>
      <PageHeader title={t("welcomePage.title")} description={t("welcomePage.description")} />
      <Panel title={t("welcomePage.steps")}>
        <ol className="nids-steps text-sm">
          <li>{t("welcomePage.step1")}</li>
          <li>{t("welcomePage.step2")}</li>
          <li>{t("welcomePage.step3")}</li>
          <li>{t("welcomePage.step4")}</li>
        </ol>
        <div className="mt-3 flex flex-wrap gap-2">
          {can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => navigate("/sensors?add=1")}>
              {t("sensorsPage.add")}
            </Button>
          )}
          <Button onClick={() => navigate("/setup")}>{t("product.setup")}</Button>
        </div>
      </Panel>
    </>
  );
}

function AlertsPage({ call, summary, reload }: { call: Call; summary: Summary; reload: () => void }) {
  const t = useT();
  const [sev, setSev] = useState<string[]>([]);
  const [sensors, setSensors] = useState<string[]>([]);
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [selected, setSelected] = useState<number | undefined>(param("alert") ? Number(param("alert")) : undefined);
  const [suppressing, setSuppressing] = useState<AlertDetail | null>(null);
  const query = new URLSearchParams();
  for (const s of sev) query.append("severity", s);
  for (const s of sensors) query.append("sensor", s);
  if (q) query.set("q", q);
  if (showSuppressed) query.set("suppressed", "true");
  const [list, load] = useLoad<{ alerts: Alert[]; total: number }>(call, `/api/v1/alerts?${query}`);
  useEffect(() => {
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  }, [load]);
  const columns = useAlertColumns();
  const s = summary;
  const sensorsUp = s.sensors.online + s.sensors.degraded;
  return (
    <>
      <PageHeader
        title={t("alertsPage.title")}
        description={t("alertsPage.description")}
        meta={
          <StatusBadge tone={sensorsUp === s.sensors.total ? "success" : "warning"}>
            {t("alertsPage.sensorsUp", { up: sensorsUp, total: s.sensors.total })}
          </StatusBadge>
        }
        actions={
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setQ(draft.trim());
            }}
          >
            <SearchInput label={t("alertsPage.search")} className="w-60" value={draft} onChange={(e) => setDraft(e.target.value)} />
          </form>
        }
      />
      <FilterBar
        onClear={
          sev.length || sensors.length || q || showSuppressed
            ? () => {
                setSev([]);
                setSensors([]);
                setQ("");
                setDraft("");
                setShowSuppressed(false);
              }
            : undefined
        }
      >
        <FacetFilter
          label={t("alertsPage.severity")}
          selected={sev}
          onChange={setSev}
          options={SEVERITIES.map((v) => ({ value: v, label: t(`severities.${v}`), count: s.alerts.bySeverity[v] }))}
        />
        <FacetFilter
          label={t("alertsPage.sensor")}
          selected={sensors}
          onChange={setSensors}
          options={s.sensors.names.map((n) => ({ value: n.id, label: n.name }))}
        />
        <Switch checked={showSuppressed} onCheckedChange={setShowSuppressed} label={t("alertsPage.showSuppressed", { count: s.alerts.suppressed })} />
      </FilterBar>
      <KpiGrid minWidth={170}>
        <KpiCard
          label={t("alertsPage.lastDay")}
          value={s.alerts.lastDay}
          icon={ShieldAlert}
          footer={
            <span className="flex flex-wrap gap-1">
              {SEVERITIES.map((v) => (
                <span key={v} className="inline-flex items-center gap-1 font-mono text-xs text-fg">
                  <SeverityBadge severity={v} compact />
                  {s.alerts.bySeverity[v]}
                </span>
              ))}
            </span>
          }
        />
        <KpiCard
          label={t("alertsPage.critical")}
          value={s.alerts.bySeverity.critical}
          tone={s.alerts.bySeverity.critical ? "critical" : "success"}
          delta={
            s.alerts.lastHourCritical ? { label: t("alertsPage.lastHour", { count: s.alerts.lastHourCritical }), direction: "up", intent: "bad" } : undefined
          }
        />
        <KpiCard
          label={t("alertsPage.sensors")}
          value={sensorsUp}
          unit={t("alertsPage.of", { total: s.sensors.total })}
          tone={sensorsUp < s.sensors.total ? "warning" : undefined}
          delta={
            s.inspected.dropRatio !== null
              ? { label: t("alertsPage.dropped", { ratio: percent(s.inspected.dropRatio) }), intent: s.inspected.dropRatio >= 0.01 ? "bad" : "good" }
              : undefined
          }
          href="/sensors"
        />
        <KpiCard label={t("alertsPage.inspected")} value={bits(s.inspected.bitsPerSecond)} unit={t("alertsPage.now")} href="/sensors" />
      </KpiGrid>
      <OverviewGrid>
        <Panel title={t("alertsPage.perHour")} description={t("alertsPage.perHourDetail")}>
          <StackedBarChart
            label={t("alertsPage.perHour")}
            categories={s.alerts.perHour.map((h) => hour(h.hour))}
            height={160}
            xTicks={7}
            segments={SEVERITIES.map((v) => ({ id: v, name: t(`severities.${v}`), color: TONE_COLORS[SEVERITY_META[v].tone] }))}
            values={s.alerts.perHour.map((h) => SEVERITIES.map((v) => h[v]))}
          />
        </Panel>
        <Panel title={t("alertsPage.talkers")} description={t("alertsPage.talkersDetail")}>
          {s.talkers.length ? (
            <BarList
              label={t("alertsPage.talkers")}
              items={s.talkers.map((x) => ({ id: x.ip, label: x.ip, value: x.bytes, href: `/flows?q=${encodeURIComponent(`src_ip:${x.ip}`)}` }))}
              format={(v) => formatBytes(v)}
            />
          ) : (
            <p className="m-0 text-sm text-fg-muted">{t("alertsPage.noFlows")}</p>
          )}
        </Panel>
      </OverviewGrid>
      <OverviewGrid>
        <Panel
          title={t("alertsPage.title")}
          description={list ? t("alertsPage.shown", { shown: list.alerts.length, total: list.total }) : t("product.loading")}
          flush
        >
          <DataTable
            label={t("alertsPage.title")}
            columns={columns}
            rows={list?.alerts ?? []}
            loading={!list}
            getRowId={(a) => String(a.id)}
            onRowClick={(a) => setSelected(a.id)}
            activeRowId={selected === undefined ? undefined : String(selected)}
            defaultSort={{ id: "time", direction: "desc" }}
            minWidth={980}
            pageSize={50}
            empty={<p className="py-8">{t("alertsPage.none")}</p>}
          />
        </Panel>
        <Panel title={t("alertsPage.flowDetail")} aria-label={t("alertsPage.flowDetail")}>
          {selected !== undefined ? (
            <AlertDetailPanel key={selected} call={call} id={selected} onSuppress={setSuppressing} />
          ) : (
            <p className="py-6 text-center text-sm text-fg-muted">{t("alertsPage.select")}</p>
          )}
        </Panel>
      </OverviewGrid>
      <SuppressDialog
        call={call}
        alert={suppressing}
        onClose={() => {
          setSuppressing(null);
          load();
          reload();
        }}
      />
    </>
  );
}

// ---------------------------------------------------------------- Flows

const FLOW_EXAMPLES = ["app_proto:dns", "state:new", "dest_port:22", "alerted:true"];

function FlowsPage({ call }: { call: Call }) {
  const t = useT();
  const [draft, setDraft] = useState(param("q") ?? "");
  const [q, setQ] = useState(param("q") ?? "");
  const [active, setActive] = useState<number | undefined>(param("flow") ? Number(param("flow")) : undefined);
  const [list, , error] = useLoad<{ flows: Flow[]; total: number; bytes: number; unanswered: number; longLived: number }>(
    call,
    `/api/v1/flows?q=${encodeURIComponent(q)}`,
  );
  const [cur] = useLoad<FlowDetail>(call, active === undefined ? null : `/api/v1/flows/${active}`);
  const cols: Column<Flow>[] = [
    {
      id: "end",
      header: t("flowsPage.end"),
      mono: true,
      width: "170px",
      sortValue: (f) => f.end,
      cell: (f) => <span className="whitespace-nowrap">{when(f.end)}</span>,
    },
    { id: "flow", header: t("alertsPage.flow"), cell: (f) => <Endpoints r={f} /> },
    { id: "proto", header: "proto", mono: true, cell: (f) => f.proto },
    { id: "app", header: "app_proto", sortValue: (f) => f.appProto ?? "", cell: (f) => (f.appProto ? <Badge mono>{f.appProto}</Badge> : "–") },
    {
      id: "duration",
      header: t("alertsPage.duration"),
      align: "right",
      mono: true,
      sortValue: (f) => seconds(f.start, f.end),
      cell: (f) => duration(seconds(f.start, f.end)),
    },
    { id: "out", header: t("alertsPage.bytesOut"), align: "right", mono: true, sortValue: (f) => f.bytesToServer, cell: (f) => formatBytes(f.bytesToServer) },
    { id: "in", header: t("alertsPage.bytesIn"), align: "right", mono: true, sortValue: (f) => f.bytesToClient, cell: (f) => formatBytes(f.bytesToClient) },
    { id: "state", header: "state", mono: true, description: t("flowsPage.stateHelp"), cell: (f) => f.state ?? "–" },
    { id: "alerted", header: t("flowsPage.alerted"), cell: (f) => (f.alerted ? <Badge tone="danger">{t("flowsPage.alert")}</Badge> : "") },
    { id: "sensor", header: t("alertsPage.sensor"), mono: true, cell: (f) => f.sensor.name },
  ];
  return (
    <>
      <PageHeader title={t("flowsPage.title")} description={t("flowsPage.description")} />
      <FilterBar>
        <QueryBar
          label={t("flowsPage.query")}
          placeholder="app_proto:dns src_ip:192.0.2.17"
          value={draft}
          onChange={setDraft}
          onSubmit={(v) => setQ(v.trim())}
        />
      </FilterBar>
      <div className="flex flex-wrap items-center gap-1.5 text-xs text-fg-muted">
        <span>{t("flowsPage.try")}</span>
        {FLOW_EXAMPLES.map((x) => (
          <Button
            key={x}
            size="xs"
            variant="ghost"
            onClick={() => {
              setDraft(x);
              setQ(x);
            }}
          >
            <span className="font-mono">{x}</span>
          </Button>
        ))}
      </div>
      {error && <Callout tone="danger" title={error} />}
      <KpiGrid>
        <KpiCard label={t("flowsPage.flows")} value={list?.total ?? "–"} unit={t("flowsPage.lastDay")} />
        <KpiCard label={t("flowsPage.bytes")} value={list ? formatBytes(list.bytes) : "–"} />
        <KpiCard label={t("flowsPage.unanswered")} value={list?.unanswered ?? "–"} delta={{ label: t("flowsPage.unansweredHelp") }} />
        <KpiCard
          label={t("flowsPage.longLived")}
          value={list?.longLived ?? "–"}
          unit={t("flowsPage.overHour")}
          delta={{ label: t("flowsPage.longLivedHelp") }}
        />
      </KpiGrid>
      <OverviewGrid>
        <Panel
          title={t("flowsPage.title")}
          description={list ? t("alertsPage.shown", { shown: list.flows.length, total: list.total }) : t("product.loading")}
          flush
        >
          <DataTable
            label={t("flowsPage.title")}
            columns={cols}
            rows={list?.flows ?? []}
            loading={!list && !error}
            getRowId={(f) => String(f.id)}
            onRowClick={(f) => setActive(f.id)}
            activeRowId={active === undefined ? undefined : String(active)}
            defaultSort={{ id: "end", direction: "desc" }}
            minWidth={1100}
            pageSize={50}
            empty={<p className="py-8">{t("flowsPage.none")}</p>}
          />
        </Panel>
        <Panel
          title={t("flowsPage.connection")}
          description={cur && cur.id === active ? (cur.communityId ?? `flow_id ${cur.flowId ?? "–"}`) : t("flowsPage.select")}
          aria-label={t("flowsPage.connection")}
        >
          {cur && cur.id === active ? (
            <div className="flex flex-col gap-2.5">
              <Facts
                label={t("flowsPage.connection")}
                items={[
                  [t("alertsPage.sensor"), cur.sensor.name],
                  [t("flowsPage.start"), when(cur.start)],
                  ["state", `${cur.state ?? "–"} · ${cur.reason ?? "–"}`],
                  [t("flowsPage.packets"), `${cur.pktsToServer} / ${cur.pktsToClient}`],
                  [t("flowsPage.total"), formatBytes(cur.bytesToServer + cur.bytesToClient)],
                  [t("flowsPage.ratio"), (cur.bytesToServer / Math.max(1, cur.bytesToClient)).toFixed(2)],
                ]}
              />
              <div className="flex flex-col gap-1">
                <h3 className="m-0 text-2xs font-medium tracking-wider text-fg-muted uppercase">{t("alertsPage.records")}</h3>
                <Records records={cur.records} />
              </div>
              {cur.alerts.length > 0 && (
                <ul className="nids-list flex flex-col gap-1 text-sm">
                  {cur.alerts.map((a) => (
                    <li key={a.id} className="flex items-center gap-1.5">
                      <SeverityBadge severity={a.severity} compact />
                      <a href={`/alerts?alert=${a.id}`}>{a.signature}</a>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <p className="py-6 text-center text-sm text-fg-muted">{t("flowsPage.select")}</p>
          )}
        </Panel>
      </OverviewGrid>
    </>
  );
}

// ---------------------------------------------------------------- Protocols

function ProtocolsPage({ call }: { call: Call }) {
  const t = useT();
  const [kind, setKind] = useState<RecordKind>("dns");
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const [list] = useLoad<{ records: NetRecord[]; total: number; clients: number; top: Array<{ name: string; count: number }> }>(
    call,
    `/api/v1/protocols/${kind}?q=${encodeURIComponent(q)}`,
  );
  const cols: Column<NetRecord>[] = [
    {
      id: "time",
      header: t("alertsPage.time"),
      mono: true,
      width: "170px",
      sortValue: (r) => r.time,
      cell: (r) => <span className="whitespace-nowrap">{when(r.time)}</span>,
    },
    { id: "flow", header: t("alertsPage.flow"), cell: (r) => <Endpoints r={r} /> },
    {
      id: "name",
      header: t(`protocolsPage.name.${kind}`),
      sortValue: (r) => r.name,
      cell: (r) => <span className="nids-wrap font-mono text-xs">{r.name || "–"}</span>,
    },
    {
      id: "line",
      header: t("protocolsPage.detail"),
      cell: (r) => (
        <span className="nids-clamp font-mono text-2xs text-fg-muted" title={recordLine(r)}>
          {recordLine(r)}
        </span>
      ),
    },
    { id: "sensor", header: t("alertsPage.sensor"), mono: true, cell: (r) => r.sensor.name },
  ];
  return (
    <>
      <PageHeader
        title={t("protocolsPage.title")}
        description={t("protocolsPage.description")}
        actions={
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setQ(draft.trim());
            }}
          >
            <SearchInput label={t("protocolsPage.search")} className="w-60" value={draft} onChange={(e) => setDraft(e.target.value)} />
          </form>
        }
      />
      <Tabs label={t("protocolsPage.title")} value={kind} onChange={setKind} items={RECORD_KINDS.map((k) => ({ value: k, label: k.toUpperCase() }))} />
      <KpiGrid>
        <KpiCard label={t("protocolsPage.records")} value={list?.total ?? "–"} unit={t("flowsPage.lastDay")} />
        <KpiCard label={t("protocolsPage.clients")} value={list?.clients ?? "–"} />
        <KpiCard label={t("protocolsPage.names")} value={list?.top.length ?? "–"} unit={t("protocolsPage.inTop")} />
      </KpiGrid>
      <OverviewGrid>
        <Panel title={t(`protocolsPage.name.${kind}`)} flush>
          <DataTable
            label={t("protocolsPage.title")}
            columns={cols}
            rows={list?.records ?? []}
            loading={!list}
            getRowId={(r) => String(r.id)}
            defaultSort={{ id: "time", direction: "desc" }}
            minWidth={980}
            pageSize={50}
            empty={<p className="py-8">{t("protocolsPage.none")}</p>}
          />
        </Panel>
        <Panel title={t("protocolsPage.top")}>
          {list?.top.length ? (
            <BarList label={t("protocolsPage.top")} items={list.top.map((x) => ({ id: x.name, label: x.name, value: x.count }))} />
          ) : (
            <p className="m-0 text-sm text-fg-muted">{t("protocolsPage.none")}</p>
          )}
        </Panel>
      </OverviewGrid>
    </>
  );
}

// ---------------------------------------------------------------- Rules

const EXAMPLE_RULE = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Admin path probe"; http.uri; content:"/admin"; sid:9000104; rev:1;)';

function RulesPage({ call, summary, reload }: { call: Call; summary: Summary; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [data, load] = useLoad<{ rules: Rule[]; deployment: Deployment }>(call, "/api/v1/rules");
  const [sups, loadSups] = useLoad<{ suppressions: Suppression[] }>(call, "/api/v1/suppressions");
  const [text, setText] = useState(EXAMPLE_RULE);
  const [editing, setEditing] = useState<string | null>(null);
  const [check, setCheck] = useState<RuleCheck | null>(null);
  const [notice, setNotice] = useState("");
  const [suppressing, setSuppressing] = useState<{ sid: number; gid: number; signature: string } | null>(null);
  const after = useCallback(() => {
    load();
    loadSups();
    reload();
  }, [load, loadSups, reload]);
  const [run, error] = useAction(after);
  const d = data?.deployment;
  const validate = async () => {
    const r = await call<RuleCheck>("/api/v1/rules/check", { method: "POST", body: JSON.stringify({ text, ...(editing && { id: editing }) }) }).catch(
      () => null,
    );
    setCheck(r);
    return r;
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const r = await validate();
    if (!r?.ok) return;
    const ok = await run(() =>
      editing
        ? call(`/api/v1/rules/${editing}`, { method: "PUT", body: JSON.stringify({ text }) })
        : call("/api/v1/rules", { method: "POST", body: JSON.stringify({ text }) }),
    );
    if (ok) {
      setNotice(t("rulesPage.saved", { sid: r.sid ?? "" }));
      setEditing(null);
      setCheck(null);
    }
  };
  const ruleCols: Column<Rule>[] = [
    { id: "sid", header: "SID", mono: true, width: "100px", sortValue: (r) => r.sid, cell: (r) => r.sid },
    {
      id: "msg",
      header: t("rulesPage.rule"),
      cell: (r) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{r.msg}</span>
          <span className="nids-clamp font-mono text-2xs text-fg-muted" title={r.text}>
            {r.text}
          </span>
        </span>
      ),
    },
    { id: "hits", header: t("rulesPage.hits"), align: "right", mono: true, sortValue: (r) => r.alertsLastDay, cell: (r) => r.alertsLastDay },
    { id: "author", header: t("rulesPage.author"), cell: (r) => <span className="text-xs">{r.createdBy}</span> },
    {
      id: "on",
      header: t("rulesPage.active"),
      width: "90px",
      hideable: false,
      cell: (r) => (
        <Switch
          checked={r.enabled}
          disabled={!can("editor")}
          onCheckedChange={(v) => void run(() => call(`/api/v1/rules/${r.id}`, { method: "PUT", body: JSON.stringify({ enabled: v }) }))}
          label={<span className="sr-only">{t("rulesPage.use", { msg: r.msg })}</span>}
        />
      ),
    },
    {
      id: "actions",
      header: "",
      width: "110px",
      hideable: false,
      cell: (r) =>
        can("editor") && (
          <span className="flex justify-end gap-1">
            <Button
              size="xs"
              variant="ghost"
              onClick={() => {
                setEditing(r.id);
                setText(r.text);
                setCheck(null);
              }}
            >
              {t("rulesPage.edit")}
            </Button>
            <Button
              size="xs"
              variant="ghost"
              icon={<Trash2 />}
              aria-label={t("rulesPage.delete", { sid: r.sid })}
              onClick={() => void run(() => call(`/api/v1/rules/${r.id}`, { method: "DELETE" }))}
            />
          </span>
        ),
    },
  ];
  return (
    <>
      <PageHeader title={t("rulesPage.title")} description={t("rulesPage.description")} />
      {notice && <Callout tone="success" title={notice} onDismiss={() => setNotice("")} />}
      {d && d.outdated > 0 && (
        <Callout tone="info" title={t("rulesPage.outdated", { count: d.outdated })}>
          {t("rulesPage.outdatedDetail")}
        </Callout>
      )}
      <ErrorText message={error} />
      <KpiGrid>
        <KpiCard
          label={t("rulesPage.loaded")}
          value={summary.rules.loaded.toLocaleString()}
          unit={t("rulesPage.onSensors", { count: summary.sensors.total })}
          tone={summary.rules.failed ? "warning" : undefined}
          delta={summary.rules.failed ? { label: t("rulesPage.failed", { count: summary.rules.failed }), intent: "bad" } : undefined}
        />
        <KpiCard label={t("rulesPage.local")} value={summary.rules.local} />
        <KpiCard label={t("rulesPage.suppressions")} value={summary.rules.suppressions} />
        <KpiCard
          label={t("rulesPage.deployed")}
          value={d ? d.total - d.waiting - d.outdated : "–"}
          unit={t("alertsPage.of", { total: d ? d.total - d.waiting : 0 })}
          tone={d?.outdated ? "warning" : undefined}
        />
      </KpiGrid>
      <OverviewGrid layout="halves">
        <Panel title={editing ? t("rulesPage.change") : t("rulesPage.write")} description={t("rulesPage.writeDetail")}>
          {can("editor") ? (
            <form aria-label={t("rulesPage.editor")} className="flex flex-col gap-2.5" onSubmit={(e) => void save(e)}>
              <label className="flex flex-col gap-1">
                <span className="text-xs font-medium text-fg">{t("rulesPage.rule")}</span>
                <textarea className="nids-textarea" value={text} rows={4} spellCheck={false} onChange={(e) => (setText(e.target.value), setCheck(null))} />
              </label>
              {check && (
                <span role="status" className={check.ok ? "text-xs text-success" : "text-xs text-danger"}>
                  {check.ok ? t("rulesPage.valid", { sid: check.sid ?? "", rev: check.rev ?? "" }) : check.error}
                </span>
              )}
              <div className="flex gap-2">
                <Button type="button" size="sm" onClick={() => void validate()}>
                  {t("rulesPage.validate")}
                </Button>
                <Button type="submit" size="sm" variant="primary">
                  {t("rulesPage.save")}
                </Button>
                {editing && (
                  <Button type="button" size="sm" variant="ghost" onClick={() => (setEditing(null), setText(EXAMPLE_RULE), setCheck(null))}>
                    {t("common.cancel")}
                  </Button>
                )}
              </div>
            </form>
          ) : (
            <p className="m-0 text-sm text-fg-muted">{t("rulesPage.editorsOnly")}</p>
          )}
        </Panel>
        <Panel
          title={t("rulesPage.suppressions")}
          description={t("rulesPage.suppressionsDetail")}
          flush
          actions={
            can("editor") && (
              <Button size="xs" icon={<Plus />} onClick={() => setSuppressing({ sid: 0, gid: 1, signature: "" })}>
                {t("rulesPage.addSuppression")}
              </Button>
            )
          }
        >
          {sups?.suppressions.length ? (
            <ul className="nids-list flex flex-col" aria-label={t("rulesPage.suppressions")}>
              {sups.suppressions.map((s) => (
                <li key={s.id} className="nids-row">
                  <span className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm">{s.signature ?? `sid:${s.sid}`}</span>
                    <span className="flex items-center gap-1.5">
                      {s.state === "expired" ? <Badge>{t("rulesPage.ended")}</Badge> : <span className="font-mono text-2xs text-fg-muted">sid:{s.sid}</span>}
                      {can("editor") && s.state === "active" && (
                        <Button
                          size="xs"
                          variant="ghost"
                          icon={<Trash2 />}
                          aria-label={t("rulesPage.end", { sid: s.sid })}
                          onClick={() => void run(() => call(`/api/v1/suppressions/${s.id}`, { method: "DELETE" }))}
                        />
                      )}
                    </span>
                  </span>
                  <span className="text-2xs text-fg-muted">
                    {s.track ? t(`rulesPage.${s.track}`, { network: s.network ?? "" }) : t("rulesPage.allAddresses")} · {s.reason} · {s.createdBy} ·{" "}
                    {s.expiresAt ? t("rulesPage.until", { when: when(s.expiresAt) }) : t("suppress.noEnd")} ·{" "}
                    {t("rulesPage.held", { count: s.suppressedLastDay })}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="m-0 px-3 py-3 text-sm text-fg-muted">{t("rulesPage.noSuppressions")}</p>
          )}
        </Panel>
      </OverviewGrid>
      <Panel title={t("rulesPage.localRules")} description={t("rulesPage.count", { count: data?.rules.length ?? 0 })} flush>
        <DataTable
          label={t("rulesPage.localRules")}
          rows={data?.rules ?? []}
          loading={!data}
          getRowId={(r) => r.id}
          minWidth={900}
          columns={ruleCols}
          empty={<p className="py-8">{t("rulesPage.noRules")}</p>}
        />
      </Panel>
      <Callout tone="info" title={t("rulesPage.rulesets")}>
        {t("rulesPage.rulesetsDetail")}
      </Callout>
      <SuppressDialog
        call={call}
        alert={suppressing}
        onClose={() => {
          setSuppressing(null);
          after();
        }}
      />
    </>
  );
}

// ---------------------------------------------------------------- Sensors

function agentCommand(origin: string, token: string) {
  return `openssl rand -hex 32 > openasy-agent-kek   # keep it with your backups
docker run -d --name network-ids-agent --restart unless-stopped --read-only \\
  --cap-drop ALL --security-opt no-new-privileges \\
  -v network-ids-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \\
  -v /var/log/suricata:/var/log/suricata:ro -v /etc/suricata/openasy:/rules \\
  -v /var/run/suricata:/var/run/suricata \\
  -e NETWORK_IDS_URL=${origin} -e NETWORK_IDS_ENROLL_TOKEN=${token} \\
  ghcr.io/openasy/network-ids-agent:${colophon.version}`;
}

function SensorCard({ s, call, reload, onToken }: { s: Sensor; call: Call; reload: () => void; onToken: (e: SensorEnrollment) => void }) {
  const t = useT();
  const { can } = useAuth();
  const [run, error] = useAction(reload);
  const drop = s.suricata?.dropRatio ?? null;
  const drops = s.lastDay.map((h) => (h.dropRatio ?? 0) * 100);
  return (
    <Panel
      aria-label={t("sensorsPage.sensor", { name: s.name })}
      title={<span className="font-mono">{s.name}</span>}
      description={s.description || s.hostname || "–"}
      actions={<SensorBadge status={s.status} />}
    >
      <div className="flex flex-col gap-2.5">
        {s.status === "waiting-to-enrol" ? (
          <p className="m-0 text-sm text-fg-muted">{t("sensorsPage.waiting")}</p>
        ) : (
          <>
            <dl className="nids-stats text-sm">
              <div>
                <dt className="text-2xs text-fg-muted">{t("sensorsPage.traffic")}</dt>
                <dd className="font-mono font-semibold">{s.suricata?.bitsPerSecond != null ? bits(s.suricata.bitsPerSecond) : "–"}</dd>
              </div>
              <div>
                <dt className="text-2xs text-fg-muted">{t("sensorsPage.dropped")}</dt>
                <dd className={drop !== null && drop >= 0.01 ? "font-mono font-semibold text-warning" : "font-mono font-semibold"}>
                  {drop !== null ? percent(drop) : "–"}
                </dd>
              </div>
              <div>
                <dt className="text-2xs text-fg-muted">{t("sensorsPage.rules")}</dt>
                <dd className="font-mono font-semibold">{s.suricata?.rulesLoaded?.toLocaleString() ?? "–"}</dd>
              </div>
              <div>
                <dt className="text-2xs text-fg-muted">{t("sensorsPage.events")}</dt>
                <dd className="font-mono font-semibold">{s.eventsIn.toLocaleString()}</dd>
              </div>
            </dl>
            <Sparkline
              data={drops}
              label={t("sensorsPage.dropRate", { name: s.name })}
              height={28}
              color={drop !== null && drop >= 0.01 ? "var(--oa-warning)" : undefined}
              format={(v) => `${v.toFixed(2)}%`}
            />
            {s.suricata?.rulesFailed ? <Callout tone="warning" title={t("sensorsPage.rulesFailed", { count: s.suricata.rulesFailed })} /> : null}
            {s.config.error && (
              <Callout tone="warning" title={t("sensorsPage.configError")}>
                {s.config.error}
              </Callout>
            )}
            {s.lastError && <Callout tone="danger" title={s.lastError} />}
            <Facts
              label={t("sensorsPage.sensor", { name: s.name })}
              items={[
                [t("sensorsPage.host"), s.hostname ?? "–"],
                ["EVE", s.evePath ?? "–"],
                [t("sensorsPage.agent"), s.version ?? "–"],
                [t("sensorsPage.localRules"), s.config.upToDate ? t("sensorsPage.upToDate") : t("sensorsPage.notYet")],
                [t("sensorsPage.lastReload"), s.suricata?.lastReload ? when(s.suricata.lastReload) : "–"],
                [t("sensorsPage.lastSeen"), s.lastSeenAt ? when(s.lastSeenAt) : "–"],
              ]}
            />
          </>
        )}
        <ErrorText message={error} />
        {can("admin") && (
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-2">
            <Button
              size="xs"
              icon={<RotateCcw />}
              onClick={() => void run(async () => onToken(await call<SensorEnrollment>(`/api/v1/sensors/${s.id}/enroll-token`, { method: "POST" })))}
            >
              {t("sensorsPage.reEnroll")}
            </Button>
            <Button
              size="xs"
              variant="ghost"
              icon={<Trash2 />}
              onClick={() =>
                window.confirm(t("sensorsPage.deleteConfirm", { name: s.name })) && void run(() => call(`/api/v1/sensors/${s.id}`, { method: "DELETE" }))
              }
            >
              {t("sensorsPage.delete")}
            </Button>
          </div>
        )}
      </div>
    </Panel>
  );
}

function SensorsPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [data, load] = useLoad<{ sensors: Sensor[] }>(call, "/api/v1/sensors");
  const [adding, setAdding] = useState(param("add") === "1");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [token, setToken] = useState<SensorEnrollment | null>(null);
  const after = useCallback(() => (load(), reload()), [load, reload]);
  const [run, error] = useAction(after);
  useEffect(() => {
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  }, [load]);
  const sensors = data?.sensors ?? [];
  const worst = sensors.filter((s) => s.status === "degraded" && (s.suricata?.dropRatio ?? 0) >= 0.01);
  return (
    <>
      <PageHeader
        title={t("sensorsPage.title")}
        description={t("sensorsPage.description")}
        meta={sensors.some((s) => s.status !== "online") ? <StatusBadge tone="warning">{t("sensorsPage.notAllOnline")}</StatusBadge> : undefined}
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {t("sensorsPage.add")}
            </Button>
          )
        }
      />
      {worst.map((s) => (
        <Callout key={s.id} tone="warning" title={t("sensorsPage.drops", { name: s.name, ratio: percent(s.suricata!.dropRatio!) })}>
          {t("sensorsPage.dropsDetail")}
        </Callout>
      ))}
      {!data ? (
        <EmptyState title={t("product.loading")} icon={<Radio />} />
      ) : !sensors.length ? (
        <EmptyState title={t("sensorsPage.none")} icon={<Radio />}>
          {t("sensorsPage.noneDetail")}
        </EmptyState>
      ) : (
        <div className="nids-cards">
          {sensors.map((s) => (
            <SensorCard key={s.id} s={s} call={call} reload={after} onToken={setToken} />
          ))}
        </div>
      )}
      <Dialog
        open={adding}
        onOpenChange={setAdding}
        title={t("sensorsPage.add")}
        description={t("sensorsPage.addDetail")}
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const r = await call<SensorEnrollment>("/api/v1/sensors", { method: "POST", body: JSON.stringify({ name, description }) });
            setAdding(false);
            setName("");
            setDescription("");
            setToken(r);
          });
        }}
        footer={
          <>
            <Button type="button" variant="ghost" onClick={() => setAdding(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="primary">
              {t("sensorsPage.addButton")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-2.5">
          <TextField label={t("sensorsPage.name")} hint={t("sensorsPage.nameHint")} mono required value={name} onChange={(e) => setName(e.target.value)} />
          <TextField label={t("sensorsPage.where")} hint={t("sensorsPage.whereHint")} value={description} onChange={(e) => setDescription(e.target.value)} />
          <ErrorText message={error} />
        </div>
      </Dialog>
      <Dialog
        open={token !== null}
        onOpenChange={(o) => !o && setToken(null)}
        size="lg"
        title={t("sensorsPage.enrol", { name: token?.sensor.name ?? "" })}
        description={t("sensorsPage.enrolDetail", { when: token ? when(token.enrollExpiresAt) : "" })}
        footer={
          <Button variant="primary" onClick={() => setToken(null)}>
            {t("sensorsPage.done")}
          </Button>
        }
      >
        {token && <Code>{agentCommand(window.location.origin, token.enrollToken)}</Code>}
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const t = useT();
  return (
    <>
      <PageHeader title={t("setupPage.title")} description={t("setupPage.description")} />
      <Panel title={t("setupPage.suricata")} description={t("setupPage.suricataDetail")}>
        <Code>{`# /etc/suricata/suricata.yaml
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      community-id: true
      types:
        - alert
        - flow
        - dns
        - http
        - tls
        - ssh
        - stats:
            totals: yes

rule-files:
  - suricata.rules              # ET Open and others, kept by suricata-update
  - /etc/suricata/openasy/openasy.rules

threshold-file: /etc/suricata/openasy/threshold.config

unix-command:
  enabled: yes
  filename: /var/run/suricata/suricata-command.socket`}</Code>
      </Panel>
      <Panel title={t("setupPage.agent")} description={t("setupPage.agentDetail")}>
        <Code>{agentCommand(window.location.origin, "oie_...")}</Code>
      </Panel>
      <Panel title={t("setupPage.how")}>
        <ul className="nids-steps text-sm">
          <li>{t("setupPage.how1")}</li>
          <li>{t("setupPage.how2")}</li>
          <li>{t("setupPage.how3")}</li>
        </ul>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const page = parsePage(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(
          r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "network-ids" && (PRODUCT_IDS as readonly string[]).includes(p.id)),
        ),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "alerts", label: msg("product.alerts"), icon: ShieldAlert, count: summary?.alerts.lastDay || undefined },
    { id: "flows", label: msg("product.flows"), icon: Waypoints },
    { id: "protocols", label: msg("product.protocols"), icon: Layers },
    { id: "rules", label: msg("product.rules"), icon: BookOpen },
    { id: "sensors", label: msg("product.sensors"), icon: Radio, count: summary?.sensors.total || undefined },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = page === "account" || page === "members" || page === "signin" || page === "tokens";

  return (
    <AppShell
      product="network-ids"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={page}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={page as "account" | "members" | "signin" | "tokens"} />
      ) : page === "setup" ? (
        <SetupPage />
      ) : !summary ? (
        <EmptyState title={msg("product.loading")} icon={<ShieldAlert />}>
          {msg("product.reading")}
        </EmptyState>
      ) : page === "alerts" && !summary.sensors.total ? (
        <WelcomePage />
      ) : page === "alerts" ? (
        <AlertsPage key={window.location.search} call={call} summary={summary} reload={reload} />
      ) : page === "flows" ? (
        <FlowsPage key={window.location.search} call={call} />
      ) : page === "protocols" ? (
        <ProtocolsPage call={call} />
      ) : page === "rules" ? (
        <RulesPage call={call} summary={summary} reload={reload} />
      ) : (
        <SensorsPage call={call} reload={reload} />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Network IDS">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
