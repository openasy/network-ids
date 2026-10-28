// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  alertsLastDay: Record<string, number>;
  sensors: { total: number; online: number; degraded: number; offline: number; versionMismatch: number; waiting: number; outdated: number };
  received: Record<string, number>;
  refused: number;
  drops: Array<{ sensor: string; ratio: number }>;
}

/** Label values are sensor names, which are letters, digits, dots, dashes and underscores; escaped all the same. */
const label = (v: string) => v.replace(/[\\"\n]/g, (c) => (c === "\n" ? "\\n" : `\\${c}`));

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="network-ids",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_network_ids_alerts_last_day Alerts in the last 24 hours, without suppressed ones, by severity.",
    "# TYPE openasy_network_ids_alerts_last_day gauge",
    ...Object.entries(g.alertsLastDay).map(([s, n]) => `openasy_network_ids_alerts_last_day{severity="${s}"} ${n}`),
    "# HELP openasy_network_ids_sensors Sensors by status.",
    "# TYPE openasy_network_ids_sensors gauge",
    `openasy_network_ids_sensors{status="online"} ${g.sensors.online}`,
    `openasy_network_ids_sensors{status="degraded"} ${g.sensors.degraded}`,
    `openasy_network_ids_sensors{status="offline"} ${g.sensors.offline}`,
    `openasy_network_ids_sensors{status="version-mismatch"} ${g.sensors.versionMismatch}`,
    `openasy_network_ids_sensors{status="waiting-to-enrol"} ${g.sensors.waiting}`,
    "# HELP openasy_network_ids_sensors_outdated Enrolled sensors that have not written the current local rules and suppressions.",
    "# TYPE openasy_network_ids_sensors_outdated gauge",
    `openasy_network_ids_sensors_outdated ${g.sensors.outdated}`,
    "# HELP openasy_network_ids_events_received_total EVE events kept since start, by kind.",
    "# TYPE openasy_network_ids_events_received_total counter",
    ...["alert", "flow", "record", "stats"].map((k) => `openasy_network_ids_events_received_total{kind="${k}"} ${g.received[k] ?? 0}`),
    "# HELP openasy_network_ids_events_refused_total EVE events refused since start: not Suricata's form.",
    "# TYPE openasy_network_ids_events_refused_total counter",
    `openasy_network_ids_events_refused_total ${g.refused}`,
    "# HELP openasy_network_ids_sensor_drop_ratio Packets the sensor's capture dropped, 0 to 1, over its last minute of counters.",
    "# TYPE openasy_network_ids_sensor_drop_ratio gauge",
    ...g.drops.map((d) => `openasy_network_ids_sensor_drop_ratio{sensor="${label(d.sensor)}"} ${d.ratio}`),
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
