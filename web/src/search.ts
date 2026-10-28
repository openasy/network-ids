// What the search window (Cmd+K) finds in Network IDS: alerts of the last day by signature, address or sid, as the
// Alerts page searches them.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { ShieldAlert } from "lucide-react";
import type { Alert } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const { alerts } = await call<{ alerts: Alert[] }>(`/api/v1/alerts?q=${encodeURIComponent(q)}`, { signal });
    return alerts.slice(0, 8).map((a): SearchResult => ({
      id: `alert:${a.id}`,
      label: a.signature,
      detail: `${a.srcIp} → ${a.destIp}`,
      kind: t("search.alert"),
      icon: ShieldAlert,
      severity: a.severity,
      href: `/alerts?alert=${a.id}`,
    }));
  };
}
