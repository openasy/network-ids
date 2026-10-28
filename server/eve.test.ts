import { describe, expect, it } from "vitest";
import { eveTime, readEvent, severityOf } from "./eve.ts";
import { alertEvent, dnsEvent, flowEvent, statsEvent, T0 } from "./test-app.ts";

describe("EVE events", () => {
  it("read Suricata's timestamps, with microseconds and a zone without a colon", () => {
    expect(eveTime("2026-10-28T13:58:12.114231+0000")).toBe("2026-10-28T13:58:12.114Z");
    expect(eveTime("2026-10-28T16:58:12.114231+0300")).toBe("2026-10-28T13:58:12.114Z");
    expect(eveTime("2026-10-28T13:58:12Z")).toBe("2026-10-28T13:58:12.000Z");
    expect(eveTime("yesterday")).toBeNull();
    expect(eveTime(1_760_000_000)).toBeNull();
  });

  it("read an alert with its signature, endpoints and flow", () => {
    expect(readEvent(alertEvent())).toMatchObject({
      type: "alert",
      flowId: "1234567890123",
      srcIp: "192.0.2.17",
      destPort: 53,
      proto: "UDP",
      sid: 2027758,
      gid: 1,
      severity: "critical",
      action: "allowed",
    });
  });

  it("weigh alerts by ET's signature_severity, else by Suricata's severity", () => {
    expect(severityOf({ severity: 1, metadata: { signature_severity: ["Major"] } })).toBe("high");
    expect(severityOf({ severity: 3, metadata: { signature_severity: ["Informational"] } })).toBe("low");
    expect(severityOf({ severity: 1 })).toBe("high");
    expect(severityOf({ severity: 2 })).toBe("medium");
    expect(severityOf({ severity: 4 })).toBe("low");
  });

  it("read flows, protocol logs and counters", () => {
    expect(readEvent(flowEvent())).toMatchObject({ type: "flow", bytesToServer: 48_211_000, state: "established", alerted: true });
    expect(readEvent(dnsEvent())).toMatchObject({
      type: "record",
      kind: "dns",
      name: "aGVsbG8.d2b1.tunnel.example.com",
      detail: { rrtype: "TXT", rcode: "NOERROR" },
    });
    // Suricata 8 puts the question under queries.
    expect(readEvent(dnsEvent({ dns: { type: "request", id: 1, queries: [{ rrname: "example.com", rrtype: "A" }] } }))).toMatchObject({
      name: "example.com",
      detail: { type: "request", rrtype: "A" },
    });
    const tls = readEvent({
      ...dnsEvent(),
      event_type: "tls",
      tls: { sni: "cdn.example.com", version: "TLS 1.2", ja3: { hash: "72a589da586844d7f0818ce684948eea", string: "771,..." } },
    });
    expect(tls).toMatchObject({ kind: "tls", name: "cdn.example.com", detail: { ja3: "72a589da586844d7f0818ce684948eea", version: "TLS 1.2" } });
    expect(readEvent(statsEvent(T0, { uptime: 60, packets: 1000, drops: 10, bytes: 50_000 }))).toMatchObject({
      type: "stats",
      packets: 1000,
      drops: 10,
      rulesLoaded: 48_912,
      rulesFailed: 0,
    });
  });

  it("leave out other event types, and refuse what is not Suricata's form", () => {
    expect(readEvent({ ...dnsEvent(), event_type: "fileinfo" })).toBeNull();
    expect(readEvent("nope")).toMatch(/object/);
    expect(readEvent({ timestamp: "x", event_type: "alert" })).toMatch(/timestamp/);
    expect(readEvent(alertEvent({ src_ip: "not-an-ip" }))).toMatch(/addresses/);
    expect(readEvent(alertEvent({ alert: { signature: "no sid" } }))).toMatch(/signature_id/);
  });
});
