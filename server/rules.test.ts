import { describe, expect, it } from "vitest";
import { inNetwork, parseNetwork, parseRule, suppressLine } from "./rules.ts";

const rule = (options: string, header = "alert dns $HOME_NET any -> any any") => `${header} (${options})`;

describe("local rules", () => {
  it("are read with their msg, sid and rev, quoted values holding ; and escaped quotes", () => {
    const r = parseRule(rule('msg:"LOCAL Long DNS; TXT \\"label\\""; dns.query; pcre:"/^[A-Za-z0-9]{40,}\\./"; sid:9000102; rev:2;'));
    expect(r).toMatchObject({ action: "alert", protocol: "dns", msg: 'LOCAL Long DNS; TXT \\"label\\"', sid: 9_000_102, rev: 2 });
    expect(r.options.map((o) => o.name)).toEqual(["msg", "dns.query", "pcre", "sid", "rev"]);
  });

  it("keep bracketed address and port lists in the header", () => {
    const r = parseRule(rule('msg:"LOCAL DB out"; sid:9000103;', "alert tcp [192.0.2.60, 192.0.2.61] [5432,3306] -> !$HOME_NET any"));
    expect(r).toMatchObject({ source: "[192.0.2.60, 192.0.2.61]", sourcePort: "[5432,3306]", destination: "!$HOME_NET", rev: 1 });
  });

  it("only alert or pass: Network IDS does not block", () => {
    expect(() => parseRule(rule('msg:"x"; sid:9000001;', "drop tcp any any -> any any"))).toThrow(/detects and does not block/);
    expect(() => parseRule(rule('msg:"x"; sid:9000001;', "pass tcp any any -> any any"))).not.toThrow();
  });

  it("never name Lua scripts, datasets or reputation files", () => {
    for (const o of ["lua:/etc/x.lua;", "luajit:x.lua;", "dataset:set,bad,type string,save /etc/passwd;", "datarep:x,>,10;"])
      expect(() => parseRule(rule(`msg:"x"; ${o} sid:9000001;`))).toThrow(/files on the sensor/);
  });

  it("need a msg in quotes and a sid in the local range, once each", () => {
    expect(() => parseRule(rule("sid:9000001;"))).toThrow(/msg/);
    expect(() => parseRule(rule("msg:x; sid:9000001;"))).toThrow(/msg/);
    expect(() => parseRule(rule('msg:"x";'))).toThrow(/sid/);
    expect(() => parseRule(rule('msg:"x"; sid:2027758;'))).toThrow(/9000000/);
    expect(() => parseRule(rule('msg:"x"; sid:9000001; sid:9000002;'))).toThrow(/twice/);
    expect(() => parseRule(rule('msg:"x"; sid:9000001; gid:3;'))).toThrow(/gid 1/);
  });

  it("are one well-formed line", () => {
    expect(() => parseRule("")).toThrow(/empty/);
    expect(() => parseRule(`${rule('msg:"x"; sid:9000001;')}\nalert ip any any -> any any (sid:1;)`)).toThrow(/one line/);
    expect(() => parseRule('alert tcp any any -> any any msg:"x"; sid:9000001;')).toThrow(/parentheses/);
    expect(() => parseRule(rule('msg:"x"; sid:9000001;', "alert tcp any any any any"))).toThrow(/header/);
    expect(() => parseRule(rule('msg:"x"; sid:9000001;', "alert tcp any any => any any"))).toThrow(/direction/);
    expect(() => parseRule(rule('msg:"x; sid:9000001;'))).toThrow(/not closed/);
    expect(() => parseRule(rule('msg:"x" sid:9000001;'))).toThrow();
  });
});

describe("networks and suppressions", () => {
  it("read addresses and CIDR networks of both families", () => {
    expect(parseNetwork("192.0.2.9")).toEqual({ address: "192.0.2.9", prefix: 32, type: "ipv4" });
    expect(parseNetwork("2001:db8::/32")).toEqual({ address: "2001:db8::", prefix: 32, type: "ipv6" });
    for (const bad of ["192.0.2.9/33", "example.com", "10.0.0.0/8/1", "10.0.0.0/x", "10.0.0.0/0"]) expect(parseNetwork(bad)).toBeNull();
    expect(inNetwork("10.1.2.3", "10.0.0.0/8")).toBe(true);
    expect(inNetwork("11.1.2.3", "10.0.0.0/8")).toBe(false);
    expect(inNetwork("2001:db8::1", "2001:db8::/32")).toBe(true);
    expect(inNetwork("10.1.2.3", "2001:db8::/32")).toBe(false);
  });

  it("are written as Suricata's suppress lines", () => {
    expect(suppressLine({ gid: 1, sid: 2013028, track: "by_src", network: "192.0.2.9" })).toBe("suppress gen_id 1, sig_id 2013028, track by_src, ip 192.0.2.9");
    expect(suppressLine({ gid: 1, sid: 2221010, track: null, network: null })).toBe("suppress gen_id 1, sig_id 2221010");
  });
});
