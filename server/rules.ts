// Local rules and suppressions in Suricata's own syntax (ADR 0070). Rules are checked here before they are kept, and
// network-ids-agent checks every line again before it writes it on a sensor: a rule can only describe traffic to
// alert on. Suricata itself is the last check; rules it cannot load show on the sensor as failed.
import { BlockList, isIP } from "node:net";

/** Local rules take SIDs from here up, out of the way of ET Open and Suricata's own. */
export const LOCAL_SID_MIN = 9_000_000;
export const LOCAL_SID_MAX = 9_999_999;
const MAX_RULE = 8 * 1024;

/**
 * Options that reach outside the rule: Lua scripts, and datasets and reputation lists that read and write files on
 * the sensor. A rule sent from here never names them.
 */
export const FORBIDDEN_OPTIONS = ["lua", "luajit", "dataset", "datarep"];
/** Detection only: rules alert, or pass traffic that should not be inspected. drop and reject would block it in IPS mode. */
const ACTIONS = ["alert", "pass"];
const PROTOCOL = /^[a-z][a-z0-9-]{0,15}$/;
const DIRECTIONS = ["->", "<>"];

export interface RuleOption {
  name: string;
  value: string | null;
}

export interface ParsedRule {
  action: string;
  protocol: string;
  source: string;
  sourcePort: string;
  direction: string;
  destination: string;
  destinationPort: string;
  options: RuleOption[];
  msg: string;
  sid: number;
  rev: number;
}

export class RuleError extends Error {}

/** Splits the header on spaces, keeping a bracketed list such as `[80, 443]` as one part. */
function headerParts(header: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let depth = 0;
  for (const ch of header) {
    if (ch === "[") depth++;
    if (ch === "]") depth--;
    if (depth < 0) throw new RuleError("The header has a ] without its [.");
    if (/\s/.test(ch) && depth === 0) {
      if (cur) parts.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (depth !== 0) throw new RuleError("The header has a [ without its ].");
  if (cur) parts.push(cur);
  return parts;
}

/** `name;` or `name:value;`, with quoted values that may hold an escaped quote or semicolon. */
function parseOptions(body: string): RuleOption[] {
  const options: RuleOption[] = [];
  let i = 0;
  while (i < body.length) {
    while (i < body.length && /\s/.test(body[i]!)) i++;
    if (i >= body.length) break;
    let name = "";
    while (i < body.length && /[A-Za-z0-9_.-]/.test(body[i]!)) name += body[i++];
    if (!name) throw new RuleError(`Expected an option name at "${body.slice(i, i + 20)}".`);
    while (i < body.length && body[i] === " ") i++;
    if (body[i] === ";") {
      options.push({ name: name.toLowerCase(), value: null });
      i++;
      continue;
    }
    if (body[i] !== ":") throw new RuleError(`The option ${name} needs a ; after it.`);
    i++;
    let value = "";
    let quoted = false;
    for (; i < body.length; i++) {
      const ch = body[i]!;
      if (ch === "\\" && i + 1 < body.length) {
        value += ch + body[++i];
        continue;
      }
      if (ch === '"') quoted = !quoted;
      if (ch === ";" && !quoted) break;
      value += ch;
    }
    if (quoted) throw new RuleError(`The value of ${name} has a quote that is not closed.`);
    if (body[i] !== ";") throw new RuleError(`The option ${name} needs a ; after its value.`);
    i++;
    options.push({ name: name.toLowerCase(), value: value.trim() });
  }
  return options;
}

const unquote = (v: string) => (v.startsWith('"') && v.endsWith('"') && v.length >= 2 ? v.slice(1, -1) : v);

/** Reads one rule, or throws RuleError saying what is wrong with it. */
export function parseRule(text: string): ParsedRule {
  const rule = text.trim();
  if (!rule) throw new RuleError("The rule is empty.");
  if (rule.length > MAX_RULE) throw new RuleError(`A rule is at most ${MAX_RULE} characters.`);
  // eslint-disable-next-line no-control-regex
  if (/[\r\n\u0000-\u0008\u000b-\u001f\u007f]/.test(rule)) throw new RuleError("A rule is one line, without control characters.");
  const open = rule.indexOf("(");
  if (open < 0 || !rule.endsWith(")")) throw new RuleError("A rule is a header, then its options in parentheses: alert tcp any any -> any any (...)");
  const parts = headerParts(rule.slice(0, open));
  if (parts.length !== 7)
    throw new RuleError("The header is: action protocol source port direction destination port, such as alert tcp $HOME_NET any -> $EXTERNAL_NET 22.");
  const [action, protocol, source, sourcePort, direction, destination, destinationPort] = parts as [string, string, string, string, string, string, string];
  if (!ACTIONS.includes(action))
    throw new RuleError(
      action === "drop" || action === "reject" || action.startsWith("reject")
        ? "Network IDS detects and does not block: use alert, or pass for traffic not to inspect."
        : "The action is alert or pass.",
    );
  if (!PROTOCOL.test(protocol)) throw new RuleError("The protocol is a name such as tcp, udp, dns, http or tls.");
  if (!DIRECTIONS.includes(direction)) throw new RuleError("The direction is -> or <>.");
  const options = parseOptions(rule.slice(open + 1, -1));
  const forbidden = options.find((o) => FORBIDDEN_OPTIONS.includes(o.name));
  if (forbidden) throw new RuleError(`The option ${forbidden.name} reads or writes files on the sensor, and is not sent from here.`);
  const one = (name: string) => {
    const found = options.filter((o) => o.name === name);
    if (found.length > 1) throw new RuleError(`The option ${name} is given twice.`);
    return found[0];
  };
  const msg = one("msg");
  if (!msg?.value || !/^".*"$/.test(msg.value)) throw new RuleError('A rule needs a msg in quotes: msg:"LOCAL ...";');
  const sid = one("sid");
  if (!sid?.value || !/^\d+$/.test(sid.value)) throw new RuleError("A rule needs a sid: sid:9000001;");
  const sidNumber = Number(sid.value);
  if (sidNumber < LOCAL_SID_MIN || sidNumber > LOCAL_SID_MAX)
    throw new RuleError(`Local rules take SIDs from ${LOCAL_SID_MIN} to ${LOCAL_SID_MAX}, out of the way of ET Open and Suricata's own.`);
  const gid = one("gid");
  if (gid && gid.value !== "1") throw new RuleError("Local rules use gid 1, Suricata's default; leave gid out.");
  const rev = one("rev");
  if (rev && (!rev.value || !/^\d{1,9}$/.test(rev.value))) throw new RuleError("rev is a whole number: rev:1;");
  return {
    action,
    protocol,
    source,
    sourcePort,
    direction,
    destination,
    destinationPort,
    options,
    msg: unquote(msg.value),
    sid: sidNumber,
    rev: rev ? Number(rev.value) : 1,
  };
}

/** An address or a network in CIDR form, or null when it is neither. */
export function parseNetwork(value: string): { address: string; prefix: number; type: "ipv4" | "ipv6" } | null {
  const [address = "", prefixText, extra] = value.trim().split("/");
  if (extra !== undefined) return null;
  const v = isIP(address);
  if (!v) return null;
  const max = v === 4 ? 32 : 128;
  if (prefixText !== undefined && !/^\d{1,3}$/.test(prefixText)) return null;
  const prefix = prefixText === undefined ? max : Number(prefixText);
  if (prefix > max || prefix < 1) return null;
  return { address, prefix, type: v === 4 ? "ipv4" : "ipv6" };
}

/** Whether ip lies in network (an address or a CIDR). */
export function inNetwork(ip: string, network: string): boolean {
  const n = parseNetwork(network);
  const v = isIP(ip);
  if (!n || !v) return false;
  const list = new BlockList();
  list.addSubnet(n.address, n.prefix, n.type);
  return list.check(ip, v === 4 ? "ipv4" : "ipv6");
}

export interface SuppressionLine {
  gid: number;
  sid: number;
  track: "by_src" | "by_dst" | null;
  network: string | null;
}

/** Suricata's threshold.config line for a suppression. */
export function suppressLine(s: SuppressionLine): string {
  return `suppress gen_id ${s.gid}, sig_id ${s.sid}${s.track && s.network ? `, track ${s.track}, ip ${s.network}` : ""}`;
}
