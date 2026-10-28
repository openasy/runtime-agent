// What Falco sends: its http_output posts each alert, as json_output writes it, to the agent on 127.0.0.1 (ADR
// 0066). The agent takes Falcosidekick's place and listens where it would, on port 2801. Alerts are masked, held in a
// buffer of fixed size until Runtime takes them, and the starts of "OpenAsy process started" are counted instead of
// kept one by one.
import type { IncomingMessage, ServerResponse } from "node:http";
import { isIP } from "node:net";
import { mask } from "./mask.ts";

/** The tag of runtime-agent's Falco rule that sees every program start (falco/openasy_rules.yaml). */
export const INVENTORY_TAG = "openasy_inventory";
/** Largest request from Falco: one alert is a few KiB; Falcosidekick-style batches stay well under this. */
const BODY_LIMIT = 1024 * 1024;

type Value = string | number | boolean | null;
export interface Alert {
  time: string;
  rule: string;
  priority: string;
  source?: string;
  tags?: string[];
  output?: string;
  output_fields?: Record<string, Value>;
  hostname?: string;
}

export interface Start {
  fields: Record<string, Value>;
  count: number;
  firstAt: string;
  lastAt: string;
}

/** Masks every text value, so no command line, path or output carries a secret off the host. */
export function scrub(a: Alert): Alert {
  const fields: Record<string, Value> = {};
  for (const [k, v] of Object.entries(a.output_fields ?? {})) fields[k] = typeof v === "string" ? mask(v) : v;
  return { ...a, ...(a.output !== undefined && { output: mask(a.output) }), output_fields: fields };
}

/** The alerts waiting for Runtime, and the program starts counted since the last send. Both have a fixed size. */
export function createBuffer(o: { maxEvents: number; maxStarts: number }) {
  let events: Alert[] = [];
  let starts = new Map<string, Start>();
  let dropped = 0;

  const startKey = (f: Record<string, Value>) =>
    [f["proc.exepath"] ?? f["proc.name"], f["proc.pname"], f["user.name"], f["container.image.repository"], f["container.image.tag"], f["container.id"]].join(
      "\u0000",
    );

  /** Counts a program start into the one before it with the same program, parent, user and container. */
  function count(s: Start) {
    const key = startKey(s.fields);
    const had = starts.get(key);
    if (had) {
      had.count += s.count;
      if (s.firstAt < had.firstAt) had.firstAt = s.firstAt;
      if (s.lastAt >= had.lastAt) {
        had.lastAt = s.lastAt;
        had.fields = s.fields;
      }
      return;
    }
    if (starts.size >= o.maxStarts) return void dropped++;
    starts.set(key, { ...s });
  }

  return {
    add(raw: Alert) {
      const a = scrub(raw);
      if (a.tags?.includes(INVENTORY_TAG)) return count({ fields: a.output_fields ?? {}, count: 1, firstAt: a.time, lastAt: a.time });
      events.push(a);
      // The oldest go first when Runtime has been out of reach for long; the report says how many.
      if (events.length > o.maxEvents) dropped += events.splice(0, events.length - o.maxEvents).length;
    },
    /** Takes up to n alerts and every counted start, for one call to Runtime. */
    take(n: number) {
      const taken = { events: events.slice(0, n), processes: [...starts.values()] };
      events = events.slice(n);
      starts = new Map();
      return taken;
    },
    /** Puts back what a failed call took, ahead of what came since. */
    putBack(t: { events: Alert[]; processes: Start[] }) {
      events = [...t.events, ...events];
      if (events.length > o.maxEvents) dropped += events.splice(0, events.length - o.maxEvents).length;
      for (const s of t.processes) count(s);
    },
    get size() {
      return events.length;
    },
    get starts() {
      return starts.size;
    },
    get dropped() {
      return dropped;
    },
  };
}

export type AlertBuffer = ReturnType<typeof createBuffer>;

const isAlert = (v: unknown): v is Alert => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const a = v as Record<string, unknown>;
  return typeof a.rule === "string" && typeof a.priority === "string" && typeof a.time === "string";
};

/** Only this host may send: Falco on the same host, or in the same pod. */
export function isLocal(address: string | undefined) {
  if (!address) return false;
  const a = address.startsWith("::ffff:") ? address.slice(7) : address;
  return a === "::1" || (isIP(a) === 4 && a.startsWith("127."));
}

/** Parses one request from Falco: one alert, a list of them, or one per line. */
export function parseAlerts(text: string): Alert[] {
  const t = text.trim();
  if (!t) return [];
  try {
    const v = JSON.parse(t) as unknown;
    return (Array.isArray(v) ? v : [v]).filter(isAlert);
  } catch {
    return t
      .split("\n")
      .map((line) => {
        try {
          return JSON.parse(line) as unknown;
        } catch {
          return undefined;
        }
      })
      .filter(isAlert);
  }
}

/** The handler Falco's http_output posts to. It answers at once; Runtime being down never slows Falco. */
export function createReceiver(buffer: AlertBuffer, stats: { received: number; badRequests: number; lastAlertAt: string | null }) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const done = (status: number) => {
      res.writeHead(status, { "content-length": 0 }).end();
      if (!req.complete) req.resume();
    };
    if (!isLocal(req.socket.remoteAddress)) return done(403);
    if (req.method !== "POST") return done(405);
    const chunks: Buffer[] = [];
    let size = 0;
    // Past the limit the rest is read and dropped, so Falco hears 413 rather than a reset connection.
    for await (const c of req as AsyncIterable<Buffer>) {
      size += c.length;
      if (size <= BODY_LIMIT) chunks.push(c);
    }
    if (size > BODY_LIMIT) return done(413);
    const alerts = parseAlerts(Buffer.concat(chunks).toString("utf8"));
    if (!alerts.length) {
      stats.badRequests++;
      return done(400);
    }
    for (const a of alerts) buffer.add(a);
    stats.received += alerts.length;
    stats.lastAlertAt = new Date().toISOString();
    done(200);
  };
}
