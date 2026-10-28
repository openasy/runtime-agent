// The loop: send what Falco saw, read the watched files, and check that Falco answers. Runtime being down never
// stops the agent or slows Falco: alerts wait in the buffer, the agent says so in /readyz and keeps trying (ADR 0023).
import { enroll, RuntimeError, sendEvents, sendFiles, type Report } from "./client.ts";
import type { AlertBuffer } from "./falco.ts";
import type { createScanner } from "./fim.ts";
import { facts } from "./host.ts";
import type { Keyring } from "./kek.ts";
import { log } from "./log.ts";
import { saveState, type AgentState } from "./state.ts";

export interface AgentOptions {
  url: string;
  version: string;
  name: string;
  state: AgentState;
  statePath: string;
  keyring: Keyring;
  enrollToken?: string;
  buffer: AlertBuffer;
  scanner: ReturnType<typeof createScanner>;
  fimPaths: string[];
  /** Where the host's root is mounted, for its os-release. */
  root: string;
  /** Falco's web server, for /healthz and /versions; empty when it is not reachable from the agent. */
  falcoUrl: string;
  /** Alerts in one call. */
  batch?: number;
}

export interface Status {
  enrolled: boolean;
  /** Runtime refused the agent's secret: the host was removed. Nothing more is sent until it enrols again. */
  refused: boolean;
  runtimeOk: boolean;
  lastError: string | null;
  lastContactAt: string | null;
  falco: Report["falco"];
  /** Alerts Falco sent the agent, and requests that held none. */
  received: number;
  badRequests: number;
  sent: number;
  rejected: number;
  lastAlertAt: string | null;
  fimFiles: number;
  fimChanges: number;
  lastScanAt: string | null;
}

/** A report is sent at least this often, so Runtime knows the agent is there when Falco is quiet. */
const HEARTBEAT_MS = 30_000;

export function createAgent(o: AgentOptions) {
  const batch = o.batch ?? 2000;
  const status: Status = {
    enrolled: !!o.state.secret,
    refused: false,
    runtimeOk: false,
    lastError: null,
    lastContactAt: null,
    falco: { status: "unknown", version: null, detail: null },
    received: 0,
    badRequests: 0,
    sent: 0,
    rejected: 0,
    lastAlertAt: null,
    fimFiles: 0,
    fimChanges: 0,
    lastScanAt: null,
  };
  const host = facts(o.root);
  const report = (): Report => ({ version: o.version, ...host, falco: status.falco, fimPaths: o.fimPaths, dropped: o.buffer.dropped });

  const failed = (err: unknown) => {
    const e = err as RuntimeError;
    status.runtimeOk = false;
    status.lastError = e.message;
    if (e.status === 401 && status.enrolled) {
      status.refused = true;
      status.lastError =
        "Runtime refused this agent's secret: the host was removed there. Delete the agent's /data volume and start it with a new enrolment token.";
      log("error", "secret refused", { error: e.message });
    } else log("warn", "runtime call failed", { status: e.status, error: e.message });
  };
  const ok = () => {
    status.runtimeOk = true;
    status.lastError = null;
    status.lastContactAt = new Date().toISOString();
  };

  /** Enrols once with the token; afterwards the agent has its own secret, kept sealed in its state. */
  async function ensureEnrolled(): Promise<boolean> {
    if (status.refused) return false;
    if (o.state.secret) return true;
    if (!o.enrollToken) {
      status.lastError = "Not enrolled: make an enrolment token under Hosts in Runtime, and start the agent with RUNTIME_ENROLL_TOKEN";
      return false;
    }
    try {
      const r = await enroll(o.url, o.enrollToken, o.name, report());
      o.state.hostId = r.hostId;
      o.state.secret = r.secret;
      status.enrolled = true;
      try {
        saveState(o.statePath, o.keyring, o.state);
      } catch (err) {
        // The token is used now: the agent keeps working with the secret in memory, and says loudly that a restart
        // will lose it.
        log("error", "enrolled, but the secret could not be saved: after a restart the host must be removed in Runtime and enrolled again", {
          path: o.statePath,
          error: String(err),
        });
      }
      ok();
      log("info", "enrolled", { host: o.name, hostId: r.hostId });
      return true;
    } catch (err) {
      failed(err);
      return false;
    }
  }

  /** Sends what is waiting, a batch at a time, or only the report when it is time for one. */
  async function sendRound() {
    if (!(await ensureEnrolled())) return;
    do {
      const quiet = o.buffer.size === 0 && o.buffer.starts === 0;
      if (quiet && status.lastContactAt && Date.now() - Date.parse(status.lastContactAt) < HEARTBEAT_MS) return;
      const taken = o.buffer.take(batch);
      try {
        const r = await sendEvents(o.url, o.state.secret!, report(), taken.events, taken.processes);
        ok();
        status.sent += r.events.taken;
        status.rejected += r.events.refused.length + r.processes.refused.length;
        if (r.events.refused.length) log("warn", "runtime left out alerts", { refused: r.events.refused.length, first: r.events.refused[0] });
      } catch (err) {
        const e = err as RuntimeError;
        // A batch Runtime cannot read would be refused again and again; it is dropped and counted, never resent.
        if (e.status === 413 || e.status === 422) {
          status.rejected += taken.events.length;
          log("error", "runtime refused a batch; dropped", { status: e.status, error: e.message, events: taken.events.length });
        } else o.buffer.putBack(taken);
        failed(err);
        return;
      }
    } while (o.buffer.size > 0);
  }

  /** Reads the watched files and sends the read. */
  async function scanRound() {
    if (!(await ensureEnrolled())) return;
    const scan = await o.scanner.scan();
    if (scan.errors.length) log("warn", "watched paths not read", { errors: scan.errors.slice(0, 10), count: scan.errors.length });
    if (!scan.complete) log("warn", "watched files stop at FIM_MAX_FILES; files past it are not read", { files: scan.files.length });
    try {
      const r = await sendFiles(o.url, o.state.secret!, report(), { paths: o.fimPaths, files: scan.files, complete: scan.complete });
      ok();
      status.fimFiles = r.files;
      status.fimChanges += r.changes;
      status.lastScanAt = new Date().toISOString();
      if (r.changes) log("info", "watched files changed", { changes: r.changes });
    } catch (err) {
      failed(err);
    }
  }

  /** Asks Falco's web server whether it is up, and its version. */
  async function checkFalco() {
    if (!o.falcoUrl) return;
    try {
      const res = await fetch(new URL("/healthz", o.falcoUrl), { signal: AbortSignal.timeout(3000) });
      if (!res.ok) throw new Error(`Falco's /healthz answered ${res.status}`);
      const v = (await fetch(new URL("/versions", o.falcoUrl), { signal: AbortSignal.timeout(3000) })
        .then((r) => r.json())
        .catch(() => ({}))) as { falco_version?: unknown };
      status.falco = { status: "ok", version: typeof v.falco_version === "string" ? v.falco_version.slice(0, 64) : null, detail: null };
    } catch (err) {
      const was = status.falco.status;
      status.falco = {
        status: "down",
        version: status.falco.version,
        detail: `Falco does not answer at ${o.falcoUrl}: ${(err as Error).message}`.slice(0, 500),
      };
      if (was !== "down") log("warn", "falco does not answer", { url: o.falcoUrl, error: (err as Error).message });
    }
  }

  return { sendRound, scanRound, checkFalco, status };
}
