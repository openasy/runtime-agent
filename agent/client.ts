// Everything the agent sends goes to the Runtime API, and only that way (ADR 0023): Runtime never calls the agent
// and never sends it anything to run. Each call carries the agent's report of itself and is answered with what was taken.
import { gzipSync } from "node:zlib";
import type { Alert, Start } from "./falco.ts";
import type { FileState } from "./fim.ts";

export interface Report {
  version: string;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  falco: { status: "ok" | "down" | "unknown"; version: string | null; detail: string | null };
  fimPaths?: string[];
  dropped: number;
}

export class RuntimeError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(status: number | undefined, code: string | undefined, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call<T>(url: string, path: string, init: { secret?: string; body: unknown; timeoutMs?: number }): Promise<T> {
  let res: Response;
  try {
    res = await fetch(new URL(path, url), {
      method: "POST",
      headers: { ...(init.secret && { authorization: `Bearer ${init.secret}` }), "content-type": "application/json", "content-encoding": "gzip" },
      body: gzipSync(JSON.stringify(init.body)),
      signal: AbortSignal.timeout(init.timeoutMs ?? 30_000),
    });
  } catch (err) {
    throw new RuntimeError(undefined, "unreachable", `runtime at ${url} is unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string; title?: string };
    throw new RuntimeError(res.status, p.code, p.detail ?? p.title ?? `${res.status}`);
  }
  return (await res.json()) as T;
}

type Taken = { taken: number; refused: Array<{ index: number; detail: string }> };

export const enroll = (url: string, token: string, name: string, report: Report) =>
  call<{ hostId: string; secret: string }>(url, "/api/v1/agent/enroll", { body: { token, name, report } });
export const sendEvents = (url: string, secret: string, report: Report, events: Alert[], processes: Start[]) =>
  call<{ events: Taken; processes: Taken }>(url, "/api/v1/agent/events", { secret, body: { report, events, processes } });
export const sendFiles = (url: string, secret: string, report: Report, scan: { paths: string[]; files: FileState[]; complete: boolean }) =>
  call<{ files: number; changes: number; baseline: boolean }>(url, "/api/v1/agent/files", { secret, body: { report, ...scan }, timeoutMs: 120_000 });
