import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { createAgent } from "./agent.ts";
import { createAgentHandler } from "./app.ts";
import { createBuffer, type Alert } from "./falco.ts";
import { createScanner } from "./fim.ts";
import { createKeyring } from "./kek.ts";
import { loadState } from "./state.ts";

/** A stand-in for Runtime's agent API that keeps what it is sent and answers as Runtime does. */
async function fakeRuntime(opts: { refuse?: number } = {}) {
  const calls: Array<{ path: string; auth: string | undefined; body: any }> = [];
  let status = opts.refuse ?? 200;
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = JSON.parse(gunzipSync(Buffer.concat(chunks)).toString("utf8"));
    calls.push({ path: req.url!, auth: req.headers.authorization, body });
    const answer =
      status !== 200
        ? { code: "invalid-token", detail: "nope" }
        : req.url === "/api/v1/agent/enroll"
          ? { hostId: "h1", secret: "oia_secret" }
          : req.url === "/api/v1/agent/files"
            ? { files: body.files.length, changes: 0, baseline: true }
            : { events: { taken: body.events.length, refused: [] }, processes: { taken: body.processes.length, refused: [] } };
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(answer));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    calls,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    set: (s: number) => (status = s),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

const keyring = createKeyring(Buffer.alloc(32, 7));
let runtime: Awaited<ReturnType<typeof fakeRuntime>> | undefined;
afterEach(async () => {
  await runtime?.close();
  runtime = undefined;
});

function setup(url: string, enrollToken?: string) {
  const dir = mkdtempSync(join(tmpdir(), "runtime-agent-"));
  const root = join(dir, "host");
  mkdirSync(join(root, "etc"), { recursive: true });
  writeFileSync(join(root, "etc/os-release"), 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n');
  writeFileSync(join(root, "etc/passwd"), "root:x:0:0::/root:/bin/sh\n");
  const statePath = join(dir, "data/agent.state");
  const buffer = createBuffer({ maxEvents: 100, maxStarts: 100 });
  const agent = createAgent({
    url,
    version: "0.1.0",
    name: "worker-prod-04",
    state: loadState(statePath, keyring),
    statePath,
    keyring,
    enrollToken,
    buffer,
    scanner: createScanner({ root, paths: ["/etc/passwd"], maxFiles: 10, maxHashBytes: 1 << 20, maxDepth: 2 }),
    fimPaths: ["/etc/passwd"],
    root,
    falcoUrl: "",
    batch: 2,
  });
  return { agent, buffer, statePath };
}

const alert = (rule: string): Alert => ({ time: "2026-10-28T12:58:12Z", rule, priority: "Notice", output: "x", output_fields: {} });

describe("a round", () => {
  it("enrols once, keeps the secret sealed, and sends alerts in batches with the report", async () => {
    runtime = await fakeRuntime();
    const { agent, buffer, statePath } = setup(runtime.url, "oie_token");
    for (const r of ["a", "b", "c"]) buffer.add(alert(r));
    await agent.sendRound();
    expect(runtime.calls.map((c) => c.path)).toEqual(["/api/v1/agent/enroll", "/api/v1/agent/events", "/api/v1/agent/events"]);
    expect(runtime.calls[0]!.body).toMatchObject({ token: "oie_token", name: "worker-prod-04", report: { version: "0.1.0", os: "Ubuntu 24.04.1 LTS" } });
    expect(runtime.calls[1]!.auth).toBe("Bearer oia_secret");
    expect(runtime.calls[1]!.body.events.map((e: Alert) => e.rule)).toEqual(["a", "b"]);
    expect(runtime.calls[2]!.body.events.map((e: Alert) => e.rule)).toEqual(["c"]);
    expect(readFileSync(statePath, "utf8")).not.toContain("oia_secret");
    expect(loadState(statePath, keyring)).toEqual({ hostId: "h1", secret: "oia_secret" });
    expect(agent.status).toMatchObject({ enrolled: true, runtimeOk: true, sent: 3 });

    // Quiet, and reported a moment ago: nothing to send.
    await agent.sendRound();
    expect(runtime.calls).toHaveLength(3);
  });

  it("reads the watched files and sends them", async () => {
    runtime = await fakeRuntime();
    const { agent } = setup(runtime.url, "oie_token");
    await agent.scanRound();
    const files = runtime.calls.find((c) => c.path === "/api/v1/agent/files")!.body;
    expect(files).toMatchObject({ paths: ["/etc/passwd"], complete: true, files: [{ path: "/etc/passwd", kind: "file" }] });
    expect(agent.status.fimFiles).toBe(1);
  });

  it("keeps alerts while Runtime is down, and sends them when it is back", async () => {
    runtime = await fakeRuntime();
    const { agent, buffer } = setup(runtime.url, "oie_token");
    await agent.sendRound();
    runtime.set(503);
    buffer.add(alert("kept"));
    await agent.sendRound();
    expect(buffer.size).toBe(1);
    expect(agent.status.runtimeOk).toBe(false);
    const res = { writeHead: () => res, end: (b: string) => (res.body = b), body: "" } as any;
    createAgentHandler("0.1.0", agent.status, buffer)({ url: "/readyz" } as any, res);
    expect(JSON.parse(res.body)).toMatchObject({ status: "degraded" });
    runtime.set(200);
    await agent.sendRound();
    expect(buffer.size).toBe(0);
    expect(runtime.calls.at(-1)!.body.events[0].rule).toBe("kept");
  });

  it("stops when Runtime refuses its secret, and never enrols again by itself", async () => {
    runtime = await fakeRuntime();
    const { agent, buffer } = setup(runtime.url, "oie_token");
    await agent.sendRound();
    runtime.set(401);
    buffer.add(alert("x"));
    await agent.sendRound();
    expect(agent.status).toMatchObject({ refused: true, lastError: expect.stringMatching(/removed/) });
    const n = runtime.calls.length;
    runtime.set(200);
    await agent.sendRound();
    await agent.scanRound();
    expect(runtime.calls).toHaveLength(n);
  });

  it("does nothing without a token, and says so", async () => {
    runtime = await fakeRuntime();
    const { agent } = setup(runtime.url);
    await agent.sendRound();
    expect(runtime.calls).toEqual([]);
    expect(agent.status.lastError).toMatch(/RUNTIME_ENROLL_TOKEN/);
  });
});
