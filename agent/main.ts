import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAgent } from "./agent.ts";
import { createAgentHandler } from "./app.ts";
import { createBuffer, createReceiver } from "./falco.ts";
import { createScanner, parsePaths } from "./fim.ts";
import { hostName } from "./host.ts";
import { createKeyring } from "./kek.ts";
import { log } from "./log.ts";
import { loadState } from "./state.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const env = process.env;
const url = env.RUNTIME_URL;
if (!url) {
  log("error", "RUNTIME_URL is required: the address of runtime, such as https://runtime.example.com");
  process.exit(1);
}
if (!url.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1|[a-z0-9-]+)(:\d+)?(\/|$)/.test(url))
  // Plain http only to a name in the same compose network or this host; across a network the secret needs TLS (ADR 0026).
  log("warn", "RUNTIME_URL is not https: the agent's secret and Falco's alerts cross the network in clear", { url });
const keyFile = env.RUNTIME_AGENT_SECRETS_KEY_FILE ?? "/run/secrets/openasy-agent-kek";
let kek: Buffer;
try {
  const text = readFileSync(keyFile, "utf8").trim();
  kek = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, "hex") : Buffer.from(text, "base64");
  if (kek.length !== 32) throw new Error("not 32 bytes");
} catch (err) {
  // The agent's secret speaks for its host: it is never kept in the clear (ADR 0021).
  log("error", "no key-encryption key: mount 32 random bytes (openssl rand -hex 32)", { file: keyFile, error: String(err) });
  process.exit(1);
}
const keyring = createKeyring(kek);
const statePath = env.RUNTIME_AGENT_STATE ?? "/data/agent.state";
const root = env.HOST_ROOT ?? "/host";
const number = (name: string, fallback: number, min: number, max: number) => {
  const v = Number(env[name] ?? fallback);
  if (!Number.isFinite(v) || v < min || v > max) throw new Error(`${name} must be a number from ${min} to ${max}`);
  return v;
};
const fimPaths = parsePaths(env.FIM_PATHS);
const fimMinutes = number("FIM_MINUTES", 5, 1, 1440);
const buffer = createBuffer({ maxEvents: number("BUFFER_EVENTS", 20_000, 100, 1_000_000), maxStarts: 5000 });
const scanner = createScanner({
  root,
  paths: fimPaths,
  maxFiles: number("FIM_MAX_FILES", 20_000, 1, 50_000),
  maxHashBytes: number("FIM_MAX_MB", 64, 1, 4096) * 1024 * 1024,
  maxDepth: 4,
});
const name = hostName(root, env);
const agent = createAgent({
  url,
  version,
  name,
  state: loadState(statePath, keyring),
  statePath,
  keyring,
  enrollToken: env.RUNTIME_ENROLL_TOKEN || undefined,
  buffer,
  scanner,
  fimPaths,
  root,
  falcoUrl: env.FALCO_WEBSERVER_URL ?? "http://127.0.0.1:8765",
});

// Falco's http_output posts here. Only this host is let in: the address is the loopback one by default.
const [falcoHost, falcoPort] = (env.FALCO_LISTEN ?? "127.0.0.1:2801").split(/:(?=\d+$)/);
const receiver = createServer(createReceiver(buffer, agent.status));
receiver.listen(Number(falcoPort), falcoHost, () => log("info", "listening for Falco", { address: `${falcoHost}:${falcoPort}` }));
const [healthHost, healthPort] = (env.HEALTH_LISTEN ?? "127.0.0.1:2802").split(/:(?=\d+$)/);
const health = createServer(createAgentHandler(version, agent.status, buffer));
health.listen(Number(healthPort), healthHost, () =>
  log("info", "runtime-agent started", {
    version,
    host: name,
    runtime: url,
    enrolled: agent.status.enrolled,
    health: `${healthHost}:${healthPort}`,
    fimPaths: fimPaths.length,
  }),
);

// One of each at a time: a slow Runtime never has two sends of the same alerts in flight.
const once = (fn: () => Promise<void>, what: string) => {
  let busy = false;
  return () => {
    if (busy) return;
    busy = true;
    fn()
      .catch((err: unknown) => log("error", `${what} failed`, { error: String(err) }))
      .finally(() => (busy = false));
  };
};
const send = once(agent.sendRound, "send");
const scan = once(agent.scanRound, "file read");
const falco = once(agent.checkFalco, "falco check");
falco();
setTimeout(send, 1000);
setTimeout(scan, 5000);
const timers = [setInterval(send, number("SEND_SECONDS", 5, 1, 300) * 1000), setInterval(scan, fimMinutes * 60_000), setInterval(falco, 30_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  receiver.close();
  setTimeout(() => process.exit(1), 10_000).unref();
  // What is buffered is sent once more before the agent goes.
  void agent.sendRound().finally(() => health.close(() => process.exit(0)));
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
