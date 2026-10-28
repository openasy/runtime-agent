import type { IncomingMessage, ServerResponse } from "node:http";
import type { Status } from "./agent.ts";
import type { AlertBuffer } from "./falco.ts";

function send(res: ServerResponse, status: number, body: string, type = "application/json") {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body), "x-content-type-options": "nosniff" });
  res.end(body);
}

/** Health and metrics for the agent (ADR 0017). The agent has no API of its own. */
export function createAgentHandler(version: string, s: Status, buffer: AlertBuffer) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    if (path === "/healthz") return send(res, 200, JSON.stringify({ status: "ok" }));
    if (path === "/readyz") {
      const problems = [
        !s.enrolled && "not enrolled",
        s.refused && "secret refused",
        !s.runtimeOk && `runtime unreachable${s.lastError ? `: ${s.lastError}` : ""}`,
        s.falco.status === "down" && (s.falco.detail ?? "falco down"),
      ].filter(Boolean);
      return send(res, problems.length ? 503 : 200, JSON.stringify(problems.length ? { status: "degraded", problems } : { status: "ready" }));
    }
    if (path === "/metrics") {
      const lines = [
        "# HELP openasy_build_info Build information.",
        "# TYPE openasy_build_info gauge",
        `openasy_build_info{product="runtime-agent",version="${version}"} 1`,
        "# HELP openasy_runtime_agent_alerts_received_total Alerts Falco sent the agent.",
        "# TYPE openasy_runtime_agent_alerts_received_total counter",
        `openasy_runtime_agent_alerts_received_total ${s.received}`,
        "# HELP openasy_runtime_agent_alerts_sent_total Alerts Runtime took.",
        "# TYPE openasy_runtime_agent_alerts_sent_total counter",
        `openasy_runtime_agent_alerts_sent_total ${s.sent}`,
        "# HELP openasy_runtime_agent_alerts_dropped_total Alerts and program starts the buffer could not hold while Runtime was out of reach.",
        "# TYPE openasy_runtime_agent_alerts_dropped_total counter",
        `openasy_runtime_agent_alerts_dropped_total ${buffer.dropped}`,
        "# HELP openasy_runtime_agent_buffered Alerts waiting for Runtime.",
        "# TYPE openasy_runtime_agent_buffered gauge",
        `openasy_runtime_agent_buffered ${buffer.size}`,
        "# HELP openasy_runtime_agent_falco_up 1 when Falco's web server answers.",
        "# TYPE openasy_runtime_agent_falco_up gauge",
        `openasy_runtime_agent_falco_up ${s.falco.status === "ok" ? 1 : 0}`,
        "# HELP openasy_runtime_agent_watched_files Files read in the last read of the watched paths.",
        "# TYPE openasy_runtime_agent_watched_files gauge",
        `openasy_runtime_agent_watched_files ${s.fimFiles}`,
        "# HELP openasy_runtime_agent_last_contact_timestamp_seconds Last successful call to Runtime; 0 before the first.",
        "# TYPE openasy_runtime_agent_last_contact_timestamp_seconds gauge",
        `openasy_runtime_agent_last_contact_timestamp_seconds ${s.lastContactAt ? Math.floor(Date.parse(s.lastContactAt) / 1000) : 0}`,
      ];
      return send(res, 200, lines.join("\n") + "\n", "text/plain; version=0.0.4");
    }
    send(res, 404, JSON.stringify({ status: "not found" }));
  };
}
