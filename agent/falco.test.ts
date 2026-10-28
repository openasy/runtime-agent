import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { createBuffer, createReceiver, INVENTORY_TAG, isLocal, parseAlerts, type Alert } from "./falco.ts";
import { mask } from "./mask.ts";

const alert = (over: Partial<Alert> = {}, fields: Record<string, string | number> = {}): Alert => ({
  time: "2026-10-28T12:58:12.418093117Z",
  rule: "Terminal shell in container",
  priority: "Notice",
  source: "syscall",
  tags: ["container", "shell"],
  output: "A shell was spawned (cmdline=sh -c id)",
  output_fields: { "proc.exepath": "/bin/sh", "proc.cmdline": "sh -c id", "proc.pname": "node", "user.name": "app", ...fields },
  ...over,
});

describe("secrets", () => {
  it("are masked in command lines before they leave the host", () => {
    expect(mask("mysql -u root -pS3cretPass db")).toBe("mysql -u root -p*** db");
    expect(mask("app --password hunter2 --port 80")).toBe("app --password *** --port 80");
    expect(mask("app --token=abc123def")).toBe("app --token=***");
    expect(mask("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x.y' https://api")).toContain("Authorization: Bearer ***");
    expect(mask("git clone https://ci:glpat-123456@gitlab.example.com/x.git")).toBe("git clone https://ci:***@gitlab.example.com/x.git");
    expect(mask("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")).toBe("export AWS_KEY=AKIA****************");
    expect(mask("ssh -p 2222 admin@db-1")).toBe("ssh -p 2222 admin@db-1");
  });
});

describe("Falco's alerts", () => {
  it("are read one per request, as a list, or one per line", () => {
    const one = JSON.stringify(alert());
    expect(parseAlerts(one)).toHaveLength(1);
    expect(parseAlerts(JSON.stringify([alert(), alert()]))).toHaveLength(2);
    expect(parseAlerts(`${one}\n${one}\nnot json`)).toHaveLength(2);
    expect(parseAlerts('{"hello":"world"}')).toEqual([]);
  });

  it("are masked and held until taken; a failed send puts them back first", () => {
    const b = createBuffer({ maxEvents: 3, maxStarts: 10 });
    b.add(alert({}, { "proc.cmdline": "mysql -pS3cret" }));
    b.add(alert({ rule: "Second" }));
    const t = b.take(1);
    expect(t.events[0]!.output_fields!["proc.cmdline"]).toBe("mysql -p***");
    b.add(alert({ rule: "Third" }));
    b.putBack(t);
    expect(b.take(10).events.map((e) => e.rule)).toEqual(["Terminal shell in container", "Second", "Third"]);
  });

  it("drop the oldest when the buffer is full, and count them", () => {
    const b = createBuffer({ maxEvents: 2, maxStarts: 10 });
    for (const r of ["a", "b", "c", "d"]) b.add(alert({ rule: r }));
    expect(b.dropped).toBe(2);
    expect(b.take(10).events.map((e) => e.rule)).toEqual(["c", "d"]);
  });

  it("count program starts by program, parent, user and container instead of keeping each", () => {
    const b = createBuffer({ maxEvents: 10, maxStarts: 2 });
    const start = (exe: string, time: string) =>
      alert({ rule: "OpenAsy process started", tags: [INVENTORY_TAG], time }, { "proc.exepath": exe, "proc.cmdline": `${exe} -x` });
    b.add(start("/usr/bin/python3", "2026-10-28T12:00:00Z"));
    b.add(start("/usr/bin/python3", "2026-10-28T12:05:00Z"));
    b.add(start("/bin/ls", "2026-10-28T12:01:00Z"));
    b.add(start("/bin/cat", "2026-10-28T12:02:00Z"));
    const t = b.take(10);
    expect(t.events).toEqual([]);
    expect(t.processes.find((p) => p.fields["proc.exepath"] === "/usr/bin/python3")).toMatchObject({
      count: 2,
      firstAt: "2026-10-28T12:00:00Z",
      lastAt: "2026-10-28T12:05:00Z",
    });
    expect(t.processes).toHaveLength(2);
    expect(b.dropped).toBe(1);
  });

  it("are taken only from this host", () => {
    expect(isLocal("127.0.0.1")).toBe(true);
    expect(isLocal("::ffff:127.0.0.1")).toBe(true);
    expect(isLocal("::1")).toBe(true);
    expect(isLocal("10.0.0.7")).toBe(false);
    expect(isLocal("::ffff:192.168.1.4")).toBe(false);
    expect(isLocal(undefined)).toBe(false);
  });

  it("are answered at once over HTTP, as Falco's http_output posts them", async () => {
    const b = createBuffer({ maxEvents: 10, maxStarts: 10 });
    const stats = { received: 0, badRequests: 0, lastAlertAt: null as string | null };
    const server = createServer(createReceiver(b, stats));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    expect((await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(alert()) })).status).toBe(200);
    expect((await fetch(url, { method: "POST", body: "nothing" })).status).toBe(400);
    expect((await fetch(url)).status).toBe(405);
    expect((await fetch(url, { method: "POST", body: "x".repeat(2 * 1024 * 1024) })).status).toBe(413);
    expect(stats).toMatchObject({ received: 1, badRequests: 1 });
    expect(b.size).toBe(1);
    await new Promise<void>((r) => server.close(() => r()));
  });
});
