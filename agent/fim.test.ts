import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createScanner, DEFAULT_PATHS, parsePaths } from "./fim.ts";

/** A host's root with a few watched files, a link out of it and a link above a watched path. */
function host() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "runtime-agent-host-")));
  mkdirSync(join(root, "etc/ssh/sshd_config.d"), { recursive: true });
  mkdirSync(join(root, "usr/bin"), { recursive: true });
  writeFileSync(join(root, "etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n");
  writeFileSync(join(root, "etc/ssh/sshd_config"), "PermitRootLogin no\n");
  writeFileSync(join(root, "etc/ssh/sshd_config.d/50-cloud.conf"), "PasswordAuthentication no\n");
  writeFileSync(join(root, "usr/bin/big"), Buffer.alloc(2048));
  symlinkSync("/etc/shadow", join(root, "usr/bin/escape"));
  symlinkSync("usr/bin", join(root, "bin"));
  return root;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

describe("the watched files", () => {
  it("are read under the host's root with their hash, mode and owner; links by their target, never followed", async () => {
    const root = host();
    const s = createScanner({ root, paths: ["/etc/passwd", "/etc/ssh", "/usr/bin", "/bin", "/etc/missing"], maxFiles: 100, maxHashBytes: 1024, maxDepth: 4 });
    const r = await s.scan();
    expect(r.complete).toBe(true);
    const by = Object.fromEntries(r.files.map((f) => [f.path, f]));
    expect(Object.keys(by).sort()).toEqual([
      "/bin",
      "/etc/passwd",
      "/etc/ssh/sshd_config",
      "/etc/ssh/sshd_config.d/50-cloud.conf",
      "/usr/bin/big",
      "/usr/bin/escape",
    ]);
    expect(by["/etc/passwd"]).toMatchObject({ kind: "file", sha256: sha("root:x:0:0:root:/root:/bin/bash\n"), mode: "0644" });
    expect(by["/usr/bin/escape"]).toMatchObject({ kind: "link", target: "/etc/shadow", sha256: null });
    expect(by["/bin"]).toMatchObject({ kind: "link", target: "usr/bin" });
    // Larger than the agent hashes: its size and mode are still compared.
    expect(by["/usr/bin/big"]).toMatchObject({ sha256: null, size: 2048 });
  });

  it("see a change to content or permissions on the next read", async () => {
    const root = host();
    const s = createScanner({ root, paths: ["/etc/passwd"], maxFiles: 100, maxHashBytes: 1024, maxDepth: 4 });
    const first = (await s.scan()).files[0]!;
    writeFileSync(join(root, "etc/passwd"), "root:x:0:0:root:/root:/bin/bash\nbackup2:x:0:0::/:/bin/sh\n");
    const second = (await s.scan()).files[0]!;
    expect(second.sha256).not.toBe(first.sha256);
    chmodSync(join(root, "etc/passwd"), 0o666);
    expect((await s.scan()).files[0]).toMatchObject({ sha256: second.sha256, mode: "0666" });
  });

  it("stop at the limit and say the read is not complete", async () => {
    const root = host();
    const r = await createScanner({ root, paths: ["/etc", "/usr/bin"], maxFiles: 2, maxHashBytes: 1024, maxDepth: 4 }).scan();
    expect(r.files).toHaveLength(2);
    expect(r.complete).toBe(false);
  });

  it("are not read through a link above a watched path", async () => {
    const root = host();
    const r = await createScanner({ root, paths: ["/bin/escape"], maxFiles: 10, maxHashBytes: 1024, maxDepth: 4 }).scan();
    expect(r.files).toEqual([]);
    expect(r.errors[0]).toMatch(/link/);
  });

  it("are named by absolute, normalized paths", () => {
    expect(parsePaths(undefined)).toEqual(DEFAULT_PATHS);
    expect(parsePaths(" /etc/passwd , /etc/ssh/ ")).toEqual(["/etc/passwd", "/etc/ssh"]);
    expect(() => parsePaths("etc/passwd")).toThrow(/absolute/);
    expect(() => parsePaths("/etc/../root")).toThrow(/normalized/);
  });
});
