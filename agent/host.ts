// What the agent says about its host: its name, operating system, kernel and architecture. The kernel is the one
// the container shares with the host, so os.release() is the host's.
import { readFileSync } from "node:fs";
import { arch, hostname, release } from "node:os";
import { join } from "node:path";

/** PRETTY_NAME from the host's os-release, such as Ubuntu 24.04.1 LTS. */
export function osName(root: string): string | null {
  for (const f of ["etc/os-release", "usr/lib/os-release"]) {
    try {
      const m = readFileSync(join(root, f), "utf8").match(/^PRETTY_NAME=("?)(.*)\1$/m);
      if (m?.[2]) return m[2].slice(0, 128);
    } catch {
      // the next file
    }
  }
  return null;
}

/** The host's name: RUNTIME_AGENT_NAME, the Kubernetes node name, the host's /etc/hostname, or this container's. */
export function hostName(root: string, env: NodeJS.ProcessEnv): string {
  const given = env.RUNTIME_AGENT_NAME || env.NODE_NAME;
  if (given) return given;
  try {
    const n = readFileSync(join(root, "etc/hostname"), "utf8").trim();
    if (n) return n;
  } catch {
    // this container's own name
  }
  return hostname();
}

export const facts = (root: string) => ({ os: osName(root), kernel: release().slice(0, 128), arch: arch() });
