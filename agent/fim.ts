// File integrity (ADR 0066): the agent reads the files it watches on its host, read-only, and sends what it found;
// Runtime compares each read with the one before. The host's root is mounted read-only at HOST_ROOT. Links are
// recorded with their target and never followed, so a link cannot point the agent at a file outside what it watches,
// or outside the host. A file is hashed again only when its inode, size, mtime or ctime changed.
import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, open, readdir, readlink, realpath } from "node:fs/promises";
import { dirname, join, normalize, resolve } from "node:path";

/** Where people and programs change what a host trusts: accounts, sudo, SSH, cron, PAM, the loader, units, binaries. */
export const DEFAULT_PATHS = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/group",
  "/etc/gshadow",
  "/etc/sudoers",
  "/etc/sudoers.d",
  "/etc/ssh/sshd_config",
  "/etc/ssh/sshd_config.d",
  "/root/.ssh/authorized_keys",
  "/etc/crontab",
  "/etc/cron.d",
  "/var/spool/cron",
  "/etc/pam.d",
  "/etc/ld.so.preload",
  "/etc/systemd/system",
  "/usr/bin",
  "/usr/sbin",
  "/usr/local/bin",
  "/usr/local/sbin",
];

export interface FileState {
  path: string;
  kind: "file" | "link";
  /** Null when the file is larger than the agent hashes, or the agent may not read it. */
  sha256: string | null;
  size: number;
  mode: string;
  uid: number;
  gid: number;
  target: string | null;
}

export interface ScanOptions {
  /** Where the host's root is mounted, such as /host; "/" when the agent runs on the host itself. */
  root: string;
  paths: string[];
  /** The read stops here and says it is not complete, so Runtime takes nothing missing as deleted. */
  maxFiles: number;
  maxHashBytes: number;
  /** How deep below a watched directory files are read. */
  maxDepth: number;
}

export interface Scan {
  files: FileState[];
  complete: boolean;
  /** Paths that could not be read at all, for the log. */
  errors: string[];
}

/** Checks the watched paths: absolute, normalized, no `..`. */
export function parsePaths(text: string | undefined): string[] {
  if (!text?.trim()) return DEFAULT_PATHS;
  const paths = text
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  const out = paths.map((p) => p.replace(/(.)\/$/, "$1"));
  for (const p of out)
    if (!p.startsWith("/") || normalize(p) !== p || p.split("/").includes("..")) throw new Error(`FIM_PATHS: ${p} is not an absolute, normalized path`);
  return [...new Set(out)];
}

const modeOf = (st: Stats) => (st.mode & 0o7777).toString(8).padStart(4, "0");

export function createScanner(o: ScanOptions) {
  const root = o.root.replace(/\/$/, "") || "/";
  const cache = new Map<string, { key: string; sha256: string | null }>();

  async function hash(full: string, st: Stats): Promise<string | null> {
    if (st.size > o.maxHashBytes) return null;
    const key = `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}`;
    const hit = cache.get(full);
    if (hit?.key === key) return hit.sha256;
    let sha: string | null = null;
    try {
      // O_NOFOLLOW: a file swapped for a link after lstat is refused rather than followed.
      const fh = await open(full, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const h = createHash("sha256");
        for await (const chunk of fh.createReadStream({ autoClose: false })) h.update(chunk as Buffer);
        sha = h.digest("hex");
      } finally {
        await fh.close();
      }
    } catch {
      sha = null;
    }
    cache.set(full, { key, sha256: sha });
    return sha;
  }

  async function scan(): Promise<Scan> {
    const files: FileState[] = [];
    const errors: string[] = [];
    const seen = new Set<string>();
    let complete = true;
    const hostPath = (full: string) => (root === "/" ? full : full.slice(root.length) || "/");

    async function visit(full: string, depth: number): Promise<void> {
      if (files.length >= o.maxFiles) return void (complete = false);
      let st: Stats;
      try {
        st = await lstat(full);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") errors.push(`${hostPath(full)}: ${(err as NodeJS.ErrnoException).code}`);
        return;
      }
      const path = hostPath(full);
      if (seen.has(path)) return;
      seen.add(path);
      const base = { path, size: st.size, mode: modeOf(st), uid: st.uid, gid: st.gid };
      if (st.isSymbolicLink()) {
        files.push({ ...base, kind: "link", sha256: null, target: await readlink(full).catch(() => null) });
      } else if (st.isFile()) {
        files.push({ ...base, kind: "file", sha256: await hash(full, st), target: null });
      } else if (st.isDirectory() && depth < o.maxDepth) {
        let names: string[];
        try {
          names = (await readdir(full)).sort();
        } catch (err) {
          errors.push(`${path}: ${(err as NodeJS.ErrnoException).code}`);
          return;
        }
        for (const n of names) await visit(join(full, n), depth + 1);
      }
      // Sockets, pipes and devices are not files anyone edits; they are left out.
    }

    // The root itself may be reached through links (macOS's /var is one); what is under it may not.
    const realRoot = await realpath(root).catch(() => root);
    for (const p of o.paths) {
      const full = root === "/" ? p : join(root, p);
      // A watched path whose parent is a link would lead outside what was asked for; such a path is read as nothing.
      const parent = await realpath(join(full, "..")).catch(() => null);
      if (parent && parent !== resolve(realRoot, `.${dirname(p)}`)) {
        errors.push(`${p}: a directory above it is a link; not read`);
        continue;
      }
      await visit(full, 0);
    }
    // A file that went away since the last read takes its hash with it.
    for (const k of cache.keys()) if (!seen.has(hostPath(k))) cache.delete(k);
    return { files, complete, errors };
  }

  return { scan };
}
