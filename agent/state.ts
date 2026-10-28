// What the agent keeps on its own volume (ADR 0021): who it is to Runtime and the secret it got when it enrolled,
// sealed with its own key-encryption key. Losing the volume means enrolling again; an admin removes the old host first.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Keyring } from "./kek.ts";

export interface AgentState {
  hostId?: string;
  secret?: string;
}

export function loadState(path: string, keyring: Keyring): AgentState {
  let sealed: string | undefined;
  try {
    sealed = readFileSync(path, "utf8").trim();
  } catch {
    sealed = undefined;
  }
  return sealed ? (JSON.parse(keyring.open(sealed).toString("utf8")) as AgentState) : {};
}

export function saveState(path: string, keyring: Keyring, state: AgentState) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, keyring.seal(JSON.stringify(state)), { mode: 0o600 });
  renameSync(tmp, path);
}
