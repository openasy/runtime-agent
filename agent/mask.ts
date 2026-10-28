// Values that look like passwords, tokens or keys are masked here, before anything leaves the host (ADR 0066). Falco
// reports command lines, and command lines carry secrets: `mysql -pS3cret`, `curl -H 'Authorization: Bearer ...'`.

/** Logs' patterns (logs/server/pipeline.ts, logs-agent/agent/lines.ts), and the flags command lines pass secrets with. */
export const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[private key masked]"],
  [/\b(authorization|proxy-authorization)(["']?\s*[:=]\s*["']?)(bearer|basic|token|apikey)?\s*[A-Za-z0-9._~+/=-]{8,}/gi, "$1$2$3 ***"],
  [/\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)(["']?\s*[:=]\s*["']?)[^\s"'&,;]{3,}/gi, "$1$2***"],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "$1****************"],
  [/\b(gh[pousr]_)[A-Za-z0-9]{30,}\b/g, "$1***"],
  [/\b(xox[abprs]-)[A-Za-z0-9-]{10,}/g, "$1***"],
  [/\b(sk_live_|rk_live_)[A-Za-z0-9]{10,}/g, "$1***"],
  [/(:\/\/[^:/\s@]+:)[^@/\s]{1,}@/g, "$1***@"],
  // --password hunter2, --token=abc, --api-key abc
  [/(--?(?:password|passwd|pass|token|secret|api-?key|access-key|auth-token|client-secret)[=\s]+)("[^"]*"|'[^']*'|\S+)/gi, "$1***"],
  // mysql -pS3cret, sshpass -pS3cret: -p glued to its value
  [/(\b(?:mysql|mysqldump|mariadb|sshpass)\b[^|;&\n]*?\s-p)(\S+)/g, "$1***"],
];

export function mask(s: string): string {
  let out = s;
  for (const [re, repl] of SECRET_PATTERNS) out = out.replace(re, repl);
  return out;
}
