# runtime-agent

[![CI](https://github.com/openasy/runtime-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/runtime-agent/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent of [OpenAsy Runtime](https://github.com/openasy/runtime). It runs on each Linux host, next to
[Falco](https://falco.org/), which watches the kernel with eBPF and matches its rules. The agent sends what Falco sees
to Runtime and reads the files that should never change (ADR 0066). It has no sensor of its own.

- **It takes Falco's alerts on 127.0.0.1 only.** Falco's `http_output` posts each alert to the agent on port 2801,
  where Falcosidekick would listen; a request from any other address is refused. Alerts wait in a buffer of fixed
  size (20,000) while Runtime is out of reach; the oldest go first when it fills, and the count is reported.
- **It masks secrets before they leave.** Command lines carry secrets (`mysql -pS3cret`, `--password ...`, tokens in
  URLs and headers); they become `***` on the host, in every field and in Falco's output line.
- **It counts program starts instead of sending each one.** Its Falco rule `OpenAsy process started` sees every
  start; the agent counts them by program, parent, user and container and sends the counts with the latest start's
  fields, for Runtime's process inventory.
- **It only reads.** The host's root is mounted read-only. The watched files are read with their SHA-256, mode,
  owner and size; links are recorded with their target and never followed, and a watched path below a link is not
  read at all. A file is hashed again only when its inode, size, mtime or ctime changed.
- **It runs nothing Runtime sends.** Runtime never calls the agent, and its answers say only what was taken. The
  agent cannot kill a process or isolate a host, by design.
- **It enrols once.** It trades an enrolment token for a secret of its own, kept in `/data/agent.state` and sealed
  with its own key-encryption key. When Runtime refuses the secret, because the host was removed there, the agent
  stops sending and never enrols again by itself: that is an admin's decision.

## Run

On each host, Falco and the agent together, with [compose.yaml](./compose.yaml):

```bash
openssl rand -hex 32 > openasy-agent-kek
RUNTIME_URL=https://runtime.example.com RUNTIME_ENROLL_TOKEN=oie_... docker compose up -d
docker compose logs runtime-agent | grep enrolled
```

The enrolment token comes from Runtime, under Hosts: one per host, or one with more uses for many. Falco runs
privileged, as it needs to load its eBPF probe; the agent runs read-only, without any capability, as root so that it
can read root's own files such as `/etc/shadow` (without root they are compared by size and mode only).

Falco needs two files from [`falco/`](./falco): [`openasy.yaml`](./falco/openasy.yaml) in `/etc/falco/config.d/`
(JSON alerts posted to the agent, its web server on 127.0.0.1 for health, and the fields a process tree is made of)
and [`openasy_rules.yaml`](./falco/openasy_rules.yaml) in `/etc/falco/rules.d/` (the program starts). Falco's own
rules stay as they ship. Tested with Falco 0.45.1 and its modern eBPF probe; 0.41's probe does not load on Linux 7.

| Variable | Default | |
| --- | --- | --- |
| `RUNTIME_URL` | | Where Runtime is, with `https://` across a network |
| `RUNTIME_ENROLL_TOKEN` | | Needed once, for the first start |
| `RUNTIME_AGENT_NAME` | `NODE_NAME`, the host's `/etc/hostname` | This host's name in Runtime |
| `FIM_PATHS` | see below | Watched files and directories, separated by commas |
| `FIM_MINUTES` | `5` | How often the watched files are read |
| `FIM_MAX_FILES` | `20000` | A read stops here and says so; nothing past it is taken as deleted |
| `FIM_MAX_MB` | `64` | Larger files are compared by size, mode and owner, not hashed |
| `FALCO_LISTEN` | `127.0.0.1:2801` | Where Falco's `http_output` posts |
| `FALCO_WEBSERVER_URL` | `http://127.0.0.1:8765` | Falco's web server, for its health and version; empty to skip |
| `HEALTH_LISTEN` | `127.0.0.1:2802` | `/healthz`, `/readyz` and `/metrics` |
| `SEND_SECONDS` | `5` | How often alerts are sent |
| `BUFFER_EVENTS` | `20000` | Alerts held while Runtime is out of reach |
| `HOST_ROOT` | `/host` | Where the host's root is mounted |
| `RUNTIME_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key that seals the agent's secret |

The watched paths by default are the accounts (`/etc/passwd`, `shadow`, `group`, `gshadow`), sudo
(`/etc/sudoers`, `sudoers.d`), SSH (`/etc/ssh/sshd_config`, `sshd_config.d`, `/root/.ssh/authorized_keys`), cron
(`/etc/crontab`, `/etc/cron.d`, `/var/spool/cron`), `/etc/pam.d`, `/etc/ld.so.preload`, `/etc/systemd/system` and
the binaries in `/usr/bin`, `/usr/sbin`, `/usr/local/bin` and `/usr/local/sbin`. Directories are read four levels
deep.

## Not yet

A Kubernetes manifest or Helm values that put the agent in Falco's DaemonSet pod, so Falco reaches it on 127.0.0.1;
Falco's gRPC output; Tetragon as a second sensor.

## Develop

```bash
npm install
npm test   # masking, Falco's alerts and the buffer, the file reader, and whole rounds against a stand-in for Runtime
```

## Licence

AGPL-3.0 (ADR 0008).
