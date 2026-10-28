# syntax=docker/dockerfile:1

# The agent needs no tool of its own: Falco is the sensor, in its own container, and the agent reads files with Node.
# Debian slim rather than distroless, as for the other agents. The agent has no runtime dependencies: Node runs the
# TypeScript sources directly.
FROM node:26.12.0-trixie-slim
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn* \
  && mkdir -p /data && chown node:root /data && chmod 0770 /data
WORKDIR /app
COPY package.json ./
COPY agent ./agent
COPY falco ./falco
# The agent's secret lives sealed in /data, writable by node and by root without capabilities (group root); the
# host's root is mounted read-only at /host.
ENV NODE_ENV=production RUNTIME_AGENT_STATE=/data/agent.state HOST_ROOT=/host
VOLUME /data
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:2802/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "agent/main.ts"]
