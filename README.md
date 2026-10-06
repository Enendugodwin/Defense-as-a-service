# Defense-as-a-service — Defensive Monitoring Platform

A prototype, self-hosted security telemetry pipeline. The repository template intentionally contains no live credentials. Configure local secrets through an untracked `.env` file before running it.

## Components

- **Endpoint agent:** collects host identity, CPU/memory, and top-process telemetry from Linux or Windows; enrolls with the API and polls for commands only when explicitly enabled.
- **FastAPI ingest API:** handles enrollment, token-authenticated telemetry, health/readiness checks, and optional authenticated command queueing.
- **Redis:** buffers telemetry and pending agent commands.
- **PostgreSQL:** stores enrolled agent metadata and per-agent tokens.
- **Processor:** drains telemetry from Redis and indexes events in OpenSearch.
- **Syslog receiver:** accepts UDP syslog and places messages in the telemetry queue.
- **CLI console:** lists agents and can queue commands for an enrolled agent.
- **OpenSearch Dashboards:** provides the data exploration UI.

> **Important:** when explicitly enabled, the agent can execute received commands through a shell. This is powerful remote-administration functionality. Run only on systems you own or are authorized to administer; isolate the lab, protect the admin key, and audit use. Command execution is enabled by default; set `REMOTE_COMMANDS_ENABLED=false` on the API and agent to disable it.

## Configure and run locally

1. Copy `.env.example` to `.env`.
2. Set unique values for all blank variables. `REGISTRATION_TOKEN` and `ADMIN_API_KEY` must be at least 32 characters; Redis and PostgreSQL passwords must be at least 16 characters.
3. Keep host bindings on loopback unless you have configured a TLS reverse proxy and firewall rules.
4. Start the stack with `docker compose up --build -d`.

Redis and OpenSearch are not published to the host. The API, dashboard, PostgreSQL, and syslog ports default to loopback. Compose healthchecks gate API startup on Redis/PostgreSQL readiness. The API process itself speaks HTTP; the agent rejects HTTP URLs to non-loopback hosts. Put a trusted TLS reverse proxy in front of the API before connecting remote agents. Configure a trusted OpenSearch CA before setting `OPENSEARCH_VERIFY_CERTS=true`.

Remote command execution is enabled by default. Set `REMOTE_COMMANDS_ENABLED=false` on both the API and an agent to disable it. Because the feature runs shell commands, allow it only on tightly controlled endpoints and protect the admin key.

## Tests

Install the development dependencies and run the mocked API/agent tests:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests do not connect to a real database, Redis, endpoint, or OpenSearch cluster.

## Current limitations

This is a prototype rather than a complete SIEM/EDR product. Agentless SSH/WinRM/SNMP collection, Sigma correlation and alerting, fleet UI, RBAC/MFA, production agent packaging, full operational backups, and retention policies remain future work. Review TLS termination, certificate verification, audit logging, immutable dependency/image pinning, backups, and retention before non-lab use.