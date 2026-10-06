# Defense-as-a-service — Defensive Monitoring Platform

A prototype, self-hosted security telemetry pipeline. The repository template intentionally contains no live credentials. Configure local secrets through an untracked `.env` file before running it.

## Components

- **Endpoint agent:** collects host identity, CPU/memory, and top-process telemetry from Linux or Windows; enrolls with the API and polls for queued commands.
- **FastAPI ingest API:** handles enrollment, token-authenticated telemetry, and authenticated command queueing.
- **Redis:** buffers telemetry and pending agent commands.
- **PostgreSQL:** stores enrolled agent metadata and per-agent tokens.
- **Processor:** drains telemetry from Redis and indexes events in OpenSearch.
- **Syslog receiver:** accepts UDP syslog and places messages in the telemetry queue.
- **CLI console:** lists agents and can queue commands for an enrolled agent.
- **OpenSearch Dashboards:** provides the data exploration UI.

> **Important:** the agent currently executes received commands through a shell. This is a powerful remote-administration capability. Run only on systems you own or are explicitly authorized to administer, isolate the lab, protect the admin key, and audit command use. The prototype does not provide a production-grade TLS/RBAC boundary.

## Configure locally

1. Copy `.env.example` to `.env`.
2. Fill every blank value with unique, strong values. Do not reuse credentials from an existing deployment.
3. Keep the default loopback bindings unless you have separately designed network access, firewalling, and TLS termination.
4. Start the containers with `docker compose up --build -d`.

The Compose template does not publish Redis or OpenSearch directly to the host. API, dashboard, PostgreSQL, and syslog host ports default to loopback. For remote agents/devices, add a TLS reverse proxy and carefully scope firewall access before changing the API or syslog bind address. The current agent/API sample uses HTTP; do not send agent tokens over an untrusted network. Configure a trusted OpenSearch CA before setting `OPENSEARCH_VERIFY_CERTS=true`.

Run the agent with `API_URL` and `REGISTRATION_TOKEN` set in its environment. It saves its issued per-agent token to `agent.token`, which is ignored by Git. The management console also needs the local `POSTGRES_*`, `ADMIN_API_KEY`, and `API_URL` environment variables.

## Required local environment variables

`REDIS_PASSWORD`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `OPENSEARCH_USER`, `OPENSEARCH_PASSWORD`, `REGISTRATION_TOKEN`, and `ADMIN_API_KEY`.

For agent execution, set `API_URL` and `REGISTRATION_TOKEN`. Never put populated secrets in source files, documentation, screenshots, issue reports, or Git history.

## Current limitations

This is a prototype rather than a complete SIEM/EDR product. The repository does not yet include agentless SSH/WinRM/SNMP collection, correlation and alerting, fleet-management UI, RBAC/MFA, production packaging, or a full automated test suite. Review and harden authentication, TLS, certificate verification, audit logging, dependency/image pinning, backups, and retention before non-lab use.
