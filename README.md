# Defense-as-a-service — Defensive Monitoring Platform

A self-hosted prototype for endpoint telemetry, syslog ingestion, command administration, and log search. It is intended for systems you own or are explicitly authorized to administer.

## Current capabilities

- **Windows/Linux endpoint agent:** reports hostname, OS/kernel, CPU/memory, and top processes; enrolls with a per-agent token and sends telemetry.
- **FastAPI ingest/control API:** registration, token-authenticated ingest and polling, health/readiness checks, agent status, admin command dispatch, command-result retrieval, and session control.
- **Redis:** one per-agent command queue plus a telemetry queue for log ingestion.
- **PostgreSQL:** agent registry, session state, and command-result output. Command results are kept separate from the OpenSearch log pipeline.
- **Processor + OpenSearch:** indexes telemetry and syslog for search and dashboards.
- **UDP syslog receiver:** accepts device/legacy syslog and sends it through the telemetry pipeline.
- **CLI and C2 web console:** list agents, queue commands, inspect results, and open a persistent line-oriented shell session to a session-capable agent.

The web console is a separate local service on port `8081`, bound to loopback by default. For remote access, use an SSH tunnel; do not expose it directly to the internet.

### Session behavior

Sessions use the existing per-agent Redis command queue. Windows uses a persistent PowerShell process; Linux uses `/bin/sh`. Working-directory and shell-variable state persist within a session. Sessions are limited to one per agent and expire after 15 minutes idle; individual commands time out after 30 seconds. This is line-oriented, not a full PTY—interactive editors and password prompts are unsupported. Results and session state are stored in PostgreSQL; the GUI does not query OpenSearch for command output.

## Current deployment status

**Last verified: October 7, 2026, in the private lab.** The API and local web console were healthy, and a Windows agent session completed a harmless `Get-Location` test. The Windows agent was upgraded to session-capable code; the Linux agent remains registered but was not checking in during the last verification.

The Windows lab agent currently uses an explicit `ALLOW_INSECURE_HTTP` override to reach the API. Agent tokens and session traffic are therefore unencrypted on that private network. Do not use this transport on an untrusted network; TLS is a required production follow-up. The Windows agent is running from a Python script rather than an installed/signed service package, so reboot persistence and managed upgrades remain unfinished.

## Configure and run

1. Copy `.env.example` to `.env` and set unique, strong values. Never commit the populated `.env`.
2. Keep the web-console host binding on loopback.
3. Start the stack with `docker compose up --build -d`.
4. Open `http://127.0.0.1:8081` on the server, or tunnel it from your workstation:

   ```bash
   ssh -L 8081:127.0.0.1:8081 <user>@<server>
   ```

   Then browse to <http://127.0.0.1:8081>.

Run `python agent/main.py --doctor` on an endpoint to check API health/readiness and its saved identity without sending telemetry or polling commands. If a saved token is rejected with 401/403, normal startup attempts one re-enrollment using `REGISTRATION_TOKEN`.

The API requires an admin key for command/session operations. Remote shell command execution is enabled by default in this lab configuration; set `REMOTE_COMMANDS_ENABLED=false` on the API and agent to disable it. Commands execute with the agent process's operating-system privileges. Protect the admin key and restrict access to the session console.

For local mocked tests:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for completed capabilities, current gaps, and prioritized next steps.

## Project files

- `api/` — FastAPI ingest, enrollment, command, session, and results endpoints.
- `agent/` — cross-platform telemetry and session-capable endpoint agent.
- `processor/` — Redis-to-OpenSearch telemetry indexing.
- `syslog-receiver/` — UDP syslog ingestion.
- `c2-web/` — loopback-only web console.
- `c2_console.py` — CLI operator console.
- `docker-compose.yml` — local deployment template with loopback defaults for the console and data services.