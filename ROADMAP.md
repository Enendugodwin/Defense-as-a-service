# Project Roadmap

Status reflects the code and private lab checks as of **October 7, 2026**. The status document intentionally contains no live credentials or endpoint identifiers.

## Completed

- [x] Docker Compose foundation: FastAPI, PostgreSQL, Redis, OpenSearch/Dashboards, processor, and syslog receiver.
- [x] Agent enrollment and per-agent token authentication.
- [x] Linux/Windows telemetry collection and outbound command polling.
- [x] Admin-authenticated command dispatch and command-result capture in PostgreSQL.
- [x] Separate C2 web console with loopback binding, agent list, persistent line-oriented sessions, result display, close-session flow, and per-agent Redis command queue.
- [x] Session capability gating so an old agent is not sent session protocol messages before it reports support.
- [x] Agent diagnostics (`--doctor`), secure token-file writes, API timeouts, and one bounded re-enrollment attempt after an invalid saved token.
- [x] Mocked API/agent/console tests and CI workflow.
- [x] Private-lab smoke test: API/web readiness and a Windows shell-session round trip were verified.

## Next priorities

1. **Transport and credential hardening**
   - Replace the lab HTTP exception with trusted TLS for all remote agents.
   - Rotate the remaining legacy service credentials and remove credential-bearing notes/source from the live tree.
   - Restrict PostgreSQL, Redis, and OpenSearch host exposure; keep operator access behind the local tunnel/reverse proxy.
   - Add role-based access, command audit controls, and secret-safe retention for command output.
2. **Installer and appliance delivery**
   - Provide a bare-metal Linux setup script for Docker/Compose, configuration validation, systemd startup, upgrade, and uninstall.
   - Produce an optional all-in-one Linux OVA for VirtualBox/VMware with documented CPU/RAM/disk and network requirements.
   - Generate unique secrets at first boot; never bake `.env`, API keys, agent tokens, or passwords into an installer or OVA. Default management interfaces to loopback and require documented TLS/firewall configuration before remote access.
3. **Agent packaging and lifecycle**
   - Build signed/reproducible Windows agent installer and Linux service package.
   - Configure API URL and trusted CA during installation; use one-time enrollment without embedding bootstrap/admin secrets.
   - Add service management, health checks, controlled upgrades/rollback, uninstall, and persistent logs.
4. **Agentless collection**
   - Add scoped SSH polling for Linux, WinRM for Windows, and SNMP polling for network devices.
5. **Detection and alerting**
   - Normalize telemetry, add Sigma-compatible rules and correlation, and provide notification hooks.
6. **Operator and production operations**
   - Fleet/alert triage UI, RBAC/MFA, broader integration/load tests, backups/recovery, index retention, and pinned image/dependency versions.

## Known limitations

- Persistent sessions are line-oriented, not a full terminal/PTY; interactive programs and password prompts are not supported.
- Remote command execution is powerful and enabled by default in the lab template; disable it where it is not required.
- The current Windows lab agent is running from Python rather than a signed package/service.
- OpenSearch remains for telemetry/log search; command-result output is stored separately in PostgreSQL.
- The lab's explicit HTTP exception is not suitable for untrusted networks.