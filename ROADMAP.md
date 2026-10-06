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
2. **Agent packaging and lifecycle**
   - Build signed/reproducible Windows and Linux packages.
   - Install the Windows agent as a managed service or scheduled task with controlled restart/update behavior.
   - Test upgrades, rollback, token recovery, and session cleanup after disconnect/reboot.
3. **Agentless collection**
   - Add scoped SSH polling for Linux, WinRM for Windows, and SNMP polling for network devices.
4. **Detection and alerting**
   - Normalize telemetry, add Sigma-compatible rules and correlation, and provide notification hooks.
5. **Operator and production operations**
   - Fleet/alert triage UI, RBAC/MFA, broader integration/load tests, backups/recovery, index retention, and pinned image/dependency versions.

## Known limitations

- Persistent sessions are line-oriented, not a full terminal/PTY; interactive programs and password prompts are not supported.
- Remote command execution is powerful and enabled by default in the lab template; disable it where it is not required.
- The current Windows lab agent is running from Python rather than a signed package/service.
- OpenSearch remains for telemetry/log search; command-result output is stored separately in PostgreSQL.
- The lab's explicit HTTP exception is not suitable for untrusted networks.