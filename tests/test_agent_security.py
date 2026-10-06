import json
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

os.environ.pop("REMOTE_COMMANDS_ENABLED", None)
from agent import main as agent


class StubResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self.payload = payload or {}

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class AgentSecurityTests(unittest.TestCase):
    def test_https_is_required_for_remote_api_urls(self):
        self.assertEqual(agent.validate_api_url("https://monitor.example:8443/"), "https://monitor.example:8443")
        with self.assertRaises(ValueError):
            agent.validate_api_url("http://192.0.2.10:8000")

    def test_http_is_allowed_only_for_loopback_development(self):
        self.assertEqual(agent.validate_api_url("http://127.0.0.1:8000/"), "http://127.0.0.1:8000")
        self.assertEqual(agent.validate_api_url("http://localhost:8000"), "http://localhost:8000")
        with self.assertRaises(ValueError):
            agent.validate_api_url("http://example.com")

    def test_private_http_requires_explicit_lab_override(self):
        with self.assertRaises(ValueError):
            agent.validate_api_url("http://192.168.100.247:8000")
        with patch.object(agent, "ALLOW_INSECURE_HTTP", True):
            self.assertEqual(agent.validate_api_url("http://192.168.100.247:8000"), "http://192.168.100.247:8000")
            with self.assertRaises(ValueError):
                agent.validate_api_url("http://8.8.8.8:8000")

    def test_api_url_rejects_embedded_credentials_and_query_strings(self):
        for value in ("https://user:pass@example.com", "https://example.com?token=abc", "ftp://example.com"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    agent.validate_api_url(value)

    def test_token_file_round_trip_and_restrictive_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "agent.token")
            expected = {"agent_id": "agent-1", "token": "t" * 48}
            agent.save_token_file(path, expected)
            self.assertEqual(agent.load_token_file(path), expected)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_invalid_token_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "agent.token")
            with open(path, "w", encoding="utf-8") as token_file:
                token_file.write(json.dumps({"agent_id": "agent-1"}))
            self.assertIsNone(agent.load_token_file(path))

    def test_valid_saved_token_passes_read_only_status_check(self):
        token_data = {"agent_id": "agent-1", "token": "t" * 48}
        response = StubResponse(200, {"agent_id": "agent-1", "status": "registered"})
        with patch.object(agent.requests, "get", return_value=response) as get:
            self.assertTrue(agent.validate_agent_token("https://monitor.example", token_data))
        self.assertEqual(get.call_args.kwargs["timeout"], agent.REQUEST_TIMEOUT)

    def test_rejected_saved_token_is_detected_without_polling_commands(self):
        token_data = {"agent_id": "old-agent", "token": "o" * 48}
        with patch.object(agent.requests, "get", return_value=StubResponse(403)) as get:
            self.assertFalse(agent.validate_agent_token("https://monitor.example", token_data))
        self.assertIn("/agents/old-agent/status", get.call_args.args[0])

    def test_valid_saved_identity_does_not_reenroll(self):
        saved = {"agent_id": "agent-1", "token": "t" * 48}
        with patch.object(agent, "load_token_file", return_value=saved):
            with patch.object(agent, "validate_agent_token", return_value=True):
                with patch.object(agent, "enroll") as enroll:
                    self.assertEqual(agent.load_or_enroll("https://monitor.example"), saved)
        enroll.assert_not_called()

    def test_rejected_saved_identity_reenrolls_once(self):
        saved = {"agent_id": "old-agent", "token": "o" * 48}
        fresh = {"agent_id": "new-agent", "token": "n" * 48}
        with patch.object(agent, "load_token_file", return_value=saved):
            with patch.object(agent, "validate_agent_token", return_value=False):
                with patch.object(agent, "enroll", return_value=fresh) as enroll:
                    result = agent.load_or_enroll("https://monitor.example")
        self.assertEqual(result, fresh)
        enroll.assert_called_once_with("https://monitor.example")

    def test_doctor_reports_stale_identity_without_enrolling(self):
        saved = {"agent_id": "old-agent", "token": "o" * 48}
        output = io.StringIO()
        with patch.object(agent.requests, "get", return_value=StubResponse(200)):
            with patch.object(agent, "load_token_file", return_value=saved):
                with patch.object(agent, "validate_agent_token", return_value=False):
                    with patch.object(agent, "enroll") as enroll:
                        with redirect_stdout(output):
                            result = agent.doctor("https://monitor.example")
        self.assertEqual(result, 1)
        self.assertIn("saved token rejected", output.getvalue())
        enroll.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX shell protocol is verified on the Linux CI runner")
    def test_session_protocol_reuses_shell_and_closes_it(self):
        sessions = {}
        with patch.object(agent.requests, "post") as post:
            agent.handle_session_message(
                {"kind": "session", "action": "open", "session_id": "session-1"},
                sessions, "agent-1", "t" * 48, "https://monitor.example",
            )
            agent.handle_session_message(
                {"kind": "session", "action": "input", "session_id": "session-1", "command_id": "c1", "command": "cd /tmp"},
                sessions, "agent-1", "t" * 48, "https://monitor.example",
            )
            agent.handle_session_message(
                {"kind": "session", "action": "input", "session_id": "session-1", "command_id": "c2", "command": "pwd"},
                sessions, "agent-1", "t" * 48, "https://monitor.example",
            )
            agent.handle_session_message(
                {"kind": "session", "action": "close", "session_id": "session-1"},
                sessions, "agent-1", "t" * 48, "https://monitor.example",
            )
        self.assertNotIn("session-1", sessions)
        events = [call.kwargs["json"]["data"] for call in post.call_args_list]
        self.assertTrue(any(item.get("command_id") == "c2" and "/tmp" in item.get("output", "") for item in events))
        self.assertEqual(events[-1]["session_state"], "closed")

    @unittest.skipUnless(os.name == "nt", "PowerShell session is tested on Windows CI")
    def test_persistent_powershell_keeps_environment_between_commands(self):
        shell = agent.PersistentShell(idle_timeout=60, command_timeout=5)
        try:
            _, first_status = shell.execute("$env:DEFENSIVE_SESSION_TEST='alive'")
            output, second_status = shell.execute("Write-Output $env:DEFENSIVE_SESSION_TEST")
            self.assertEqual(first_status, 0)
            self.assertEqual(second_status, 0)
            self.assertIn("alive", output)
        finally:
            shell.close()

    @unittest.skipIf(os.name == "nt", "POSIX shell persistence is verified on the Linux CI runner")
    def test_persistent_shell_keeps_working_directory_between_commands(self):
        shell = agent.PersistentShell(idle_timeout=60, command_timeout=5)
        try:
            _, first_status = shell.execute("cd /tmp")
            output, second_status = shell.execute("pwd")
            self.assertEqual(first_status, 0)
            self.assertEqual(second_status, 0)
            self.assertIn("/tmp", output)
        finally:
            shell.close()

    def test_remote_execution_is_enabled_by_default_without_running_a_command(self):
        self.assertTrue(agent.REMOTE_COMMANDS_ENABLED)
        with patch.object(agent.subprocess, "run", return_value=object()) as run:
            agent.execute_remote_command("echo test")
        run.assert_called_once()

    def test_remote_execution_can_be_disabled_explicitly(self):
        with patch.object(agent, "REMOTE_COMMANDS_ENABLED", False):
            with self.assertRaises(RuntimeError):
                agent.execute_remote_command("echo test")

    def test_enabled_execution_is_mocked_and_has_a_timeout(self):
        fake_result = object()
        with patch.object(agent.subprocess, "run", return_value=fake_result) as run:
            result = agent.execute_remote_command("echo test", enabled=True)
        self.assertIs(result, fake_result)
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertTrue(run.call_args.kwargs["shell"])

    def test_command_length_is_bounded(self):
        with patch.object(agent, "REMOTE_COMMANDS_ENABLED", True):
            with self.assertRaises(ValueError):
                agent.execute_remote_command("x" * (agent.MAX_COMMAND_LENGTH + 1))


if __name__ == "__main__":
    unittest.main()