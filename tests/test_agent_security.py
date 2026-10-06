import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from agent import main as agent


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

    def test_remote_execution_is_disabled_by_default(self):
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