import os
import unittest
from datetime import datetime
from unittest.mock import patch

# Isolated test-only values; nothing here is a live credential.
for name, char in {
    "REDIS_PASSWORD": "r",
    "POSTGRES_DB": "d",
    "POSTGRES_USER": "u",
    "POSTGRES_PASSWORD": "p",
    "REGISTRATION_TOKEN": "t",
    "ADMIN_API_KEY": "a",
}.items():
    os.environ[name] = char * 64
os.environ.pop("REMOTE_COMMANDS_ENABLED", None)

from fastapi.testclient import TestClient
from api import main as api


class FakeCursor:
    def __init__(self):
        self.query = ""
        self.params = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, query, params=None):
        self.query, self.params = query, params

    def fetchone(self):
        if "WHERE token" in self.query and self.params == ("valid-agent-token",):
            return ("agent-1",)
        if "SELECT last_seen" in self.query and self.params == ("agent-1",):
            return (datetime(2026, 1, 2, 3, 4, 5),)
        if "WHERE agent_id" in self.query and self.params == ("agent-1",):
            return (1,)
        if self.query == "SELECT 1":
            return (1,)
        return None


class FakeConnection:
    def cursor(self):
        return FakeCursor()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def close(self):
        pass


class ApiSecurityTests(unittest.TestCase):
    def request(self, callback):
        with patch.object(api, "get_db_conn", side_effect=FakeConnection):
            with TestClient(api.app) as client:
                return callback(client)

    def test_health_and_readiness(self):
        with patch.object(api.r, "ping", return_value=True):
            health, readiness = self.request(
                lambda client: (client.get("/health"), client.get("/ready"))
            )
        self.assertEqual(health.status_code, 200)
        self.assertEqual(readiness.status_code, 200)

    def test_readiness_fails_closed_when_redis_is_down(self):
        with patch.object(api.r, "ping", side_effect=RuntimeError("unavailable")):
            response = self.request(lambda client: client.get("/ready"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "Dependencies unavailable")

    def test_bad_registration_token_is_rejected(self):
        response = self.request(lambda client: client.post("/enroll", json={
            "hostname": "host-1", "os": "Linux", "registration_token": "wrong"
        }))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_returns_a_new_agent_token(self):
        response = self.request(lambda client: client.post("/enroll", json={
            "hostname": "host-1", "os": "Linux", "registration_token": "t" * 64
        }))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["agent_id"])
        self.assertGreaterEqual(len(response.json()["token"]), 32)

    def test_ingest_rejects_invalid_agent_token(self):
        with patch.object(api, "verify_token", return_value=None):
            response = self.request(lambda client: client.post(
                "/ingest",
                headers={"x-api-key": "wrong"},
                json={"agent_id": "agent-1", "event_type": "test", "data": {}},
            ))
        self.assertEqual(response.status_code, 403)

    def test_agent_status_is_read_only_and_authenticated(self):
        with patch.object(api, "verify_token", return_value="agent-1"):
            response = self.request(lambda client: client.get(
                "/agents/agent-1/status", headers={"x-api-key": "valid-agent-token"}
            ))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["agent_id"], "agent-1")
        self.assertEqual(response.json()["status"], "registered")
        self.assertEqual(response.json()["last_seen"], "2026-01-02T03:04:05")

    def test_agent_status_rejects_invalid_token(self):
        with patch.object(api, "verify_token", return_value=None):
            response = self.request(lambda client: client.get(
                "/agents/agent-1/status", headers={"x-api-key": "wrong"}
            ))
        self.assertEqual(response.status_code, 403)

    def test_command_is_enabled_by_default(self):
        self.assertTrue(api.REMOTE_COMMANDS_ENABLED)
        with patch.object(api, "agent_is_enrolled", return_value=True):
            with patch.object(api.r, "lpush") as enqueue:
                response = self.request(lambda client: client.post(
                    "/send-command",
                    headers={"x-api-key": "a" * 64},
                    json={"agent_id": "agent-1", "command": "echo test"},
                ))
        self.assertEqual(response.status_code, 200)
        enqueue.assert_called_once_with("commands:agent-1", "echo test")

    def test_command_requires_admin_authentication(self):
        with patch.object(api, "REMOTE_COMMANDS_ENABLED", True):
            with patch.object(api.r, "lpush") as enqueue:
                response = self.request(lambda client: client.post(
                    "/send-command",
                    headers={"x-api-key": "wrong"},
                    json={"agent_id": "agent-1", "command": "echo test"},
                ))
        self.assertEqual(response.status_code, 403)
        enqueue.assert_not_called()

    def test_command_requires_an_enrolled_agent(self):
        with patch.object(api, "REMOTE_COMMANDS_ENABLED", True):
            with patch.object(api, "agent_is_enrolled", return_value=False):
                with patch.object(api.r, "lpush") as enqueue:
                    response = self.request(lambda client: client.post(
                        "/send-command",
                        headers={"x-api-key": "a" * 64},
                        json={"agent_id": "unknown", "command": "echo test"},
                    ))
        self.assertEqual(response.status_code, 404)
        enqueue.assert_not_called()

    def test_command_queues_only_with_opt_in_and_auth(self):
        with patch.object(api, "REMOTE_COMMANDS_ENABLED", True):
            with patch.object(api, "agent_is_enrolled", return_value=True):
                with patch.object(api.r, "lpush") as enqueue:
                    response = self.request(lambda client: client.post(
                        "/send-command",
                        headers={"x-api-key": "a" * 64},
                        json={"agent_id": "agent-1", "command": "echo test"},
                    ))
        self.assertEqual(response.status_code, 200)
        enqueue.assert_called_once_with("commands:agent-1", "echo test")

    def test_agent_cannot_receive_queued_commands_while_disabled(self):
        with patch.object(api, "REMOTE_COMMANDS_ENABLED", False):
            with patch.object(api, "verify_token", return_value="agent-1"):
                with patch.object(api.r, "rpop") as dequeue:
                    response = self.request(lambda client: client.get(
                        "/commands/agent-1", headers={"x-api-key": "valid-agent-token"}
                    ))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"command": None})
        dequeue.assert_not_called()

    def test_agent_can_poll_after_explicit_command_opt_in(self):
        with patch.object(api, "REMOTE_COMMANDS_ENABLED", True):
            with patch.object(api, "verify_token", return_value="agent-1"):
                with patch.object(api.r, "rpop", return_value="echo test") as dequeue:
                    response = self.request(lambda client: client.get(
                        "/commands/agent-1", headers={"x-api-key": "valid-agent-token"}
                    ))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"command": "echo test"})
        dequeue.assert_called_once_with("commands:agent-1")

    def test_command_length_is_bounded(self):
        response = self.request(lambda client: client.post(
            "/send-command",
            headers={"x-api-key": "a" * 64},
            json={"agent_id": "agent-1", "command": "x" * 2049},
        ))
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()