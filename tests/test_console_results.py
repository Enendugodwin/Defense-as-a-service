import os
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

os.environ.update({
    "ADMIN_API_KEY": "a" * 64,
    "POSTGRES_DB": "d" * 16,
    "POSTGRES_USER": "u" * 16,
    "POSTGRES_PASSWORD": "p" * 64,
})

import c2_console


class FakeResponse:
    status_code = 200

    def json(self):
        return {
            "results": [{
                "agent_id": "agent-1",
                "command_id": "result-1",
                "received_at": "2026-10-06T12:00:00+00:00",
                "status": 0,
                "output": "expected command output",
            }]
        }


class ConsoleResultTests(unittest.TestCase):
    def test_send_command_prints_result_correlation_id(self):
        import hashlib
        output = StringIO()
        response = type("Response", (), {"status_code": 200})()
        with patch("builtins.input", side_effect=["agent-1", "echo test"]):
            with patch.object(c2_console.requests, "post", return_value=response) as post:
                with redirect_stdout(output):
                    c2_console.send_command()
        expected_id = hashlib.sha256(b"echo test").hexdigest()[:16]
        self.assertIn(expected_id, output.getvalue())
        self.assertEqual(post.call_args.kwargs["json"], {"agent_id": "agent-1", "command": "echo test"})

    def test_list_command_results_displays_output_and_uses_admin_api(self):
        output = StringIO()
        with patch("builtins.input", side_effect=["agent-1", "10"]):
            with patch.object(c2_console.requests, "get", return_value=FakeResponse()) as get:
                with redirect_stdout(output):
                    c2_console.list_command_results()
        self.assertIn("result-1", output.getvalue())
        self.assertIn("exit=0", output.getvalue())
        self.assertIn("expected command output", output.getvalue())
        self.assertEqual(get.call_args.args[0], f"{c2_console.API_URL}/command-results/agent-1")
        self.assertEqual(get.call_args.kwargs["params"], {"limit": 10})
        self.assertEqual(get.call_args.kwargs["timeout"], (5, 15))


if __name__ == "__main__":
    unittest.main()