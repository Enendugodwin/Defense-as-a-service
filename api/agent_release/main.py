import argparse
import hashlib
import ipaddress
import json
import logging
import os
import platform
import psutil
import requests
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .session_shell import PersistentShell
except ImportError:
    from session_shell import PersistentShell

API_URL = os.environ.get("API_URL", "").strip().rstrip("/")
REGISTRATION_TOKEN = os.environ.get("REGISTRATION_TOKEN", "")
TOKEN_FILE = Path(os.environ.get("AGENT_TOKEN_FILE", "agent.token"))
REMOTE_COMMANDS_ENABLED = os.getenv("REMOTE_COMMANDS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_HTTP = os.getenv("ALLOW_INSECURE_HTTP", "false").strip().lower() in {"1", "true", "yes", "on"}
SESSION_IDLE_TIMEOUT_SECONDS = max(60, int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "900")))
SESSION_IDLE_TIMEOUT_SECONDS = max(60, int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "900")))
TELEMETRY_INTERVAL = max(10, int(os.getenv("TELEMETRY_INTERVAL", "60")))
COMMAND_POLL_INTERVAL = max(3, int(os.getenv("COMMAND_POLL_INTERVAL", "5")))
REQUEST_TIMEOUT = (5, 15)
MAX_COMMAND_LENGTH = 2048
MAX_COMMAND_OUTPUT = 32768
AGENT_VERSION = "0.3.0"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("defensive_platform.agent")


def validate_api_url(value: str) -> str:
    if not value:
        raise ValueError("Set API_URL before starting the agent")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("API_URL is malformed") from exc
    if not hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("API_URL must have a host and no embedded credentials, query, or fragment")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("API_URL must use HTTPS (HTTP is allowed only on loopback)")
    try:
        loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        loopback = hostname.lower() == "localhost"
    if scheme != "https" and not loopback:
        try:
            private_network = ipaddress.ip_address(hostname).is_private
        except ValueError:
            private_network = False
        if not (ALLOW_INSECURE_HTTP and private_network):
            raise ValueError("Remote agents must use HTTPS; private-network HTTP requires ALLOW_INSECURE_HTTP=true")
    return value.rstrip("/")


def load_token_file(path=TOKEN_FILE):
    try:
        with open(path, "r", encoding="utf-8") as token_file:
            data = json.load(token_file)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data.get("agent_id") or not data.get("token"):
        return None
    return data


def save_token_file(path, token_data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as token_file:
            json.dump(token_data, token_file)
            token_file.flush()
            os.fsync(token_file.fileno())
        os.replace(temporary_name, str(path))
        if os.name != "nt":
            os.chmod(str(path), 0o600)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def collect_telemetry():
    system_info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "agent_version": AGENT_VERSION,
        "capabilities": ["persistent_session_v1"],
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
    }
    processes = []
    for proc in psutil.process_iter(["pid", "name", "username", "memory_percent"], ad_value=None):
        try:
            info = proc.info
            if info.get("memory_percent") is not None:
                processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    processes.sort(key=lambda item: item.get("memory_percent", 0), reverse=True)
    return {"system": system_info, "top_processes": processes[:5]}


def telemetry_loop(agent_id, token, api_url):
    while True:
        try:
            payload = {
                "agent_id": agent_id,
                "event_type": "endpoint_telemetry",
                "data": collect_telemetry(),
            }
            response = requests.post(
                f"{api_url}/ingest",
                json=payload,
                headers={"x-api-key": token},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("Telemetry delivery failed: %s", type(exc).__name__)
        except Exception:
            logger.exception("Telemetry collection failed")
        time.sleep(TELEMETRY_INTERVAL)


def execute_remote_command(command, enabled=None):
    if enabled is None:
        enabled = REMOTE_COMMANDS_ENABLED
    if not enabled:
        raise RuntimeError("Remote command execution is disabled")
    if not isinstance(command, str) or not command.strip() or len(command) > MAX_COMMAND_LENGTH:
        raise ValueError("Command is empty or exceeds the configured length limit")
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def post_session_event(agent_id, token, api_url, session_id, command_id, output, status, session_state):
    payload = {
        "agent_id": agent_id,
        "event_type": "session_event",
        "data": {
            "session_id": session_id,
            "command_id": command_id,
            "output": str(output or "")[:MAX_COMMAND_OUTPUT],
            "status": status,
            "session_state": session_state,
        },
    }
    response = requests.post(
        f"{api_url}/ingest",
        json=payload,
        headers={"x-api-key": token},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()


def handle_session_message(message, sessions, agent_id, token, api_url):
    action = message.get("action")
    session_id = message.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return
    if action == "open":
        if session_id not in sessions and sessions:
            post_session_event(agent_id, token, api_url, session_id, "session-open", "Only one active shell session is allowed per agent.", 1, "error")
            return
        sessions[session_id] = PersistentShell(idle_timeout=SESSION_IDLE_TIMEOUT_SECONDS)
        post_session_event(agent_id, token, api_url, session_id, "session-open", "Line-oriented shell session ready; interactive TTY applications are not supported.", 0, "active")
        return
    if action == "close":
        shell = sessions.pop(session_id, None)
        if shell:
            shell.close()
        post_session_event(agent_id, token, api_url, session_id, "session-close", "Session closed.", 0, "closed")
        return
    if action != "input":
        return

    command_id = str(message.get("command_id") or "session-input")[:128]
    shell = sessions.get(session_id)
    if shell is None:
        post_session_event(agent_id, token, api_url, session_id, command_id, "Session is not active or has expired.", 1, "expired")
        return
    try:
        output, status = shell.execute(message.get("command"))
        post_session_event(agent_id, token, api_url, session_id, command_id, output, status, "active")
    except subprocess.TimeoutExpired as exc:
        output = exc.output or "Command timed out; session was closed."
        shell.close()
        sessions.pop(session_id, None)
        post_session_event(agent_id, token, api_url, session_id, command_id, output, 124, "error")
    except Exception as exc:
        logger.warning("Persistent session command failed: %s", type(exc).__name__)
        shell.close()
        sessions.pop(session_id, None)
        post_session_event(agent_id, token, api_url, session_id, command_id, "Session ended; check agent logs.", 1, "error")


def expire_idle_sessions(sessions, agent_id, token, api_url):
    for session_id, shell in list(sessions.items()):
        if shell.is_idle_expired():
            shell.close()
            sessions.pop(session_id, None)
            try:
                post_session_event(agent_id, token, api_url, session_id, "idle-timeout", "Session closed after inactivity.", 124, "expired")
            except requests.RequestException as exc:
                logger.warning("Could not report session expiry: %s", type(exc).__name__)


def post_session_event(agent_id, token, api_url, session_id, command_id, output, status, session_state):
    payload = {
        "agent_id": agent_id,
        "event_type": "session_event",
        "data": {
            "session_id": session_id,
            "command_id": command_id,
            "output": str(output or "")[:MAX_COMMAND_OUTPUT],
            "status": status,
            "session_state": session_state,
        },
    }
    response = requests.post(
        f"{api_url}/ingest",
        json=payload,
        headers={"x-api-key": token},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()


def handle_session_message(message, sessions, agent_id, token, api_url):
    action = message.get("action")
    session_id = message.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return
    if action == "open":
        if session_id not in sessions and sessions:
            post_session_event(agent_id, token, api_url, session_id, "session-open", "Only one active shell session is allowed per agent.", 1, "error")
            return
        sessions[session_id] = PersistentShell(idle_timeout=SESSION_IDLE_TIMEOUT_SECONDS)
        post_session_event(agent_id, token, api_url, session_id, "session-open", "Line-oriented shell session ready; interactive TTY applications are not supported.", 0, "active")
        return
    if action == "close":
        shell = sessions.pop(session_id, None)
        if shell:
            shell.close()
        post_session_event(agent_id, token, api_url, session_id, "session-close", "Session closed.", 0, "closed")
        return
    if action != "input":
        return

    command_id = str(message.get("command_id") or "session-input")[:128]
    shell = sessions.get(session_id)
    if shell is None:
        post_session_event(agent_id, token, api_url, session_id, command_id, "Session is not active or has expired.", 1, "expired")
        return
    try:
        output, status = shell.execute(message.get("command"))
        post_session_event(agent_id, token, api_url, session_id, command_id, output, status, "active")
    except ValueError as exc:
        post_session_event(agent_id, token, api_url, session_id, command_id, str(exc), 1, "active")
    except subprocess.TimeoutExpired as exc:
        output = exc.output or "Command timed out; session was closed."
        shell.close()
        sessions.pop(session_id, None)
        post_session_event(agent_id, token, api_url, session_id, command_id, output, 124, "error")
    except Exception as exc:
        logger.warning("Persistent session command failed: %s", type(exc).__name__)
        shell.close()
        sessions.pop(session_id, None)
        post_session_event(agent_id, token, api_url, session_id, command_id, "Session ended; check agent logs.", 1, "error")


def expire_idle_sessions(sessions, agent_id, token, api_url):
    for session_id, shell in list(sessions.items()):
        if shell.is_idle_expired():
            shell.close()
            sessions.pop(session_id, None)
            try:
                post_session_event(agent_id, token, api_url, session_id, "idle-timeout", "Session closed after inactivity.", 124, "expired")
            except requests.RequestException as exc:
                logger.warning("Could not report session expiry: %s", type(exc).__name__)


def command_loop(agent_id, token, api_url):
    if not REMOTE_COMMANDS_ENABLED:
        logger.warning("Remote command execution disabled; agent will not poll for commands")
        return
    logger.warning("Remote command execution enabled for agent_id=%s", agent_id)
    headers = {"x-api-key": token}
    sessions = {}
    while True:
        try:
            expire_idle_sessions(sessions, agent_id, token, api_url)
            response = requests.get(
                f"{api_url}/commands/{agent_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            command = response.json().get("command")
            if command:
                try:
                    message = json.loads(command)
                except (TypeError, json.JSONDecodeError):
                    message = None
                if isinstance(message, dict) and message.get("kind") == "session":
                    handle_session_message(message, sessions, agent_id, token, api_url)
                else:
                    result = execute_remote_command(command)
                    output = (result.stdout or result.stderr or "")[:MAX_COMMAND_OUTPUT]
                    result_payload = {
                        "agent_id": agent_id,
                        "event_type": "command_result",
                        "data": {
                            "command_id": hashlib.sha256(command.encode("utf-8")).hexdigest()[:16],
                            "output": output,
                            "status": result.returncode,
                        },
                    }
                    posted = requests.post(
                        f"{api_url}/ingest",
                        json=result_payload,
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                    )
                    posted.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("Command channel request failed: %s", type(exc).__name__)
        except subprocess.TimeoutExpired:
            logger.warning("Remote command timed out for agent_id=%s", agent_id)
        except Exception:
            logger.exception("Remote command processing failed")
        time.sleep(COMMAND_POLL_INTERVAL)


def enroll(api_url):
    if len(REGISTRATION_TOKEN) < 32:
        raise RuntimeError("Set a registration token of at least 32 characters before enrolling")
    payload = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "registration_token": REGISTRATION_TOKEN,
    }
    response = requests.post(f"{api_url}/enroll", json=payload, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    token_data = response.json()
    if not isinstance(token_data, dict) or not token_data.get("agent_id") or not token_data.get("token"):
        raise RuntimeError("Enrollment response is missing the agent identity")
    save_token_file(TOKEN_FILE, token_data)
    return token_data



def validate_agent_token(api_url, token_data):
    response = requests.get(
        f"{api_url}/agents/{token_data['agent_id']}/status",
        headers={"x-api-key": token_data["token"]},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code in {401, 403}:
        return False
    if response.status_code == 404:
        raise RuntimeError("API does not support agent status checks; update the ingest API")
    response.raise_for_status()
    body = response.json()
    return body.get("agent_id") == token_data["agent_id"] and body.get("status") == "registered"


def load_or_enroll(api_url):
    token_data = load_token_file(TOKEN_FILE)
    if token_data is None:
        return enroll(api_url)
    if validate_agent_token(api_url, token_data):
        return token_data
    logger.warning("Saved agent identity was rejected; attempting one re-enrollment")
    return enroll(api_url)


def request_error_summary(error):
    response = getattr(error, "response", None)
    if response is not None:
        return f"{type(error).__name__} (HTTP {response.status_code})"
    return type(error).__name__


def doctor(api_url):
    healthy = True
    for endpoint in ("/health", "/ready"):
        try:
            response = requests.get(api_url + endpoint, timeout=REQUEST_TIMEOUT)
            print(f"API {endpoint}: HTTP {response.status_code}")
            healthy = healthy and response.status_code == 200
        except requests.RequestException as exc:
            print(f"API {endpoint}: unreachable ({request_error_summary(exc)})")
            healthy = False

    token_data = load_token_file(TOKEN_FILE)
    if token_data is None:
        print("Agent identity: no valid local token file; normal startup will enroll")
        return 0 if healthy else 1
    try:
        valid = validate_agent_token(api_url, token_data)
    except (requests.RequestException, RuntimeError) as exc:
        print(f"Agent identity: check failed ({request_error_summary(exc)})")
        return 1
    if valid:
        print(f"Agent identity: registered ({token_data['agent_id']})")
        return 0 if healthy else 1
    print("Agent identity: saved token rejected; normal startup will attempt one re-enrollment")
    return 1

def main(argv=None):
    parser = argparse.ArgumentParser(description="Defensive Platform endpoint agent")
    parser.add_argument("--doctor", action="store_true", help="check API readiness and the saved agent identity without sending telemetry")
    args = parser.parse_args(argv)

    try:
        api_url = validate_api_url(API_URL)
    except ValueError as exc:
        logger.error("Agent configuration error: %s", exc)
        return 2

    if args.doctor:
        return doctor(api_url)

    try:
        token_data = load_or_enroll(api_url)
    except (ValueError, RuntimeError, requests.RequestException, OSError) as exc:
        logger.error("Agent setup failed: %s", request_error_summary(exc))
        return 1

    agent_id = token_data["agent_id"]
    token = token_data["token"]
    logger.info("Agent enrolled: %s", agent_id)
    telemetry_thread = threading.Thread(
        target=telemetry_loop,
        args=(agent_id, token, api_url),
        daemon=True,
    )
    telemetry_thread.start()
    if REMOTE_COMMANDS_ENABLED:
        command_loop(agent_id, token, api_url)
    else:
        logger.info("Telemetry is active; remote command execution is disabled")
        telemetry_thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
