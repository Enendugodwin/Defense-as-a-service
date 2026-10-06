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

API_URL = os.environ.get("API_URL", "").strip().rstrip("/")
REGISTRATION_TOKEN = os.environ.get("REGISTRATION_TOKEN", "")
TOKEN_FILE = Path(os.environ.get("AGENT_TOKEN_FILE", "agent.token"))
REMOTE_COMMANDS_ENABLED = os.getenv("REMOTE_COMMANDS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
TELEMETRY_INTERVAL = max(10, int(os.getenv("TELEMETRY_INTERVAL", "60")))
COMMAND_POLL_INTERVAL = max(3, int(os.getenv("COMMAND_POLL_INTERVAL", "5")))
REQUEST_TIMEOUT = (5, 15)
MAX_COMMAND_LENGTH = 2048
MAX_COMMAND_OUTPUT = 32768

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
        raise ValueError("Remote agents must use HTTPS; plain HTTP is allowed only for loopback development")
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


def command_loop(agent_id, token, api_url):
    if not REMOTE_COMMANDS_ENABLED:
        logger.warning("Remote command execution disabled; agent will not poll for commands")
        return
    logger.warning("Remote command execution enabled for agent_id=%s", agent_id)
    headers = {"x-api-key": token}
    while True:
        try:
            response = requests.get(
                f"{api_url}/commands/{agent_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            command = response.json().get("command")
            if command:
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


def main():
    try:
        api_url = validate_api_url(API_URL)
        token_data = load_token_file(TOKEN_FILE) or enroll(api_url)
    except (ValueError, RuntimeError, requests.RequestException, OSError) as exc:
        raise SystemExit(f"Agent setup failed: {type(exc).__name__}") from None

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


if __name__ == "__main__":
    main()