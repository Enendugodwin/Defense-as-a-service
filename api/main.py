import hashlib
import json
import logging
import os
import secrets
from contextlib import closing
from datetime import datetime
from typing import Any, Dict

import psycopg2
import redis
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field


def required_secret(name: str, minimum_length: int) -> str:
    value = os.environ.get(name, "")
    if len(value) < minimum_length:
        raise RuntimeError(f"{name} must be configured with at least {minimum_length} characters")
    return value


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("defensive_platform.api")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = required_secret("REDIS_PASSWORD", max(1, int(os.getenv("REDIS_PASSWORD_MIN_LENGTH", "16"))))
DB_HOST = os.getenv("DB_HOST", "postgres")
DB_NAME = os.environ["POSTGRES_DB"]
DB_USER = os.environ["POSTGRES_USER"]
DB_PASS = required_secret("POSTGRES_PASSWORD", 16)
REGISTRATION_TOKEN = required_secret("REGISTRATION_TOKEN", 32)
ADMIN_API_KEY = required_secret("ADMIN_API_KEY", 32)
REMOTE_COMMANDS_ENABLED = env_flag("REMOTE_COMMANDS_ENABLED", True)
API_DOCS_ENABLED = env_flag("API_DOCS_ENABLED", False)
DB_CONNECT_TIMEOUT = max(1, int(os.getenv("DB_CONNECT_TIMEOUT", "5")))
SESSION_IDLE_TIMEOUT_SECONDS = max(60, int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "900")))
MAX_COMMAND_RESULT_OUTPUT = 32768

app = FastAPI(
    title="Defensive Platform Ingest API",
    docs_url="/docs" if API_DOCS_ENABLED else None,
    redoc_url=None,
    openapi_url="/openapi.json" if API_DOCS_ENABLED else None,
)
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
    socket_connect_timeout=3,
    socket_timeout=3,
)


def get_db_conn():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        connect_timeout=DB_CONNECT_TIMEOUT,
    )


class Telemetry(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=64)
    data: Dict[str, Any]


class CommandRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    command: str = Field(min_length=1, max_length=2048)


class EnrollmentRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    os: str = Field(min_length=1, max_length=64)
    registration_token: str = Field(min_length=1, max_length=512)


class SessionStartRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)


class SessionInputRequest(BaseModel):
    command: str = Field(min_length=1, max_length=2048)


def credentials_match(provided: str, expected: str) -> bool:
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def verify_token(token: str):
    if not token or len(token) > 512:
        return None
    try:
        with closing(get_db_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT agent_id FROM agents WHERE token = %s", (token,))
                row = cur.fetchone()
    except psycopg2.Error:
        logger.exception("Agent token verification failed")
        raise HTTPException(status_code=503, detail="Authentication service unavailable") from None
    return row[0] if row else None


def agent_is_enrolled(agent_id: str) -> bool:
    with closing(get_db_conn()) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM agents WHERE agent_id = %s", (agent_id,))
            return cur.fetchone() is not None


def agent_session_capable(agent_id: str) -> bool:
    with closing(get_db_conn()) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT session_capable FROM agents WHERE agent_id = %s", (agent_id,))
            row = cur.fetchone()
    return bool(row and row[0])


@app.on_event("startup")
def startup_event():
    with closing(get_db_conn()) as conn:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY,
                        hostname TEXT NOT NULL,
                        os TEXT NOT NULL,
                        token TEXT UNIQUE NOT NULL,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        agent_version TEXT,
                        session_capable BOOLEAN NOT NULL DEFAULT FALSE
                    )"""
                )
                cur.execute("ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_version TEXT")
                cur.execute("ALTER TABLE agents ADD COLUMN IF NOT EXISTS session_capable BOOLEAN NOT NULL DEFAULT FALSE")
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS command_results (
                        result_id BIGSERIAL PRIMARY KEY,
                        agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
                        command_id TEXT NOT NULL,
                        received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        status INTEGER,
                        output TEXT NOT NULL DEFAULT ''
                    )"""
                )
                cur.execute("ALTER TABLE command_results ADD COLUMN IF NOT EXISTS session_id TEXT")
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS command_results_agent_time_idx "
                    "ON command_results (agent_id, received_at DESC, result_id DESC)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS command_results_session_idx "
                    "ON command_results (session_id, result_id)"
                )
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS command_sessions (
                        session_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
                        status TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        last_activity TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        closed_at TIMESTAMPTZ
                    )"""
                )
                cur.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS command_sessions_one_active_agent_idx "
                    "ON command_sessions (agent_id) WHERE status IN ('starting', 'active', 'closing')"
                )


@app.get("/agent-package/{filename}")
def download_agent_package(filename: str, x_api_key: str = Header(None)):
    if filename not in {"main.py", "session_shell.py"}:
        raise HTTPException(status_code=404, detail="Agent package file not found")
    agent_id = verify_token(x_api_key)
    if not agent_id:
        raise HTTPException(status_code=403, detail="Invalid agent API token")
    package_path = Path(__file__).parent / "agent_release" / filename
    if not package_path.is_file():
        raise HTTPException(status_code=404, detail="Agent package file unavailable")
    return FileResponse(
        str(package_path),
        media_type="text/plain; charset=utf-8",
        filename=filename,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
def health():
    return {"status": "online"}


@app.get("/ready")
def ready():
    try:
        with closing(get_db_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        if not r.ping():
            raise RuntimeError("Redis is not ready")
    except Exception:
        logger.exception("Readiness check failed")
        raise HTTPException(status_code=503, detail="Dependencies unavailable") from None
    return {"status": "ready"}


@app.post("/enroll")
async def enroll(req: EnrollmentRequest):
    if not credentials_match(req.registration_token, REGISTRATION_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid registration token")

    agent_id = secrets.token_hex(16)
    token = secrets.token_urlsafe(32)
    try:
        with closing(get_db_conn()) as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO agents (agent_id, hostname, os, token) VALUES (%s, %s, %s, %s)",
                        (agent_id, req.hostname, req.os, token),
                    )
    except psycopg2.Error:
        logger.exception("Agent enrollment storage failed")
        raise HTTPException(status_code=503, detail="Enrollment storage unavailable") from None

    return {"agent_id": agent_id, "token": token}


def normalize_command_result(data):
    output = data.get("output", "")
    if not isinstance(output, str):
        output = json.dumps(output, ensure_ascii=False)
    output = output[:MAX_COMMAND_RESULT_OUTPUT]

    command_id = data.get("command_id")
    if not command_id:
        command_text = data.get("command")
        command_id = hashlib.sha256(command_text.encode("utf-8")).hexdigest()[:16] if isinstance(command_text, str) else secrets.token_hex(8)
    command_id = str(command_id)[:128]

    status = data.get("status")
    if isinstance(status, bool):
        status = None
    elif not isinstance(status, int):
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = None
    if status is not None and not -(2**31) <= status < 2**31:
        status = None
    return command_id, status, output


def persist_command_result(agent_id: str, data: Dict[str, Any]):
    command_id, status, output = normalize_command_result(data)
    session_id = data.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        session_id = None
    session_state = data.get("session_state")
    with closing(get_db_conn()) as conn:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE agents SET last_seen = CURRENT_TIMESTAMP WHERE agent_id = %s", (agent_id,))
                if session_id:
                    cur.execute("SELECT agent_id FROM command_sessions WHERE session_id = %s", (session_id,))
                    session_row = cur.fetchone()
                    if not session_row or session_row[0] != agent_id:
                        raise HTTPException(status_code=403, detail="Session does not belong to this agent")
                cur.execute(
                    "INSERT INTO command_results (agent_id, session_id, command_id, status, output) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (agent_id, session_id, command_id, status, output),
                )
                if session_id and session_state in {"active", "closing", "closed", "expired", "error"}:
                    closed_at = session_state in {"closed", "expired", "error"}
                    cur.execute(
                        "UPDATE command_sessions SET status = %s, last_activity = CURRENT_TIMESTAMP, "
                        "closed_at = CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE closed_at END "
                        "WHERE session_id = %s AND agent_id = %s",
                        (session_state, closed_at, session_id, agent_id),
                    )
    return command_id


@app.post("/ingest")
async def ingest(telemetry: Telemetry, x_api_key: str = Header(None)):
    agent_id = verify_token(x_api_key)
    if not agent_id or not credentials_match(agent_id, telemetry.agent_id):
        raise HTTPException(status_code=403, detail="Invalid or mismatched API token")

    system_info = telemetry.data.get("system", {})
    capabilities = system_info.get("capabilities", []) if isinstance(system_info, dict) else []
    agent_version = system_info.get("agent_version") if isinstance(system_info, dict) else None
    try:
        if telemetry.event_type in {"command_result", "session_event"}:
            command_id = persist_command_result(agent_id, telemetry.data)
            return {"status": "stored", "command_id": command_id}
        with closing(get_db_conn()) as conn:
            with conn:
                with conn.cursor() as cur:
                    if "persistent_session_v1" in capabilities:
                        cur.execute(
                            "UPDATE agents SET last_seen = CURRENT_TIMESTAMP, agent_version = %s, session_capable = TRUE "
                            "WHERE agent_id = %s",
                            (str(agent_version or "unknown")[:64], agent_id),
                        )
                    else:
                        cur.execute(
                            "UPDATE agents SET last_seen = CURRENT_TIMESTAMP WHERE agent_id = %s",
                            (agent_id,),
                        )
        r.lpush("telemetry_queue", telemetry.model_dump_json())
    except (psycopg2.Error, redis.RedisError):
        logger.exception("Telemetry ingestion dependency failed")
        raise HTTPException(status_code=503, detail="Telemetry service unavailable") from None
    return {"status": "queued"}


@app.post("/send-command")
async def send_command(cmd: CommandRequest, x_api_key: str = Header(None)):
    if not credentials_match(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    if not REMOTE_COMMANDS_ENABLED:
        raise HTTPException(status_code=503, detail="Remote command execution is disabled")
    try:
        if not agent_is_enrolled(cmd.agent_id):
            raise HTTPException(status_code=404, detail="Agent not found")
        r.lpush(f"commands:{cmd.agent_id}", cmd.command)
    except psycopg2.Error:
        logger.exception("Command authorization lookup failed")
        raise HTTPException(status_code=503, detail="Command service unavailable") from None
    except redis.RedisError:
        logger.exception("Command queue unavailable")
        raise HTTPException(status_code=503, detail="Command service unavailable") from None
    logger.warning("Remote command queued for agent_id=%s", cmd.agent_id)
    return {"status": "command_queued", "agent": cmd.agent_id}


def get_agent_last_seen(agent_id: str):
    try:
        with closing(get_db_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT last_seen FROM agents WHERE agent_id = %s", (agent_id,))
                row = cur.fetchone()
    except psycopg2.Error:
        logger.exception("Agent status lookup failed")
        raise HTTPException(status_code=503, detail="Agent status unavailable") from None
    return row[0] if row else None


@app.get("/agents/{agent_id}/status")
def agent_status(agent_id: str, x_api_key: str = Header(None)):
    verified_id = verify_token(x_api_key)
    if not verified_id or not credentials_match(verified_id, agent_id):
        raise HTTPException(status_code=403, detail="Invalid or mismatched API token")
    last_seen = get_agent_last_seen(agent_id)
    if last_seen is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent_id": agent_id,
        "status": "registered",
        "last_seen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else None,
    }


def get_command_results(agent_id: str, limit: int):
    with closing(get_db_conn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT command_id, received_at, status, output "
                "FROM command_results WHERE agent_id = %s "
                "ORDER BY received_at DESC, result_id DESC LIMIT %s",
                (agent_id, limit),
            )
            return cur.fetchall()


@app.get("/admin/agents")
def admin_agents(x_api_key: str = Header(None)):
    if not credentials_match(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    try:
        with closing(get_db_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT agent_id, hostname, os, last_seen, agent_version, session_capable "
                    "FROM agents ORDER BY last_seen DESC"
                )
                rows = cur.fetchall()
    except psycopg2.Error:
        logger.exception("Agent list lookup failed")
        raise HTTPException(status_code=503, detail="Agent registry unavailable") from None
    return {"agents": [
        {"agent_id": row[0], "hostname": row[1], "os": row[2], "last_seen": row[3].isoformat() if row[3] else None,
         "agent_version": row[4], "session_capable": bool(row[5])}
        for row in rows
    ]}


@app.post("/sessions")
def open_session(request: SessionStartRequest, x_api_key: str = Header(None)):
    if not credentials_match(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    if not REMOTE_COMMANDS_ENABLED:
        raise HTTPException(status_code=503, detail="Remote command execution is disabled")
    if not agent_is_enrolled(request.agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    if not agent_session_capable(request.agent_id):
        raise HTTPException(status_code=409, detail="Agent must be upgraded before opening a session")
    session_id = secrets.token_urlsafe(18)
    try:
        with closing(get_db_conn()) as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE command_sessions SET status = 'expired', closed_at = CURRENT_TIMESTAMP "
                        "WHERE agent_id = %s AND status IN ('starting', 'active', 'closing') "
                        "AND last_activity < CURRENT_TIMESTAMP - (%s * INTERVAL '1 second')",
                        (request.agent_id, SESSION_IDLE_TIMEOUT_SECONDS),
                    )
                    cur.execute(
                        "SELECT session_id FROM command_sessions WHERE agent_id = %s "
                        "AND status IN ('starting', 'active', 'closing') LIMIT 1",
                        (request.agent_id,),
                    )
                    if cur.fetchone():
                        raise HTTPException(status_code=409, detail="Agent already has an active session")
                    cur.execute(
                        "INSERT INTO command_sessions (session_id, agent_id, status) VALUES (%s, %s, 'starting')",
                        (session_id, request.agent_id),
                    )
        r.lpush("commands:" + request.agent_id, json.dumps({
            "kind": "session", "action": "open", "session_id": session_id
        }))
    except HTTPException:
        raise
    except psycopg2.Error:
        logger.exception("Session creation failed")
        raise HTTPException(status_code=503, detail="Session store unavailable") from None
    except redis.RedisError:
        logger.exception("Session open command could not be queued")
        raise HTTPException(status_code=503, detail="Agent command queue unavailable") from None
    return {"session_id": session_id, "agent_id": request.agent_id, "status": "starting"}


@app.post("/sessions/{session_id}/input")
def send_session_input(session_id: str, request: SessionInputRequest, x_api_key: str = Header(None)):
    if not credentials_match(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    if not REMOTE_COMMANDS_ENABLED:
        raise HTTPException(status_code=503, detail="Remote command execution is disabled")
    if "\n" in request.command or "\r" in request.command:
        raise HTTPException(status_code=422, detail="Session input must be a single line")
    try:
        with closing(get_db_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT agent_id, status FROM command_sessions WHERE session_id = %s", (session_id,))
                row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found")
        agent_id, status = row
        if status != "active":
            raise HTTPException(status_code=409, detail="Session is not active")
        command_id = secrets.token_hex(12)
        r.lpush("commands:" + agent_id, json.dumps({
            "kind": "session", "action": "input", "session_id": session_id,
            "command_id": command_id, "command": request.command
        }))
        with closing(get_db_conn()) as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE command_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = %s",
                        (session_id,),
                    )
    except HTTPException:
        raise
    except psycopg2.Error:
        logger.exception("Session input lookup failed")
        raise HTTPException(status_code=503, detail="Session store unavailable") from None
    except redis.RedisError:
        logger.exception("Session input could not be queued")
        raise HTTPException(status_code=503, detail="Agent command queue unavailable") from None
    return {"session_id": session_id, "command_id": command_id, "status": "queued"}


@app.get("/sessions/{session_id}")
def get_session(session_id: str, x_api_key: str = Header(None), after_id: int = Query(0, ge=0)):
    if not credentials_match(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    try:
        with closing(get_db_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT session_id, agent_id, status, created_at, last_activity "
                    "FROM command_sessions WHERE session_id = %s",
                    (session_id,),
                )
                session = cur.fetchone()
                if not session:
                    raise HTTPException(status_code=404, detail="Session not found")
                cur.execute(
                    "SELECT result_id, command_id, received_at, status, output FROM command_results "
                    "WHERE session_id = %s AND result_id > %s ORDER BY result_id ASC LIMIT 100",
                    (session_id, after_id),
                )
                rows = cur.fetchall()
    except HTTPException:
        raise
    except psycopg2.Error:
        logger.exception("Session state lookup failed")
        raise HTTPException(status_code=503, detail="Session store unavailable") from None
    return {
        "session_id": session[0], "agent_id": session[1], "status": session[2],
        "created_at": session[3].isoformat() if session[3] else None,
        "last_activity": session[4].isoformat() if session[4] else None,
        "events": [
            {"result_id": row[0], "command_id": row[1], "received_at": row[2].isoformat() if row[2] else None,
             "status": row[3], "output": row[4][:MAX_COMMAND_RESULT_OUTPUT]}
            for row in rows
        ],
    }


@app.delete("/sessions/{session_id}")
def close_session(session_id: str, x_api_key: str = Header(None)):
    if not credentials_match(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    try:
        with closing(get_db_conn()) as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT agent_id, status FROM command_sessions WHERE session_id = %s", (session_id,))
                    row = cur.fetchone()
                    if not row:
                        raise HTTPException(status_code=404, detail="Session not found")
                    agent_id, status = row
                    if status not in {"closed", "expired", "error"}:
                        cur.execute(
                            "UPDATE command_sessions SET status = 'closing', last_activity = CURRENT_TIMESTAMP WHERE session_id = %s",
                            (session_id,),
                        )
        if status not in {"closed", "expired", "error"}:
            r.lpush("commands:" + agent_id, json.dumps({
                "kind": "session", "action": "close", "session_id": session_id
            }))
    except HTTPException:
        raise
    except psycopg2.Error:
        logger.exception("Session close lookup failed")
        raise HTTPException(status_code=503, detail="Session store unavailable") from None
    except redis.RedisError:
        logger.exception("Session close could not be queued")
        raise HTTPException(status_code=503, detail="Agent command queue unavailable") from None
    return {"session_id": session_id, "status": "closing"}


@app.get("/command-results/{agent_id}")
def command_results(
    agent_id: str,
    x_api_key: str = Header(None),
    limit: int = Query(20, ge=1, le=100),
):
    if not credentials_match(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    try:
        if not agent_is_enrolled(agent_id):
            raise HTTPException(status_code=404, detail="Agent not found")
        rows = get_command_results(agent_id, limit)
    except HTTPException:
        raise
    except psycopg2.Error:
        logger.exception("Command-result lookup failed")
        raise HTTPException(status_code=503, detail="Command-result store unavailable") from None

    records = []
    for command_id, received_at, status, output in rows:
        records.append({
            "agent_id": agent_id,
            "command_id": command_id,
            "received_at": received_at.isoformat() if received_at else None,
            "status": status,
            "output": output[:MAX_COMMAND_RESULT_OUTPUT],
        })
    return {"agent_id": agent_id, "count": len(records), "results": records}


@app.get("/commands/{agent_id}")
async def get_command(agent_id: str, x_api_key: str = Header(None)):
    verified_id = verify_token(x_api_key)
    if not verified_id or not credentials_match(verified_id, agent_id):
        raise HTTPException(status_code=403, detail="Invalid or mismatched API token")
    if not REMOTE_COMMANDS_ENABLED:
        return {"command": None}
    try:
        command = r.rpop(f"commands:{agent_id}")
    except redis.RedisError:
        logger.exception("Command queue unavailable")
        raise HTTPException(status_code=503, detail="Command service unavailable") from None
    return {"command": command}