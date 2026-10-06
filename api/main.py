import logging
import os
import secrets
from contextlib import closing
from datetime import datetime
from typing import Any, Dict

import psycopg2
import redis
from fastapi import FastAPI, Header, HTTPException
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
REDIS_PASSWORD = required_secret("REDIS_PASSWORD", 16)
DB_HOST = os.getenv("DB_HOST", "postgres")
DB_NAME = os.environ["POSTGRES_DB"]
DB_USER = os.environ["POSTGRES_USER"]
DB_PASS = required_secret("POSTGRES_PASSWORD", 16)
REGISTRATION_TOKEN = required_secret("REGISTRATION_TOKEN", 32)
ADMIN_API_KEY = required_secret("ADMIN_API_KEY", 32)
REMOTE_COMMANDS_ENABLED = env_flag("REMOTE_COMMANDS_ENABLED", True)
API_DOCS_ENABLED = env_flag("API_DOCS_ENABLED", False)
DB_CONNECT_TIMEOUT = max(1, int(os.getenv("DB_CONNECT_TIMEOUT", "5")))

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
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )"""
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
        r.ping()
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


@app.post("/ingest")
async def ingest(telemetry: Telemetry, x_api_key: str = Header(None)):
    agent_id = verify_token(x_api_key)
    if not agent_id or not credentials_match(agent_id, telemetry.agent_id):
        raise HTTPException(status_code=403, detail="Invalid or mismatched API token")

    try:
        with closing(get_db_conn()) as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE agents SET last_seen = %s WHERE agent_id = %s",
                        (datetime.utcnow(), agent_id),
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