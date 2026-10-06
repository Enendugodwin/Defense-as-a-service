from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import redis
import json
import os
import psycopg2
from psycopg2 import sql
import secrets
from datetime import datetime

app = FastAPI()

# Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ["REDIS_PASSWORD"]
DB_HOST = os.getenv("DB_HOST", "postgres")
DB_NAME = os.environ["POSTGRES_DB"]
DB_USER = os.environ["POSTGRES_USER"]
DB_PASS = os.environ["POSTGRES_PASSWORD"]
REGISTRATION_TOKEN = os.environ["REGISTRATION_TOKEN"]
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")

# Initialize Redis
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

# DB Connection Helper
def get_db_conn():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

# Initialize DB Table
@app.on_event('startup')
def startup_event():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            os TEXT,
            token TEXT UNIQUE,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

class Telemetry(BaseModel):
    agent_id: str
    event_type: str
    data: dict

class CommandRequest(BaseModel):
    agent_id: str
    command: str

class EnrollmentRequest(BaseModel):
    hostname: str
    os: str
    registration_token: str

def verify_token(token: str):
    if not token:
        return None
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('SELECT agent_id FROM agents WHERE token = %s', (token,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    return result[0] if result else None

@app.get('/health')
def health():
    return {'status': 'online'}

@app.post('/enroll')
async def enroll(req: EnrollmentRequest):
    if req.registration_token != REGISTRATION_TOKEN:
        raise HTTPException(status_code=403, detail='Invalid registration token')

    agent_id = secrets.token_hex(8)
    token = secrets.token_urlsafe(32)

    conn = get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO agents (agent_id, hostname, os, token) VALUES (%s, %s, %s, %s)',
            (agent_id, req.hostname, req.os, token)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

    return {'agent_id': agent_id, 'token': token}

@app.post('/ingest')
async def ingest(telemetry: Telemetry, x_api_key: str = Header(None)):
    agent_id = verify_token(x_api_key)
    if not agent_id or agent_id != telemetry.agent_id:
        raise HTTPException(status_code=403, detail='Invalid or mismatched API Token')

    # Update last seen
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('UPDATE agents SET last_seen = %s WHERE agent_id = %s', (datetime.now(), agent_id))
    conn.commit()
    cur.close()
    conn.close()

    r.lpush('telemetry_queue', telemetry.json())
    return {'status': 'queued'}

@app.post('/send-command')
async def send_command(cmd: CommandRequest, x_api_key: str = Header(None)):
    if not ADMIN_API_KEY or x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail='Invalid Admin Key')

    r.lpush(f'commands:{cmd.agent_id}', cmd.command)
    return {'status': 'command_queued', 'agent': cmd.agent_id}

@app.get('/commands/{agent_id}')
async def get_command(agent_id: str, x_api_key: str = Header(None)):
    verified_id = verify_token(x_api_key)
    if not verified_id or verified_id != agent_id:
        raise HTTPException(status_code=403, detail='Invalid or mismatched API Token')

    cmd = r.rpop(f'commands:{agent_id}')
    if cmd:
        return {'command': cmd}
    return {'command': None}
