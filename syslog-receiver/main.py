import socket
import redis
import os
import json

# Config
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASS = os.environ["REDIS_PASSWORD"]
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))

# Initialize Redis
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS, decode_responses=True)

# Initialize UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', SYSLOG_PORT))

print(f'📡 Syslog Receiver listening on UDP port {SYSLOG_PORT}...')

while True:
    try:
        data, addr = sock.recvfrom(4096)
        message = data.decode('utf-8', errors='ignore').strip()

        payload = {
            'agent_id': addr[0],
            'event_type': 'syslog',
            'data': {
                'raw_message': message,
                'source_ip': addr[0],
                'source_port': addr[1]
            }
        }

        r.lpush('telemetry_queue', json.dumps(payload))
        print(f'Received syslog from {addr[0]}')

    except Exception as e:
        print(f'Error processing syslog: {e}')
