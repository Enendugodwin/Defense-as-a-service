import requests
import psutil
import socket
import platform
import time
import json
import os
import subprocess
import threading

# Config
API_URL = os.environ.get("API_URL", "").rstrip("/")
REGISTRATION_TOKEN = os.environ.get("REGISTRATION_TOKEN", "")
TOKEN_FILE = os.environ.get("AGENT_TOKEN_FILE", "agent.token")
TELEMETRY_INTERVAL = 60
COMMAND_POLL_INTERVAL = 5

def collect_telemetry():
    sys_info = {
        'hostname': socket.gethostname(),
        'os': platform.system(),
        'os_release': platform.release(),
        'cpu_usage': psutil.cpu_percent(interval=1),
        'memory_usage': psutil.virtual_memory().percent
    }
    processes = []
    for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'memory_percent']),
                      key=lambda x: x.info['memory_percent'], reverse=True)[:5]:
        processes.append(proc.info)
    return {'system': sys_info, 'top_processes': processes}

def telemetry_loop(agent_id, token):
    while True:
        data = collect_telemetry()
        payload = {'agent_id': agent_id, 'event_type': 'endpoint_telemetry', 'data': data}
        headers = {'x-api-key': token}
        try:
            requests.post(f'{API_URL}/ingest', json=payload, headers=headers)
        except Exception as e:
            print(f'Transmission error: {e}')
        time.sleep(TELEMETRY_INTERVAL)

def command_loop(agent_id, token):
    print(f'📡 Command listener active for {agent_id}...')
    while True:
        try:
            headers = {'x-api-key': token}
            response = requests.get(f'{API_URL}/commands/{agent_id}', headers=headers)
            if response.status_code == 200:
                cmd_data = response.json()
                command = cmd_data.get('command')
                if command:
                    print(f'📩 Received command: {command}')
                    try:
                        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
                        output = result.stdout if result.stdout else result.stderr
                        status = result.returncode
                    except Exception as e:
                        output = str(e)
                        status = -1

                    print(f'✅ Command executed. Sending result...')
                    payload = {'agent_id': agent_id, 'event_type': 'command_result', 'data': {'command': command, 'output': output, 'status': status}}
                    requests.post(f'{API_URL}/ingest', json=payload, headers=headers)
        except Exception as e:
            print(f'Polling error: {e}')
        time.sleep(COMMAND_POLL_INTERVAL)

if __name__ == '__main__':
    if not API_URL:
        raise SystemExit('Set API_URL before starting the agent.')
    # Load or enroll
    token_data = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            try:
                token_data = json.load(f)
            except json.JSONDecodeError:
                token_data = None

    if not token_data:
        if not REGISTRATION_TOKEN:
            raise SystemExit("Set REGISTRATION_TOKEN before enrolling this agent.")
        print('🔐 No token found. Enrolling...')
        payload = {
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'registration_token': REGISTRATION_TOKEN
        }
        try:
            response = requests.post(f'{API_URL}/enroll', json=payload)
            if response.status_code == 200:
                token_data = response.json()
                with open(TOKEN_FILE, 'w') as f:
                    json.dump(token_data, f)
                print(f'✅ Enrolled successfully. Agent ID: {token_data[agent_id]}')
            else:
                print(f'❌ Enrollment failed: {response.text}')
                exit(1)
        except Exception as e:
            print(f'❌ Enrollment error: {e}')
            exit(1)

    agent_id = token_data['agent_id']
    token = token_data['token']

    print(f'🚀 Agent {agent_id} started. (Telemetry: {TELEMETRY_INTERVAL}s, Poll: {COMMAND_POLL_INTERVAL}s)')

    t = threading.Thread(target=telemetry_loop, args=(agent_id, token), daemon=True)
    t.start()

    command_loop(agent_id, token)
