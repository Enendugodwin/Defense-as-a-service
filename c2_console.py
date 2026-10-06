import hashlib
import requests
import psycopg2
import os

# Config
API_URL = os.environ.get("API_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "")
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "database": os.environ["POSTGRES_DB"],
    "user": os.environ["POSTGRES_USER"],
    "password": os.environ["POSTGRES_PASSWORD"]
}

def list_agents():
    print("\n--- Connected Agents ---")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute('SELECT agent_id, hostname, os, last_seen FROM agents')
        rows = cur.fetchall()
        print(f"{'Agent ID':<20} | {'Hostname':<20} | {'OS':<10} | {'Last Seen'}")
        print("-" * 70)
        for row in rows:
            print(f"{row[0]:<20} | {row[1]:<20} | {row[2]:<10} | {row[3]}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error fetching agents: {e}")

def send_command():
    if not ADMIN_KEY:
        print("Set ADMIN_API_KEY before sending commands.")
        return
    agent_id = input("\nEnter Target Agent ID: ").strip()
    command = input("Enter Command to execute: ").strip()
    if not agent_id or not command:
        print("Agent ID and command are required.")
        return
    command_id = hashlib.sha256(command.encode("utf-8")).hexdigest()[:16]

    payload = {'agent_id': agent_id, 'command': command}
    headers = {'x-api-key': ADMIN_KEY}

    try:
        r = requests.post(f'{API_URL}/send-command', json=payload, headers=headers)
        if r.status_code == 200:
            print(f"Command queued for {agent_id}. Result ID: {command_id}")
        else:
            print(f"Failed to send command: {r.text}")
    except Exception as e:
        print(f"Connection error: {e}")

def list_command_results():
    if not ADMIN_KEY:
        print("Set ADMIN_API_KEY before querying command results.")
        return
    agent_id = input("\nEnter Agent ID: ").strip()
    if not agent_id:
        print("Agent ID is required.")
        return
    raw_limit = input("Maximum results [20]: ").strip()
    try:
        limit = int(raw_limit) if raw_limit else 20
    except ValueError:
        print("Result limit must be an integer.")
        return
    if not 1 <= limit <= 100:
        print("Result limit must be between 1 and 100.")
        return

    try:
        response = requests.get(
            f"{API_URL}/command-results/{agent_id}",
            headers={"x-api-key": ADMIN_KEY},
            params={"limit": limit},
            timeout=(5, 15),
        )
        if response.status_code != 200:
            print(f"Result query failed: HTTP {response.status_code}")
            return
        results = response.json().get("results", [])
    except requests.RequestException as exc:
        print(f"Result query failed: {type(exc).__name__}")
        return
    except ValueError:
        print("Result query returned invalid JSON.")
        return

    if not results:
        print("No command results found for this agent.")
        return
    for item in results:
        print(f"\n[{item.get('received_at')}] result={item.get('command_id')} exit={item.get('status')}")
        output = item.get("output") or "(no output)"
        if len(output) > 10000:
            print(output[:10000] + "\n... display truncated; stored result remains in PostgreSQL.")
        else:
            print(output)


def main():
    while True:
        print("\n Defensive Platform C2 Console")
        print("1. List Agents")
        print("2. Send Command")
        print("3. View Command Results")
        print("4. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == '1':
            list_agents()
        elif choice == '2':
            send_command()
        elif choice == '3':
            list_command_results()
        elif choice == '4':
            print("Exiting console...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == '__main__':
    main()
