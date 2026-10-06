import redis
import os
import json
import time
from datetime import datetime, timezone
from opensearchpy import OpenSearch

REDIS_PASS = os.environ["REDIS_PASSWORD"]
OS_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
OS_PASS = os.environ["OPENSEARCH_PASSWORD"]
OS_USER = os.getenv("OPENSEARCH_USER", "admin")

r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=int(os.getenv("REDIS_PORT", "6379")), password=REDIS_PASS, decode_responses=True)
client = OpenSearch(
    hosts=[{'host': OS_HOST, 'port': 9200}],
    http_auth=(OS_USER, OS_PASS),
    use_ssl=True,
    verify_certs=os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true",
    ssl_show_warn=False
)

print('🚀 Log Processor Started. Waiting for telemetry...')

while True:
    try:
        result = r.brpop('telemetry_queue')
        if result:
            _, message = result
            data = json.loads(message)
            if not isinstance(data, dict):
                raise ValueError("Telemetry event must be a JSON object")
            data.setdefault("received_at", datetime.now(timezone.utc).isoformat())
            if data.get("event_type") == "command_result" and isinstance(data.get("data"), dict):
                output = data["data"].get("output")
                if isinstance(output, str) and len(output) > 32768:
                    data["data"]["output"] = output[:32768]
            date_str = time.strftime('%Y.%m.%d')
            index_name = f'telemetry-{date_str}'
            client.index(index=index_name, body=data)
            print(f'Indexed event from {data.get("agent_id")}')
    except Exception as e:
        print(f'Error: {e}')
        time.sleep(1)
