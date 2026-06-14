import json
import os
import sys
import requests

BASE_URL = "https://api.xdr.trendmicro.com"
TOKEN = os.environ.get("TREND_TOKEN")
if not TOKEN:
    print("Error: TREND_TOKEN environment variable is not set.", file=sys.stderr)
    sys.exit(1)

url = f"{BASE_URL}/v3.0/asrm/attackSurfaceDevices"
params = {"top": 100}
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}

r = requests.get(url, params=params, headers=headers, timeout=30)
if r.status_code != 200:
    print(f"Error: {r.status_code}", file=sys.stderr)
    print(r.text, file=sys.stderr)
    sys.exit(1)



data = r.json()
print(json.dumps(data, indent=2))
rows = []
for device in data.get("items", []):
    agent_id        = device.get("id", "N/A")
    name            = device.get("deviceName", "N/A")
    criticality     = device.get("criticality", "N/A")
    ip              = device.get("ip", []),
    tags            = device.get("assetCustomTags", [])
