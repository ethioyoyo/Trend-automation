import requests
import json

BASE_URL = 'https://app.deepsecurity.trendmicro.com/api'
API_KEY  = '8BEC6851-96F0-D7D3-5002-C1062BC9E89C:CB77AF3B-16F2-F519-1E61-AFF9B2B2CF46:qKhC1TxhgCVVze6qISiL2oJq1f9GcEz+KJH2iBVUVBE='

headers = {
    'api-secret-key': API_KEY,
    'api-version': 'v1',
    'Content-Type': 'application/json'
}

r = requests.get(f'{BASE_URL}/policies', headers=headers)

if r.ok:
    policies = r.json()
    print(f"{'Policy Name':<40} {'Setting Key':<50} {'Value'}")
    print("-" * 110)
    for p in policies.get('policies', []):
        name = p.get('name', 'N/A')
        settings = p.get('policySettings', {})
        for key, val in settings.items():
            value = val.get('value', '') if isinstance(val, dict) else val
            print(f"{name:<40} {key:<50} {value}")
else:
    print(f"Error {r.status_code}: {r.text}")