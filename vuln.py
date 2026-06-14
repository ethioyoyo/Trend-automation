import requests
import json
import sys

# ─── Configuration ────────────────────────────────────────────────────────────
url_base = "https://api.xdr.trendmicro.com"   # e.g. https://api.xdr.trendmicro.com
token       = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiI5YTU3NDQzOS0wYjYyLTQ2YzEtODkxNC1hMzUyMGY4MTY0MDUiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzc3ODIzNDIyLCJldCI6MTc4NTU5OTQyMSwiaWQiOiJhZGI5MDQ4MC1kNjRjLTRlM2QtOTZiYy0xYmNiNWQ2YjM4YmUiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.ZsE3hj6R38_DUqlN2oiVXfUoPuJVcDEuXWHubTAiObHTdSZqlQLOBPtIIGABJwASKS_uR8P97S7u02ItwBLcIz60EMq5epKcnUPkOYXTI3x-tJ-6rj_DgEE_sie0llRClWqZoo3MQTNIYV3EWsgEJ7aXhzeNTMy1uz4glZQJmsCtIMUwPCAanobqtbznLmjMk0RIiKczJbqFESBLQ61W-RbR07LXrKjrNidVdOx3iInApO9kuBgjvHPtfEOGsOjMga_d_VI6K9JQX9Q2FuDBh6PjyZa_mGuv0p7TaTCx5uSDaESTnvIwjzb06q1iHvk_oGsEsQN1FRUBoxdQBPyRDgpTzCX-FPqkIFllYmu5RA91SjybdAhC_NRJBdvJfZK11QRHRRw6kK1hdx6etollxHxJHMSIgjUkHELmRsBpO0rzsKsfLj8bGDRsOvtLvZbbFj_eZcYtnRmLOrZ9jFjCXDFcly1svz7DP7RSq3CBkkMyb4pxJnHL5r0oAPX3ib5KDfQxE02dvvXw-UXhOxZle9rxgTk0MtuEx0nKwzzYxixPnap2zipRYx-KmO9jR0jWs3V8dQgJa8ZhEL5LnbV8i_4dNVfZuxBAZYN2a9zMjA-e5_FzCNouQKgO9luGDH0n_omKSx9z4uaZ6n8Denin_Hzp-9ulJt_D8a_dJdAzlJQ"
url_path = "/v3.0/asrm/vulnerableDevices"
 
 
query_params = {
    'top': 200,
    'cveDetectionStatus': 'detected',
}
headers = {
    'Authorization': 'Bearer ' + token,
}
 
r = requests.get(url_base + url_path, params=query_params, headers=headers)
print(f"HTTP {r.status_code}\n")
 
if r.status_code != 200:
    print(r.text)
    exit(1)
 
body  = r.json()
items = body.get('items', [])
print(f"Total records: {len(items)}\n")
 
# Show ALL field names found across every record
all_keys = sorted({k for item in items for k in item.keys()})
print("=== FIELD NAMES IN RESPONSE ===")
for k in all_keys:
    print(f"  {k}")
print()
 
# For each record print a compact summary
print("=== RECORD SUMMARIES ===")
for i, item in enumerate(items, 1):
    print(f"\n--- Record {i} ---")
    # Print every field and its value (truncate long lists)
    for k, v in item.items():
        if isinstance(v, list):
            print(f"  {k}: [{len(v)} items] {str(v[:2])[:120]}...")
        elif isinstance(v, dict):
            print(f"  {k}: {str(v)[:120]}")
        else:
            print(f"  {k}: {v}")
 
print("\n=== RAW JSON (full) ===")
print(json.dumps(items, indent=2))
 