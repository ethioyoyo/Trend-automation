import requests
import sys
import os

BASE_URL = "https://api.xdr.trendmicro.com"
#TOKEN = os.environ.get("TREND_TOKEN")
TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiI5YTU3NDQzOS0wYjYyLTQ2YzEtODkxNC1hMzUyMGY4MTY0MDUiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzc3ODIzNDIyLCJldCI6MTc4NTU5OTQyMSwiaWQiOiJhZGI5MDQ4MC1kNjRjLTRlM2QtOTZiYy0xYmNiNWQ2YjM4YmUiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.ZsE3hj6R38_DUqlN2oiVXfUoPuJVcDEuXWHubTAiObHTdSZqlQLOBPtIIGABJwASKS_uR8P97S7u02ItwBLcIz60EMq5epKcnUPkOYXTI3x-tJ-6rj_DgEE_sie0llRClWqZoo3MQTNIYV3EWsgEJ7aXhzeNTMy1uz4glZQJmsCtIMUwPCAanobqtbznLmjMk0RIiKczJbqFESBLQ61W-RbR07LXrKjrNidVdOx3iInApO9kuBgjvHPtfEOGsOjMga_d_VI6K9JQX9Q2FuDBh6PjyZa_mGuv0p7TaTCx5uSDaESTnvIwjzb06q1iHvk_oGsEsQN1FRUBoxdQBPyRDgpTzCX-FPqkIFllYmu5RA91SjybdAhC_NRJBdvJfZK11QRHRRw6kK1hdx6etollxHxJHMSIgjUkHELmRsBpO0rzsKsfLj8bGDRsOvtLvZbbFj_eZcYtnRmLOrZ9jFjCXDFcly1svz7DP7RSq3CBkkMyb4pxJnHL5r0oAPX3ib5KDfQxE02dvvXw-UXhOxZle9rxgTk0MtuEx0nKwzzYxixPnap2zipRYx-KmO9jR0jWs3V8dQgJa8ZhEL5LnbV8i_4dNVfZuxBAZYN2a9zMjA-e5_FzCNouQKgO9luGDH0n_omKSx9z4uaZ6n8Denin_Hzp-9ulJt_D8a_dJdAzlJQ'

if not TOKEN:
    print("Error: TREND_TOKEN environment variable is not set.", file=sys.stderr)
    sys.exit(1)

url = f"{BASE_URL}/v3.0/endpointSecurity/endpoints"
params = {"top": 100}
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}

r = requests.get(url, params=params, headers=headers, timeout=30)

filename = "endpoint_list_output.txt"
with open(filename, "w") as f:
    if r.status_code != 200:
        print(f"Error: {r.status_code}", file=sys.stderr)
        print(r.text, file=sys.stderr)
        sys.exit(1)

    data = r.json()
    rows = []

    for device in data.get("items", []):
        agent_id        = device.get("agentGuid", "N/A")
        name            = device.get("endpointName", "N/A")
        ip              = device.get("lastUsedIp", "N/A")
        epp             = device.get("eppAgent", {})
        version         = epp.get("version", "N/A")
        update          = device.get("agentUpdatePolicy", "N/A")
        version_control = device.get("versionControlPolicy", "N/A")

        details = {}
        details_url = f"{BASE_URL}/v3.0/endpointSecurity/endpoints/{agent_id}"
        details_response = requests.get(details_url, headers=headers, timeout=30)
        if details_response.status_code == 200:
            details = details_response.json()

        f.write(f"##########################details_response: {details_response.status_code}, details: {details} #################\n")

        # cve_items  = []
        # cve_count  = 0
        # cve_url     = f"{BASE_URL}/v3.0/asrm/vulnerableDevices"
        # cve_headers = {**headers, "TMV1-Filter": f"(deviceName eq '{name}')"}
        # cve_response = requests.get(cve_url, headers=cve_headers, params={"top": 50}, timeout=30)
        # if cve_response.status_code == 200:
        #     cve_details = cve_response.json()
        #     cve_items   = cve_details.get("items", [])
        #     cve_count   = len(cve_items)

        # rows.append({
        #     "agent_id":       agent_id,
        #     "name":           name,
        #     "ip":             ip,
        #     "version":        version,
        #     "update":         update,
        #     "version_control": version_control,
        #     "details":        details,
        #     "cve_items":      cve_items,
        #     "cve_count":      cve_count,
        # })  

# if r.status_code != 200:
#     print(f"Error: {r.status_code}", file=sys.stderr)
#     print(r.text, file=sys.stderr)
#     sys.exit(1)

# data = r.json()
# rows = []

# for device in data.get("items", []):
#     agent_id = device.get("agentGuid", "N/A")
#     name = device.get("endpointName", "N/A")
#     ip = device.get("lastUsedIp", "N/A")
#     epp = device.get("eppAgent", {})
#     version = epp.get("version", "N/A")
#     update = device.get("agentUpdatePolicy", "N/A")
#     version_control = device.get("versionControlPolicy", "N/A")

#     details = {}
#     details_url = f"{BASE_URL}/v3.0/endpointSecurity/endpoints/{agent_id}"
#     details_response = requests.get(details_url, headers=headers, timeout=30)
#     if details_response.status_code == 200:
#         details = details_response.json()
#         eppAgent = details.get("eppAgent", {})
#  #       tags = eppAgent.get("tags", [])

#         print(f"details_response: {details_response.status_code}, details: {eppAgent}")

    
# #    print(f"details_response: {details_response.status_code}, details: {details}")
# #    print(f"{name} - {ip} - {update} - {version} - {version_control} - tags: {tags}")

#     cve_details = {}
#     cve_url = f"{BASE_URL}/v3.0/asrm/vulnerableDevices"
#     param = {}
#     cve_headers = {
#         "Authorization": f"Bearer {TOKEN}",
#         "Content-Type": "application/json",
#         "TMV1-Filter": f"(id eq '{agent_id}')"
#     }
#     cve_response = requests.get(cve_url, headers=cve_headers, timeout=30)
#     if cve_response.status_code == 200:
#         cve_details = cve_response.json()
#         details["vulnerabilities"] = cve_details.get("items", [])

#     print(f"{agent_id:<36} {name:<30} {ip:<15} {version:<20} {update:<20} {version_control:<20}")
# #    print(f"{name}  cve_response: {cve_response.status_code}, details_response: {details_response.status_code},cve_details: {cve_details.get('items', [])}")

