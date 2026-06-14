import requests
import json
import os
from datetime import datetime, timedelta

#BASE_URL = "https://api.xdr.trendmicro.com"
TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiI5YTU3NDQzOS0wYjYyLTQ2YzEtODkxNC1hMzUyMGY4MTY0MDUiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzc3ODIzNDIyLCJldCI6MTc4NTU5OTQyMSwiaWQiOiJhZGI5MDQ4MC1kNjRjLTRlM2QtOTZiYy0xYmNiNWQ2YjM4YmUiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.ZsE3hj6R38_DUqlN2oiVXfUoPuJVcDEuXWHubTAiObHTdSZqlQLOBPtIIGABJwASKS_uR8P97S7u02ItwBLcIz60EMq5epKcnUPkOYXTI3x-tJ-6rj_DgEE_sie0llRClWqZoo3MQTNIYV3EWsgEJ7aXhzeNTMy1uz4glZQJmsCtIMUwPCAanobqtbznLmjMk0RIiKczJbqFESBLQ61W-RbR07LXrKjrNidVdOx3iInApO9kuBgjvHPtfEOGsOjMga_d_VI6K9JQX9Q2FuDBh6PjyZa_mGuv0p7TaTCx5uSDaESTnvIwjzb06q1iHvk_oGsEsQN1FRUBoxdQBPyRDgpTzCX-FPqkIFllYmu5RA91SjybdAhC_NRJBdvJfZK11QRHRRw6kK1hdx6etollxHxJHMSIgjUkHELmRsBpO0rzsKsfLj8bGDRsOvtLvZbbFj_eZcYtnRmLOrZ9jFjCXDFcly1svz7DP7RSq3CBkkMyb4pxJnHL5r0oAPX3ib5KDfQxE02dvvXw-UXhOxZle9rxgTk0MtuEx0nKwzzYxixPnap2zipRYx-KmO9jR0jWs3V8dQgJa8ZhEL5LnbV8i_4dNVfZuxBAZYN2a9zMjA-e5_FzCNouQKgO9luGDH0n_omKSx9z4uaZ6n8Denin_Hzp-9ulJt_D8a_dJdAzlJQ'

# url = f"{BASE_URL}/v3.0/workbench/insights"



# headers = {
#     "Authorization": f"Bearer {TOKEN}",
#     "Content-Type": "application/json"
# }

# alert_id = "WB-57957-20260417-00098"
# url = f"{BASE_URL}/v3.0/workbench/alerts/{alert_id}"


# r = requests.get(url, headers=headers)

# print("Status:", r.status_code)

# try:
#     print(json.dumps(r.json(), indent=4))
# except:
#     print(r.text)

# query_params = {
#     'orderBy': 'YOUR_ORDERBY (string)',
#     'top': 'YOUR_TOP (integer)',
#     'lastDetectedStartDateTime': 'YOUR_LASTDETECTEDSTARTDATETIME (string)',
#     'lastDetectedEndDateTime': 'YOUR_LASTDETECTEDENDDATETIME (string)',
#     'firstSeenStartDateTime': 'YOUR_FIRSTSEENSTARTDATETIME (string)',
#     'firstSeenEndDateTime': 'YOUR_FIRSTSEENENDDATETIME (string)'
# }

url_base = "https://api.xdr.trendmicro.com"
url_path = '/v3.0/asrm/attackSurfaceDevices'
TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiI5YTU3NDQzOS0wYjYyLTQ2YzEtODkxNC1hMzUyMGY4MTY0MDUiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzc3ODIzNDIyLCJldCI6MTc4NTU5OTQyMSwiaWQiOiJhZGI5MDQ4MC1kNjRjLTRlM2QtOTZiYy0xYmNiNWQ2YjM4YmUiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.ZsE3hj6R38_DUqlN2oiVXfUoPuJVcDEuXWHubTAiObHTdSZqlQLOBPtIIGABJwASKS_uR8P97S7u02ItwBLcIz60EMq5epKcnUPkOYXTI3x-tJ-6rj_DgEE_sie0llRClWqZoo3MQTNIYV3EWsgEJ7aXhzeNTMy1uz4glZQJmsCtIMUwPCAanobqtbznLmjMk0RIiKczJbqFESBLQ61W-RbR07LXrKjrNidVdOx3iInApO9kuBgjvHPtfEOGsOjMga_d_VI6K9JQX9Q2FuDBh6PjyZa_mGuv0p7TaTCx5uSDaESTnvIwjzb06q1iHvk_oGsEsQN1FRUBoxdQBPyRDgpTzCX-FPqkIFllYmu5RA91SjybdAhC_NRJBdvJfZK11QRHRRw6kK1hdx6etollxHxJHMSIgjUkHELmRsBpO0rzsKsfLj8bGDRsOvtLvZbbFj_eZcYtnRmLOrZ9jFjCXDFcly1svz7DP7RSq3CBkkMyb4pxJnHL5r0oAPX3ib5KDfQxE02dvvXw-UXhOxZle9rxgTk0MtuEx0nKwzzYxixPnap2zipRYx-KmO9jR0jWs3V8dQgJa8ZhEL5LnbV8i_4dNVfZuxBAZYN2a9zMjA-e5_FzCNouQKgO9luGDH0n_omKSx9z4uaZ6n8Denin_Hzp-9ulJt_D8a_dJdAzlJQ'


headers = {
    'Authorization': 'Bearer ' + TOKEN,
    'Content-Type': 'application/json'
}

r = requests.get(url_base + url_path, headers=headers)

print(r.status_code)
for k, v in r.headers.items():
    print(f'{k}: {v}')
print('')
if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
    print(json.dumps(r.json(), indent=4))
else:
    print(r.text)