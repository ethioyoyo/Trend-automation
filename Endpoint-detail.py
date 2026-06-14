import requests
import json
import os

BASE_URL = "https://api.xdr.trendmicro.com"
TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiI5YTU3NDQzOS0wYjYyLTQ2YzEtODkxNC1hMzUyMGY4MTY0MDUiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzc3ODIzNDIyLCJldCI6MTc4NTU5OTQyMSwiaWQiOiJhZGI5MDQ4MC1kNjRjLTRlM2QtOTZiYy0xYmNiNWQ2YjM4YmUiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.ZsE3hj6R38_DUqlN2oiVXfUoPuJVcDEuXWHubTAiObHTdSZqlQLOBPtIIGABJwASKS_uR8P97S7u02ItwBLcIz60EMq5epKcnUPkOYXTI3x-tJ-6rj_DgEE_sie0llRClWqZoo3MQTNIYV3EWsgEJ7aXhzeNTMy1uz4glZQJmsCtIMUwPCAanobqtbznLmjMk0RIiKczJbqFESBLQ61W-RbR07LXrKjrNidVdOx3iInApO9kuBgjvHPtfEOGsOjMga_d_VI6K9JQX9Q2FuDBh6PjyZa_mGuv0p7TaTCx5uSDaESTnvIwjzb06q1iHvk_oGsEsQN1FRUBoxdQBPyRDgpTzCX-FPqkIFllYmu5RA91SjybdAhC_NRJBdvJfZK11QRHRRw6kK1hdx6etollxHxJHMSIgjUkHELmRsBpO0rzsKsfLj8bGDRsOvtLvZbbFj_eZcYtnRmLOrZ9jFjCXDFcly1svz7DP7RSq3CBkkMyb4pxJnHL5r0oAPX3ib5KDfQxE02dvvXw-UXhOxZle9rxgTk0MtuEx0nKwzzYxixPnap2zipRYx-KmO9jR0jWs3V8dQgJa8ZhEL5LnbV8i_4dNVfZuxBAZYN2a9zMjA-e5_FzCNouQKgO9luGDH0n_omKSx9z4uaZ6n8Denin_Hzp-9ulJt_D8a_dJdAzlJQ'
id = "dfe1f3a0-2866-8708-29fc-c18c1aab79ef"  # REPLACE with actual endpoint ID

url = f"{BASE_URL}/v3.0/endpointSecurity/endpoints/{id}"

params = {}

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}

r = requests.get(url, params=params, headers=headers)

if r.status_code != 200:
    print("Error:", r.status_code)
    print(r.text)
    exit()
data = r.json()
print(f"data: {data}")