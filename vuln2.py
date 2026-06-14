import requests
import json
import sys

# ─── Configuration ────────────────────────────────────────────────────────────
REGION_FQDN = "https://api.xdr.trendmicro.com"   # e.g. https://api.xdr.trendmicro.com
TOKEN       = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiI5YTU3NDQzOS0wYjYyLTQ2YzEtODkxNC1hMzUyMGY4MTY0MDUiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzc3ODIzNDIyLCJldCI6MTc4NTU5OTQyMSwiaWQiOiJhZGI5MDQ4MC1kNjRjLTRlM2QtOTZiYy0xYmNiNWQ2YjM4YmUiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.ZsE3hj6R38_DUqlN2oiVXfUoPuJVcDEuXWHubTAiObHTdSZqlQLOBPtIIGABJwASKS_uR8P97S7u02ItwBLcIz60EMq5epKcnUPkOYXTI3x-tJ-6rj_DgEE_sie0llRClWqZoo3MQTNIYV3EWsgEJ7aXhzeNTMy1uz4glZQJmsCtIMUwPCAanobqtbznLmjMk0RIiKczJbqFESBLQ61W-RbR07LXrKjrNidVdOx3iInApO9kuBgjvHPtfEOGsOjMga_d_VI6K9JQX9Q2FuDBh6PjyZa_mGuv0p7TaTCx5uSDaESTnvIwjzb06q1iHvk_oGsEsQN1FRUBoxdQBPyRDgpTzCX-FPqkIFllYmu5RA91SjybdAhC_NRJBdvJfZK11QRHRRw6kK1hdx6etollxHxJHMSIgjUkHELmRsBpO0rzsKsfLj8bGDRsOvtLvZbbFj_eZcYtnRmLOrZ9jFjCXDFcly1svz7DP7RSq3CBkkMyb4pxJnHL5r0oAPX3ib5KDfQxE02dvvXw-UXhOxZle9rxgTk0MtuEx0nKwzzYxixPnap2zipRYx-KmO9jR0jWs3V8dQgJa8ZhEL5LnbV8i_4dNVfZuxBAZYN2a9zMjA-e5_FzCNouQKgO9luGDH0n_omKSx9z4uaZ6n8Denin_Hzp-9ulJt_D8a_dJdAzlJQ"
# ──────────────────────────────────────────────────────────────────────────────

URL  = REGION_FQDN + "/v3.0/asrm/vulnerableDevices"
PAGE = 200   # records per page

# Filter to Notepad++ devices.
# TMV1-Filter uses OData syntax. Try option A first; if the API returns 400
# (field not supported in filter), it will automatically fall back to option B
# (fetch everything and filter client-side).
FILTER_HEADER = "contains(tolower(productName), 'notepad++')"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "TMV1-Filter":   FILTER_HEADER,
}

QUERY_PARAMS = {
    "top": PAGE,
}

DEBUG = True   # set False once working


# ─── Fetch ────────────────────────────────────────────────────────────────────

def fetch_notepadpp_devices() -> list[dict]:
    """
    Strategy:
      1. Try server-side OData filter (fast, minimal data transfer).
      2. If the API rejects the filter (400), fall back to fetching all
         records and filtering client-side.
    """
    print("Strategy 1: server-side filter  ->  TMV1-Filter:", FILTER_HEADER)

    all_items = []
    next_link = URL
    params    = dict(QUERY_PARAMS)
    page_num  = 0
    error_resp = None

    while next_link:
        page_num += 1
        print(f"  Fetching page {page_num} ...", end="\r", flush=True)

        if next_link == URL:
            if DEBUG:
                safe = {k: (v[:24] + "..." if k == "Authorization" else v) for k, v in HEADERS.items()}
                print(f"\n[DEBUG] GET {next_link}")
                print(f"[DEBUG] params  : {params}")
                print(f"[DEBUG] headers : {safe}")
            r = requests.get(next_link, headers=HEADERS, params=params, timeout=30)
        else:
            r = requests.get(next_link, headers=HEADERS, timeout=30)

        if r.status_code != 200:
            error_resp = r
            break

        body = r.json()
        all_items.extend(body.get("items", []))
        next_link = body.get("nextLink") or body.get("@odata.nextLink")

    if error_resp is not None:
        print(f"\n[WARN] Server-side filter rejected (HTTP {error_resp.status_code}).")
        print(f"       {error_resp.text}")
        print("\nStrategy 2: fetching all records and filtering client-side ...\n")

        no_filter_headers = {k: v for k, v in HEADERS.items() if k != "TMV1-Filter"}
        all_items = []
        next_link = URL
        page_num  = 0

        while next_link:
            page_num += 1
            print(f"  Fetching page {page_num} ...", end="\r", flush=True)
            if next_link == URL:
                r = requests.get(next_link, headers=no_filter_headers, params=params, timeout=30)
            else:
                r = requests.get(next_link, headers=no_filter_headers, timeout=30)

            if r.status_code != 200:
                print(f"\n[ERROR] HTTP {r.status_code}\n{r.text}")
                sys.exit(1)

            body = r.json()
            all_items.extend(body.get("items", []))
            next_link = body.get("nextLink") or body.get("@odata.nextLink")

        print(f"  Total records fetched: {len(all_items)}")

        # Client-side filter across common product name fields
        all_items = [
            v for v in all_items
            if "notepad" in str(v.get("productName",      "")).lower()
            or "notepad" in str(v.get("applicationName",  "")).lower()
            or "notepad" in str(v.get("softwareName",     "")).lower()
        ]
        print(f"  Notepad++ records after filtering: {len(all_items)}\n")
    else:
        print(f"  Done -- {len(all_items)} records fetched across {page_num} page(s).\n")

    return all_items


# ─── Display ──────────────────────────────────────────────────────────────────

def summarise(vulns: list[dict]) -> None:
    if not vulns:
        print("No Notepad++ vulnerability records found.")
        return

    W_DEVICE  = 30
    W_PRODUCT = 20
    W_CVE     = 18
    W_CVSS    = 6
    W_RISK    = 6
    W_STATUS  = 14
    W_LAST    = 22

    header = (
        f"{'Device':<{W_DEVICE}} "
        f"{'Product':<{W_PRODUCT}} "
        f"{'CVE ID':<{W_CVE}} "
        f"{'CVSS':>{W_CVSS}} "
        f"{'Risk':>{W_RISK}} "
        f"{'Status':<{W_STATUS}} "
        f"{'Last Detected':<{W_LAST}}"
    )
    sep = "-" * len(header)

    print(header)
    print(sep)

    for v in vulns:
        device  = (v.get("deviceName") or v.get("endpointName") or "")[:W_DEVICE]
        product = (v.get("productName") or v.get("applicationName") or v.get("softwareName") or "")[:W_PRODUCT]
        cve     = (v.get("cveId") or "")[:W_CVE]
        cvss    = v.get("cvssScore", "N/A")
        risk    = v.get("riskScore",  "N/A")
        status  = (v.get("cveDetectionStatus") or "")[:W_STATUS]
        last    = (v.get("lastDetectedDateTime") or "")[:W_LAST]

        print(
            f"{device:<{W_DEVICE}} "
            f"{product:<{W_PRODUCT}} "
            f"{cve:<{W_CVE}} "
            f"{str(cvss):>{W_CVSS}} "
            f"{str(risk):>{W_RISK}} "
            f"{status:<{W_STATUS}} "
            f"{last:<{W_LAST}}"
        )

    print(sep)
    print(f"Total: {len(vulns)} Notepad++ vulnerability record(s)\n")

    # Unique affected devices
    devices = sorted({v.get("deviceName") or v.get("endpointName") or "Unknown" for v in vulns})
    print(f"Affected devices ({len(devices)}):")
    for d in devices:
        print(f"  * {d}")

    # Severity breakdown
    def sf(v, k):
        try:    return float(v.get(k, 0) or 0)
        except: return 0.0

    print("\nSeverity breakdown (CVSS):")
    print(f"  Critical >=9.0 : {sum(1 for v in vulns if sf(v,'cvssScore') >= 9.0)}")
    print(f"  High     7-9   : {sum(1 for v in vulns if 7.0 <= sf(v,'cvssScore') < 9.0)}")
    print(f"  Medium   4-7   : {sum(1 for v in vulns if 4.0 <= sf(v,'cvssScore') < 7.0)}")
    print(f"  Low      <4    : {sum(1 for v in vulns if sf(v,'cvssScore') < 4.0)}")


def save_json(vulns: list[dict], path: str = "notepadpp_vulnerabilities.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vulns, f, indent=4)
    print(f"\nFull data saved -> {path}")


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Trend Micro Vision One -- Notepad++ Vulnerable Devices")
    print("=" * 60)

    vulns = fetch_notepadpp_devices()
    summarise(vulns)
    save_json(vulns)