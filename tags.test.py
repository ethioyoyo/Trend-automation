import requests
import os

BASE_URL = "https://api.xdr.trendmicro.com"
TOKEN = os.environ.get("TREND_TOKEN")
if not TOKEN:
    print("Error: TREND_TOKEN environment variable is not set.")
    exit()

url = f"{BASE_URL}/v3.0/asrm/attackSurfaceCustomTags"
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}
r = requests.get(url, params={"top": 1000}, headers=headers)
if r.status_code != 200:
    print("Error:", r.status_code)
    print(r.text)
    exit()

data = r.json()

for tag in data.get("items", []):
    tag_id    = tag.get("id")
    tag_value = tag.get("value")

    tag_response = requests.get(
        f"{BASE_URL}/v3.0/asrm/attackSurfaceDevices",
        headers={**headers, "TMV1-Filter": f"assetCustomTagIds eq '{tag_id}'"},
        params={"top": 200},
    )
    if tag_response.status_code != 200:
        print(f"Error fetching devices for tag '{tag_value}': {tag_response.status_code}")
        print(tag_response.text)
        continue

    tag_data = tag_response.json()
    devices  = tag_data.get("items", [])

    tag_high_count     = 0
    tag_critical_count = 0
    tag_critical_cves  = []
    rows = []

    for device in devices:
        ip_addresses      = ", ".join(device.get("ip", [])) or "N/A"
        name              = device.get("deviceName", "N/A")
        device_id         = device.get("id", "N/A")
        latest_risk_score = device.get("latestRiskScore", "N/A")
        cve_count         = device.get("cveCount", "N/A")

        vuln_response = requests.get(
            f"{BASE_URL}/v3.0/asrm/vulnerableDevices",
            headers={**headers, "TMV1-Filter": f"(id eq '{device_id}')"},
            params={"top": 200},
        )

        criticality      = "N/A"
        total_vulns      = 0
        high_count       = 0
        critical_count   = 0
        event_risk_level = "N/A"

        if vuln_response.status_code == 200:
            for vuln in vuln_response.json().get("items", []):
                criticality  = vuln.get("criticality", "N/A")
                cve_records  = vuln.get("cveRecords", [])
                total_vulns += len(cve_records)
                for cve in cve_records:
                    event_risk_level = cve.get("eventRiskLevel", "N/A")
                    cvss = cve.get("cvssScore", 0) or 0
                    if cvss >= 9.0:
                        critical_count += 1
                        tag_critical_count += 1
                        tag_critical_cves.append((cvss, cve.get("id", "N/A")))
                    elif cvss >= 7.0:
                        high_count += 1
                        tag_high_count += 1

        rows.append((name, ip_addresses, latest_risk_score, criticality, total_vulns, high_count, critical_count, event_risk_level))

    if not rows:
        continue

    # Tag summary header
    top_cves = sorted(set(tag_critical_cves), key=lambda x: x[0], reverse=True)[:10]
    top_cves_str = ", ".join(f"{cve_id}({cvss})" for cvss, cve_id in top_cves) or "None"
    print(f"\nTAG: {tag_value}  |  Devices: {len(devices)}  |  High: {tag_high_count}  |  Critical: {tag_critical_count}")
    print(f"Top Critical CVEs: {top_cves_str}")

    # Truncate long values to fit columns
    def trunc(val, width):
        s = str(val)
        return s if len(s) <= width else s[:width - 1] + "…"

    col_widths  = [22, 18, 10, 11, 6, 6, 8]
    headers_row = ["Device", "IP", "Risk Score", "Criticality", "Vulns", "High", "Critical"]
    sep = "┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
    div = "├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
    bot = "└" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"

    def fmt_row(cells):
        return "│" + "│".join(f" {trunc(c, w):<{w}} " for c, w in zip(cells, col_widths)) + "│"

    print(sep)
    print(fmt_row(headers_row))
    print(div)
    for row in rows:
        print(fmt_row(row[:7]))
    print(bot)
