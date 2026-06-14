import html
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
#    "Content-Type": "application/json",
    "TMV1-Filter": "assetCustomTagIds eq 'IMpg1AzVCzFKWaNquszEkqsktlvn-01'",
}

r = requests.get(url, params=params, headers=headers, timeout=30)

if r.status_code != 200:
    print(f"Error: {r.status_code}", file=sys.stderr)
    print(r.text, file=sys.stderr)
    sys.exit(1)

data = r.json()
#print(json.dumps(data, indent=2))
rows = []

for device in data.get("items", []):
    agent_id        = device.get("id", "N/A")
    name            = device.get("deviceName", "N/A")
    criticality     = device.get("criticality", "N/A")
    ip              = device.get("ip", []),
    tags            = device.get("assetCustomTags", [])

#    print(f"{agent_id} - {name} - {criticality} - {id}")

    cve_items  = []
    cve_count  = 0
    cve_url     = f"{BASE_URL}/v3.0/asrm/vulnerableDevices"
    cve_headers = {**headers, "TMV1-Filter": f"(deviceName eq '{name}')"}
    cve_response = requests.get(cve_url, headers=cve_headers, params={"top": 50}, timeout=30)
    if cve_response.status_code == 200:
        vuln_items = cve_response.json().get("items", [])
        if vuln_items:
            cve_items = vuln_items[0].get("cveRecords", [])
            cve_count = len(cve_items)

    rows.append({
        "name":            name,
        "ip":              ip,
        "cve_items":       cve_items,
        "cve_count":       cve_count,

    })


    print(f"{name} - {ip} - {criticality} - {cve_count} CVEs - tags: {tags}")
# # ── HTML Generation ────────────────────────────────────────────────────────────

# html_doc = """<!DOCTYPE html>
# <html lang="en">
# <head>
#   <meta charset="UTF-8">
#   <title>Trend Micro XDR - Endpoints</title>
#   <style>
#     body { font-family: Arial, sans-serif; margin: 2rem; background: #f4f6f9; color: #333; }
#     h1   { color: #c00; }
#     table { width: 100%; border-collapse: collapse; background: #fff;
#             box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
#     th   { background: #c00; color: #fff; padding: 10px 14px; text-align: left; }
#     td   { padding: 9px 14px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
#     tr:hover td { background: #fff5f5; }
#     details summary { cursor: pointer; color: #c00; font-weight: bold; }
#     pre  { background: #f0f0f0; padding: 8px; border-radius: 4px;
#            font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; }
#     .badge { background: #c00; color: #fff; border-radius: 12px;
#              padding: 2px 8px; font-size: 0.78rem; margin-right: 6px; }
#     .badge.none { background: #4caf50; }
#     .toggle-btn {
#       background: #c00; color: #fff; border: none; border-radius: 4px;
#       padding: 3px 10px; cursor: pointer; font-size: 0.8rem; margin-top: 4px;
#     }
#     .toggle-btn:hover { background: #a00; }
#     .cve-table { margin-top: 8px; width: 100%; border-collapse: collapse; font-size: 0.82rem; }
#     .cve-table th { background: #555; color: #fff; padding: 5px 8px; }
#     .cve-table td { padding: 4px 8px; border-bottom: 1px solid #ddd; }
#     .cve-row:hover td { background: #ffeaea; }
#   </style>
# </head>
# <body>
#   <h1>Trend Micro XDR — Endpoint List</h1>
#   <table>
#     <thead>
#       <tr>
#         <th>Endpoint Name</th>
#         <th>IP Address</th>
#         <th>Update Policy</th>
#         <th>Agent Version</th>
#         <th>Version Control</th>
#           <th>tags</th>
#         <th>Details</th>
#         <th>CVE Vulnerabilities</th>
#       </tr>
#     </thead>
#     <tbody>
# """

# for row in rows:
#     name_e    = html.escape(str(row["name"]))
#     ip_e      = html.escape(str(row["ip"]))
#     update_e  = html.escape(str(row["update"]))
#     version_e = html.escape(str(row["version"]))
#     vc_e      = html.escape(str(row["version_control"]))

#     details_html = (
#         f"<details><summary>View</summary>"
#         f"<pre>{html.escape(json.dumps(row['details'], indent=2))}</pre></details>"
#         if row["details"] else "N/A"
#     )

#     cve_count = row["cve_count"]
#     badge_cls = "badge none" if cve_count == 0 else "badge"
#     badge     = f'<span class="{badge_cls}">{cve_count} CVE{"s" if cve_count != 1 else ""}</span>'

#     if cve_count > 0 and row["cve_items"]:
#         row_id   = html.escape(str(row["name"])).replace(" ", "_")
#         cve_rows = ""
#         for cve in row["cve_items"]:
#             cve_id     = html.escape(str(cve.get("id",                       "N/A")))
#             risk_level = html.escape(str(cve.get("eventRiskLevel",           "N/A")))
#             exploit    = html.escape(str(cve.get("globalExploitActivityLevel","N/A")))
#             score      = html.escape(str(cve.get("cvssScore",                "N/A")))
#             components = html.escape(", ".join(cve.get("affectedComponents", [])) or "N/A")
#             status     = html.escape(str(cve.get("mitigationStatus",         "N/A")))
#             cve_rows += f"""
#               <tr class="cve-row">
#                 <td><b>{cve_id}</b></td>
#                 <td>{risk_level}</td>
#                 <td>{exploit}</td>
#                 <td>{score}</td>
#                 <td>{status}</td>
#                 <td>{components}</td>
#               </tr>"""

#         cve_html = f"""{badge}
#           <button class="toggle-btn" onclick="toggleCVE('{row_id}')">&#9654; Show CVEs</button>
#           <table id="cve-{row_id}" class="cve-table" style="display:none;">
#             <thead>
#               <tr>
#                 <th>CVE ID</th><th>Risk Level</th><th>Exploit Activity</th>
#                 <th>CVSS Score</th><th>Status</th><th>Affected Components</th>
#               </tr>
#             </thead>
#             <tbody>{cve_rows}</tbody>
#           </table>"""
#     else:
#         cve_html = badge

#     html_doc += f"""      <tr>
#         <td>{name_e}</td>
#         <td>{ip_e}</td>
#         <td>{update_e}</td>
#         <td>{version_e}</td>
#         <td>{vc_e}</td>
#         <td>{details_html}</td>
#         <td>{cve_html}</td>
#       </tr>
# """

# html_doc += """    </tbody>
#   </table>

#   <script>
#     function toggleCVE(id) {
#       const table = document.getElementById('cve-' + id);
#       const btn   = table.previousElementSibling;
#       if (table.style.display === 'none') {
#         table.style.display = 'table';
#         btn.innerHTML = '&#9660; Hide CVEs';
#       } else {
#         table.style.display = 'none';
#         btn.innerHTML = '&#9654; Show CVEs';
#       }
#     }
#   </script>
# </body>
# </html>
# """

# output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoints.html")
# with open(output_file, "w") as f:
#     f.write(html_doc)

# print(f"Report saved to {output_file}")
