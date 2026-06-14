import requests
import csv
import argparse

BASE_URL = 'https://app.deepsecurity.trendmicro.com/api'
API_KEY  = '8BEC6851-96F0-D7D3-5002-C1062BC9E89C:CB77AF3B-16F2-F519-1E61-AFF9B2B2CF46:qKhC1TxhgCVVze6qISiL2oJq1f9GcEz+KJH2iBVUVBE='

headers = {
    'api-secret-key': API_KEY,
    'api-version': 'v1',
    'Content-Type': 'application/json'
}

# --- Argument Parser ---
parser = argparse.ArgumentParser(description='Fetch AntiMalware settings from Trend Micro S&WP')
parser.add_argument('-p', '--policy', type=str, help='Policy name to filter (runs all policies if omitted)', default=None)
parser.add_argument('-excluded_dir', action='store_true', help='List all excluded directories for the policy', default=False)
parser.add_argument('-excluded_files', action='store_true', help='List all excluded files for the policy', default=False)
parser.add_argument('-excluded_file_extensions', action='store_true', help='List all excluded file extensions for the policy', default=False)
parser.add_argument('-excluded_process_images', action='store_true', help='List all excluded process image files for the policy', default=False)
args = parser.parse_args()

AM_CONFIG_FIELDS = [
    'name', 'description', 'scanType',
    'documentExploitProtectionEnabled', 'documentExploitProtection', 'documentExploitHeuristicLevel',
    'machineLearningEnabled', 'behaviorMonitoringEnabled', 'documentRecoveryEnabled',
    'intelliTrapEnabled', 'memoryScanEnabled', 'spywareEnabled', 'alertEnabled',
    'directoriesToScan', 'directoryListID', 'filesToScan',
    'fileExtensionListID', 'excludedDirectoryListID', 'excludedFileListID',
    'excludedFileExtensionListID', 'excludedProcessImageFileListID',
    'realTimeScan', 'scanCompressedEnabled', 'scanCompressedMaximumSize',
    'scanCompressedMaximumLevels', 'scanCompressedMaximumFiles',
    'microsoftOfficeEnabled', 'microsoftOfficeLayers',
    'networkDirectoriesEnabled', 'customRemediationActionsEnabled', 'customScanActionsEnabled',
    'scanActionForVirus', 'scanActionForTrojans', 'scanActionForPacker',
    'scanActionForSpyware', 'scanActionForOtherThreats', 'scanActionForCookies',
    'scanActionForCVE', 'scanActionForHeuristics', 'scanActionForPossibleMalware',
    'amsiScanEnabled', 'scanActionForBehaviorMonitoring', 'scanActionForMachineLearning',
    'scanActionForAmsi', 'processMemoryScanAction',
    'detectionLevel', 'preventionLevel',
    'machineLearningDetectionLevel', 'machineLearningPreventionLevel',
    'behaviorMonitoringDetectionLevel', 'behaviorMonitoringPreventionLevel',
    'amsiDetectionLevel', 'amsiPreventionLevel',
    'processMemoryScanDetectionLevel', 'processMemoryScanPreventionLevel',
    'ID', 'cpuUsage'
]

# Maps list ID fields → (endpoint, items key)
LIST_ID_RESOLVERS = {
    'directoryListID':               ('directorylists',      'directories'),
    'excludedDirectoryListID':       ('directorylists',      'directories'),
    'excludedFileListID':            ('filelists',           'files'),
    'excludedFileExtensionListID':   ('fileextensionlists',  'fileExtensions'),
    'excludedProcessImageFileListID':('filelists',           'files'),
}

def resolve_list_id(field, list_id):
    """Resolve any list ID field to its name. Returns 'None' if ID is 0."""
    if not list_id or int(list_id) == 0:
        return 'None'
    endpoint, items_key = LIST_ID_RESOLVERS[field]
    r = requests.get(f'{BASE_URL}/{endpoint}/{list_id}', headers=headers)
    if r.ok:
        data  = r.json()
        name  = data.get('name', 'N/A')
        items = data.get(items_key, [])
        print(f'    {field} → {name}')
        for item in items:
            print(f'      - {item}')
        return name
    print(f'    Error resolving {field} ID {list_id}: {r.status_code}')
    return f'Error({r.status_code})'

def fetch_am_config(config_id, config_type, policy_name, writer):
    """Fetch AM config, resolve all list IDs, print and write to CSV."""
    if not config_id or int(config_id) == 0:
        print(f'  {config_type}: No config assigned (ID=0)')
        return

    r = requests.get(f'{BASE_URL}/antimalwareconfigurations/{config_id}', headers=headers)
    if not r.ok:
        print(f'  Error fetching {config_type} ID {config_id}: {r.status_code} {r.text}')
        return

    config   = r.json()
    config_name = config.get('name', 'N/A')
    extracted = {field: config.get(field, 'N/A') for field in AM_CONFIG_FIELDS}
    if args.excluded_dir:
        excl_dir_name = extracted.get('excludedDirectoryListID', 'None')
        excl_dirs_id  = config.get('excludedDirectoryListID', 0)
        print(f'\n  --- Excluded Directories for [{config_type}] ---')
        print(f'  List Name: {excl_dir_name}')
        if excl_dirs_id and int(excl_dirs_id) != 0:
            r = requests.get(f'{BASE_URL}/directorylists/{excl_dirs_id}', headers=headers)
            if r.ok:
                directories = r.json().get('items', [])
                print(f' Count: {len(directories)}')
                for d in r.json().get('items', []):
                    print(f'    - {d}')
        else:
            print('  No excluded directories assigned')

    if args.excluded_files:
        excl_file_name = extracted.get('excludedFileListID', 'None')
        excl_files_id  = config.get('excludedFileListID', 0)
        print(f'\n  --- Excluded Files for [{config_type}] ---')
        print(f'  List Name: {excl_file_name}')
        if excl_files_id and int(excl_files_id) != 0:
            r = requests.get(f'{BASE_URL}/filelists/{excl_files_id}', headers=headers)
            if r.ok:
                files = r.json().get('items', [])
                print(f' Count: {len(files)}')
                for f in r.json().get('items', []):
                    print(f'    - {f}')
        else:
            print('  No excluded files assigned')

    if args.excluded_file_extensions:
        excl_ext_name = extracted.get('excludedFileExtensionListID', 'None')
        excl_ext_id   = config.get('excludedFileExtensionListID', 0)
        print(f'\n  --- Excluded File Extensions for [{config_type}] ---')
        print(f'  List Name: {excl_ext_name}')
        if excl_ext_id and int(excl_ext_id) != 0:
            r = requests.get(f'{BASE_URL}/fileextensionlists/{excl_ext_id}', headers=headers)
            if r.ok:
                extensions = r.json().get('items', [])
                print(f' Count: {len(extensions)}')
                for e in r.json().get('items', []):
                    print(f'    - {e}')
        else:
            print('  No excluded file extensions assigned')

    if args.excluded_process_images:
        excl_proc_name = extracted.get('excludedProcessImageFileListID', 'None')
        excl_proc_id   = config.get('excludedProcessImageFileListID', 0)
        print(f'\n  --- Excluded Process Image Files for [{config_type}] ---')
        print(f'  List Name: {excl_proc_name}')
        if excl_proc_id and int(excl_proc_id) != 0:
            r = requests.get(f'{BASE_URL}/filelists/{excl_proc_id}', headers=headers)
            if r.ok:
                proc_images = r.json().get('items', [])
                print(f' Count: {len(proc_images)}')
                for p in r.json().get('items', []):
                    print(f'    - {p}')
        else:
            print('  No excluded process image files assigned')

    # Resolve all list ID fields → names
    for field in LIST_ID_RESOLVERS:
        extracted[field] = resolve_list_id(field, config.get(field, 0))

    print(f'\n  [{config_type}] Policy: {policy_name} | Config: {config_name} (ID: {config_id})')
    for field, value in extracted.items():
        print(f'    {field}: {value}')

    # Write one row per config type
    writer.writerow([policy_name, config_type, config_id] + [extracted.get(f, '') for f in AM_CONFIG_FIELDS])


# --- Main ---
if __name__ == '__main__':
    r = requests.get(f'{BASE_URL}/policies', headers=headers)

    if r.ok:
        policies    = r.json()

        # Filter by Policy name if -p argument was provided
        if args.policy:
            policies['policies'] = [p for p in policies.get('policies', []) if args.policy.lower() in p.get('name', '').lower()]
            if not policies['policies']:
                print(f'No policies found matching "{args.policy}"')
                exit(1)
            print(f'Running on policy: {args.policy}')
        else:
            print(f'No policy specified. Running on all policies. Total policies: {len(policies.get("policies", []))}')
        output_file = 'antimalware_settings.csv'

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Policy Name', 'Config Type', 'Config ID'] + AM_CONFIG_FIELDS)

            for p in policies.get('policies', []):
                name = p.get('name', 'N/A')
                am   = p.get('antiMalware', {})

                # --- Simple/nested AM fields (state, moduleStatus, directory settings) ---
                for key, val in am.items():
                    if isinstance(val, dict):
                        for sub_key, sub_val in val.items():
                            value = ', '.join(str(i) for i in sub_val) if isinstance(sub_val, list) else str(sub_val)
                            print(f'{name} | {key}.{sub_key} = {value}')
                    elif key not in ('realTimeScanConfigurationID', 'manualScanConfigurationID',
                                     'scheduledScanConfigurationID', 'realTimeScanScheduleID'):
                        print(f'{name} | {key} = {val}')

                # --- Config ID lookups (all 3 use the same function now) ---
                fetch_am_config(am.get('realTimeScanConfigurationID'),  'realTimeScan',   name, writer)
                fetch_am_config(am.get('manualScanConfigurationID'),    'manualScan',     name, writer)
                fetch_am_config(am.get('scheduledScanConfigurationID'), 'scheduledScan',  name, writer)

                # --- Schedule lookup ---
                sched_id = am.get('realTimeScanScheduleID', 0)
                if sched_id and int(sched_id) != 0:
                    sched_r = requests.get(f'{BASE_URL}/schedules/{sched_id}', headers=headers)
                    if sched_r.ok:
                        print(f'{name} | realTimeScanScheduleID → {sched_r.json().get("name")}')
                    else:
                        print(f'{name} | realTimeScanScheduleID Error: {sched_r.status_code}')

        print(f'\nDone — saved to {output_file}')
    else:
        print(f'Error {r.status_code}: {r.text}')