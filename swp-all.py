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

MODULE_MAP = {
    'am'   : 'antiMalware',
    'ips'  : 'intrusionPrevention',
    'fw'   : 'firewall',
    'wr'   : 'webReputation',
    'im'   : 'integrityMonitoring',
    'li'   : 'logInspection',
    'appc' : 'applicationControl',
    'dc'   : 'deviceControl',
    'ac'   : 'activityMonitoring',
    'sap'  : 'SAP',
}

# --- Argument Parser ---
parser = argparse.ArgumentParser(description='Fetch AntiMalware settings from Trend Micro S&WP')
parser.add_argument('-p', '--policy', type=str, help='Policy name to filter (runs all policies if omitted)', default=None)
parser.add_argument('-m', '--module', nargs='*', help='Modules to fetch (e.g. ips am fw). Runs all if omitted.', default=None)
parser.add_argument('-excluded_dir', action='store_true', help='List all excluded directories for the policy', default=False)
parser.add_argument('-excluded_files', action='store_true', help='List all excluded files for the policy', default=False)
parser.add_argument('-excluded_file_extensions', action='store_true', help='List all excluded file extensions for the policy', default=False)
parser.add_argument('-excluded_process_images', action='store_true', help='List all excluded process image files for the policy', default=False)
args = parser.parse_args()

if args.module:
    selected_modules = [MODULE_MAP[m] for m in args.module if m in MODULE_MAP]
else:
    selected_modules = list(MODULE_MAP.values())  # all modules

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

    config      = r.json()
    config_name = config.get('name', 'N/A')
    extracted   = {field: config.get(field, 'N/A') for field in AM_CONFIG_FIELDS}

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
        policies       = r.json()
        module_summary = []

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
                name            = p.get('name', 'N/A')
                am              = p.get('antiMalware', {})
                ip              = p.get('intrusionPrevention', {})
                appc            = p.get('applicationControl', {})
                wr             = p.get('webReputation', {})
                dc             = p.get('deviceControl', {})
                policy_settings = p.get('policySettings', {})
                rec_scan_mode   = p.get('recommendationScanMode', 'N/A')

                # --- Collect Module Status for summary ---
                module_summary.append({
                    'policy': name,
                    **{mod: p.get(mod, {}).get('moduleStatus', {}).get('status', 'N/A')
                       for mod in selected_modules}
                })

                # --- Policy Header ---
                print(f'\n{"="*60}')
                print(f'Policy: {name}')
                print(f'{"="*60}')

                # --- Module Loop ---
                for module in selected_modules:
                    data   = p.get(module, {})
                    state  = data.get('state', 'N/A')
                    status = data.get('moduleStatus', {}).get('status', 'N/A')

                    print(f'\n  [{module}]')
                    print(f'    state        : {state}')
                    print(f'    moduleStatus : {status}')

                    # --- Anti-Malware specific ---
                    if module == 'antiMalware':
                        sched_id = am.get('realTimeScanScheduleID', 0)
                        if sched_id and int(sched_id) != 0:
                            sched_r = requests.get(f'{BASE_URL}/schedules/{sched_id}', headers=headers)
                            if sched_r.ok:
                                print(f'    realTimeScanSchedule : {sched_r.json().get("name")}')
                            else:
                                print(f'    realTimeScanSchedule : Error {sched_r.status_code}')
                        fetch_am_config(am.get('realTimeScanConfigurationID'),  'realTimeScan',  name, writer)
                        fetch_am_config(am.get('manualScanConfigurationID'),    'manualScan',    name, writer)
                        fetch_am_config(am.get('scheduledScanConfigurationID'), 'scheduledScan', name, writer)

                    # --- Intrusion Prevention specific ---
                    elif module == 'intrusionPrevention':
                        ip_rule_ids     = ip.get('ruleIDs', [])
                        inbound_tls     = policy_settings.get('intrusionPreventionSettingInspectInboundTlsTrafficEnabled',   {}).get('value', 'N/A')
                        outbound_tls    = policy_settings.get('intrusionPreventionSettingInspectOutboundTlsTrafficEnabled',  {}).get('value', 'N/A')
                        rec_mode        = policy_settings.get('intrusionPreventionSettingRecommendationScanMode',            {}).get('value', 'N/A')
                        auto_apply      = policy_settings.get('intrusionPreventionSettingAutoApplyRecommendationsEnabled',   {}).get('value', 'N/A')
                        auto_core_rules = policy_settings.get('intrusionPreventionSettingAutomaticallyApplyCoreIpsRules',    {}).get('value', 'N/A')
                        ips_first_hit   = policy_settings.get('intrusionPreventionSettingLogDataRuleFirstMatchEnabled',      {}).get('value', 'N/A')
                        auto_assign     = policy_settings.get('platformSettingAutoAssignNewIntrusionPreventionRulesEnabled', {}).get('value', 'N/A')

                        print(f'    ruleCount                  : {len(ip_rule_ids)}')
                        print(f'    TLS Inbound Inspection     : {inbound_tls}')
                        print(f'    TLS Outbound Inspection    : {outbound_tls}')
                        print(f'    Recommendation Scan Mode   : {rec_scan_mode}')
                        print(f'    IPS Rec Scan Mode Setting  : {rec_mode}')
                        print(f'    Auto-Apply Recommendations : {auto_apply}')
                        print(f'    Auto-Apply Core Rules      : {auto_core_rules}')
                        print(f'    Log First Match Only       : {ips_first_hit}')
                        print(f'    Auto-Assign New Rules      : {auto_assign}')
                        

                    # --- Application Control specific ---
                    elif module == 'applicationControl':
                        state = appc.get('state', 'N/A')
                        status = appc.get('moduleStatus', {}).get('status', 'N/A')
                        trustRulesetID = appc.get('trustRulesetID', 0)
                        appc_rule_ids = appc.get('ruleIDs', [])
                        enforment_mode = appc.get('blockUnrecognized', 'N/A')

                        if trustRulesetID and int(trustRulesetID) != 0:
                            r = requests.get(f'{BASE_URL}/applicationcontroltrustrulesets/{trustRulesetID}', headers=headers)
                            if r.ok:
                                ruleset_name = r.json().get('name', 'N/A')
                                print(f'    trustRuleset : {ruleset_name} (ID: {trustRulesetID})')
                            else:
                                print(f'    trustRuleset : Error {r.status_code}')

                        # print(f'    state      : {state}')
                        # print(f'    status     : {status}')
                        # print(f'    trustRulesetID : {trustRulesetID}')
                        print(f'    ruleCount : {len(appc_rule_ids)}')
                        print(f'    Enforcement Mode : {enforment_mode}')

                    # --- Web Reputation specific ---
                    elif module == 'webReputation':
                        wr_settings = {
                            'Security Level'                      : 'webReputationSettingSecurityLevel',
                            'Block Untested Pages'                : 'webReputationSettingSecurityBlockUntestedPagesEnabled',
                            'Alerting Enabled'                    : 'webReputationSettingAlertingEnabled',
                            'Smart Protection Local Server'       : 'webReputationSettingSmartProtectionLocalServerEnabled',
                            'Smart Protection Local Server URLs'  : 'webReputationSettingSmartProtectionLocalServerUrls',
                            'Local Server Allow Off-Domain Global': 'webReputationSettingSmartProtectionLocalServerAllowOffDomainGlobal',
                            'Global Server Use Proxy'             : 'webReputationSettingSmartProtectionGlobalServerUseProxyEnabled',
                            'Global Server Proxy ID'              : 'webReputationSettingSmartProtectionWebReputationGlobalServerProxyId',
                            'Connection Lost Warning'             : 'webReputationSettingSmartProtectionServerConnectionLostWarningEnabled',
                            'Combined Mode Protection Source'     : 'webReputationSettingCombinedModeProtectionSource',
                            'Monitor Port List ID'                : 'webReputationSettingMonitorPortListId',
                            'Syslog Config ID'                    : 'webReputationSettingSyslogConfigId',
                            'Blocking Page Link'                  : 'webReputationSettingBlockingPageLink',
                            'Allowed URLs'                        : 'webReputationSettingAllowedUrls',
                            'Allowed URL Domains'                 : 'webReputationSettingAllowedUrlDomains',
                            'Blocked URLs'                        : 'webReputationSettingBlockedUrls',
                            'Blocked URL Domains'                 : 'webReputationSettingBlockedUrlDomains',
                            'Blocked URL Keywords'                : 'webReputationSettingBlockedUrlKeywords',
                        }
                        for label, key in wr_settings.items():
                            value = policy_settings.get(key, {}).get('value', 'N/A')
                            print(f'    {label:<40} : {value}')

                    # --- Device Control specific ---
                    elif module == 'deviceControl': 
                        dc_settings = {
                            'Control Mode'                       : 'deviceControlSettingDeviceControlEnabled',
                            'Removable Storage Control Mode'      : 'deviceControlSettingDeviceControlUsbStorageDeviceAction',
                            'Mobile Device Control Mode'         : 'deviceControlSettingMobileDeviceControlMode',
                            'CD/DVD Control Mode'                : 'deviceControlSettingCdDvdControlMode',
                            'USB Control Mode'                   : 'deviceControlSettingDeviceControlUsbStorageDeviceAction',
                            'Bluetooth Control Mode'              : 'deviceControlSettingBluetoothControlMode',
                            'Serial Port Control Mode'           : 'deviceControlSettingSerialPortControlMode',
                            'Parallel Port Control Mode'         : 'deviceControlSettingParallelPortControlMode',
                            'Infrared Control Mode'              : 'deviceControlSettingInfraredControlMode',
                            'Other Control Mode'                 : 'deviceControlSettingOtherControlMode',
                            'Auto-Run Control Mode'                : 'deviceControlSettingDeviceControlAutoRunUsbAction',
                        }
                        for label, key in dc_settings.items():
                            value = policy_settings.get(key, {}).get('value', 'N/A')
                            print(f'    {label:<40} : {value}')

                # --- Per-Policy Summary ---
                print(f'\n  {"─"*56}')
                print(f'  Summary: {name}')
                print(f'  {"─"*56}')
                for module in selected_modules:
                    mod_state  = p.get(module, {}).get('state', 'N/A')
                    mod_status = p.get(module, {}).get('moduleStatus', {}).get('status', 'N/A')
                    print(f'    {module:<30} state={mod_state:<12} status={mod_status}')

        # --- Module Status Summary CSV ---
        if module_summary:
            summary_file = 'module_status_summary.csv'
            all_modules  = sorted({mod for row in module_summary for mod in row if mod != 'policy'})
            with open(summary_file, 'w', newline='') as sf:
                summary_writer = csv.writer(sf)
                summary_writer.writerow(['Policy'] + all_modules)
                for row in module_summary:
                    summary_writer.writerow([row['policy']] + [row.get(m, 'N/A') for m in all_modules])
            print(f'\nModule Status Summary:')
            print(','.join(['Policy'] + all_modules))
            for row in module_summary:
                print(','.join([row['policy']] + [row.get(m, 'N/A') for m in all_modules]))
            print(f'\nModule status summary saved to {summary_file}')

        print(f'\nDone — saved to {output_file}')
    else:
        print(f'Error {r.status_code}: {r.text}')
