import requests
import csv

BASE_URL = 'https://app.deepsecurity.trendmicro.com/api'
API_KEY  = '8BEC6851-96F0-D7D3-5002-C1062BC9E89C:CB77AF3B-16F2-F519-1E61-AFF9B2B2CF46:qKhC1TxhgCVVze6qISiL2oJq1f9GcEz+KJH2iBVUVBE='

headers = {
    'api-secret-key': API_KEY,
    'api-version': 'v1',
    'Content-Type': 'application/json'
}

# All fields to extract from antimalwareconfigurations
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

r = requests.get(f'{BASE_URL}/policies', headers=headers)

if r.ok:
    policies = r.json()
    output_file = 'antimalware_settings.csv'

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Policy Name', 'Setting Key', 'Sub Key', 'Value'])

        for p in policies.get('policies', []):
            name = p.get('name', 'N/A')
            am = p.get('antiMalware', {})
            for key, val in am.items():
                if isinstance(val, dict):
                     for sub_key, sub_val in val.items():
                         if isinstance(sub_val, list):
                             value = ', '.join(str(i) for i in sub_val) if sub_val else ''
                         else:
                             value = str(sub_val)
                         writer.writerow([name, key, sub_key, value])
#                         print(f"Policy: {name}, Setting: {key}, Sub Key: {sub_key}, Value: {value}")
                else:
                    writer.writerow([name, key, '', str(val) if val is not None else ''])

                if 'realTimeScanConfigurationID' in key:
                    aw_r = requests.get(f"{BASE_URL}/antimalwareconfigurations/{val}", headers=headers)
                    if aw_r.ok:
                        aw_config = aw_r.json()
                        aw_name   = aw_config.get('name', 'N/A')
                        extracted = {field: aw_config.get(field, 'N/A') for field in AM_CONFIG_FIELDS}

                        # Resolve excludedDirectoryListID → name and replace in extracted
                        excluded_dirs_list_id = aw_config.get('excludedDirectoryListID')
                        if excluded_dirs_list_id and int(excluded_dirs_list_id) != 0:
                            excl_dirs_r = requests.get(f"{BASE_URL}/directorylists/{excluded_dirs_list_id}", headers=headers)
                            if excl_dirs_r.ok:
                                excl_dirs_data    = excl_dirs_r.json()
                                dir_excl_dir_name = excl_dirs_data.get('name', 'N/A')
                                excl_dirs         = excl_dirs_data.get('directories', [])
                                # Replace the ID with the resolved name in extracted
                                extracted['excludedDirectoryListID'] = dir_excl_dir_name
                                print(f"  Excluded Directory List: {dir_excl_dir_name}")
                                for d in excl_dirs:
                                    print(f"    - {d}")
                        else:
                            extracted['excludedDirectoryListID'] = 'None'
                        # Resolve excludedFileListID → name and replace in extracted
                        excluded_files_list_id = aw_config.get('excludedFileListID')
                        if excluded_files_list_id and int(excluded_files_list_id) != 0:
                            excl_files_r = requests.get(f"{BASE_URL}/filelists/{excluded_files_list_id}", headers=headers)
                            if excl_files_r.ok:
                                excl_files_data    = excl_files_r.json()
                                file_excl_file_name = excl_files_data.get('name', 'N/A')
                                excl_files         = excl_files_data.get('files', [])
                                # Replace the ID with the resolved name in extracted
                                extracted['excludedFileListID'] = file_excl_file_name
                                print(f"  Excluded File List: {file_excl_file_name}")
                                for f in excl_files:
                                    print(f"    - {f}")
                        else:
                            extracted['excludedFileListID'] = 'None'
                        
                        # Resolve excludedFileExtensionListID → name and replace in extracted
                        excluded_file_ext_list_id = aw_config.get('excludedFileExtensionListID')
                        if excluded_file_ext_list_id and int(excluded_file_ext_list_id) != 0:
                            excl_file_ext_r = requests.get(f"{BASE_URL}/fileextensionlists/{excluded_file_ext_list_id}", headers=headers)
                            if excl_file_ext_r.ok:
                                excl_file_ext_data    = excl_file_ext_r.json()
                                file_ext_excl_name   = excl_file_ext_data.get('name', 'N/A')
                                excl_file_exts       = excl_file_ext_data.get('fileExtensions', [])
                                extracted['excludedFileExtensionListID'] = file_ext_excl_name
                                print(f"  Excluded File Extension List: {file_ext_excl_name}")
                                for fe in excl_file_exts:
                                    print(f"    - {fe}")
                        else:
                            extracted['excludedFileExtensionListID'] = 'None'
                        
                        # Resolve excludedProcessImageFileListID → name and replace in extracted
                        excluded_process_image_file_list_id = aw_config.get('excludedProcessImageFileListID')
                        if excluded_process_image_file_list_id and int(excluded_process_image_file_list_id) != 0:
                            excl_process_image_file_r = requests.get(f"{BASE_URL}/filelists/{excluded_process_image_file_list_id}", headers=headers)
                            if excl_process_image_file_r.ok:
                                excl_process_image_file_data    = excl_process_image_file_r.json()
                                process_image_excl_file_name   = excl_process_image_file_data.get('name', 'N/A')
                                excl_process_image_files       = excl_process_image_file_data.get('files', [])
                                extracted['excludedProcessImageFileListID'] = process_image_excl_file_name
                                print(f"  Excluded Process Image File List: {process_image_excl_file_name}")
                                for fe in excl_process_image_files:
                                    print(f"    - {fe}")
                        else:
                            extracted['excludedProcessImageFileListID'] = 'None'

                        print(f"Policy : {name} | Config ID: {val} | Name: {aw_name}")
                        for field, value in extracted.items():
                            print(f"  {field}: {value}")
                    else:
                        print(f"Error fetching anti-malware configuration for Policy: {name}, Setting: {key}, Value: {val} - Status Code: {aw_r.status_code}, Response: {aw_r.text}")
                             
                # value = val.get('value', '') if isinstance(val, dict) else val
                # writer.writerow([name, key, value])


                if 'realTimeScanScheduleID' in key:
                    sched_r = requests.get(f"{BASE_URL}/schedules/{val}", headers=headers)
                    if sched_r.ok:
                        sched_config = sched_r.json()
                        sched_name   = sched_config.get('name', 'N/A')
                        print(f"Policy: {name}, Setting: {key}, Value: {sched_name}")
                    else:
                        print(f"Error fetching schedule for Policy: {name}, Setting: {key}, Value: {value} - Status Code: {sched_r.status_code}, Response: {sched_r.text}")

                if 'manualScanConfigurationID' in key:
                    manual_r = requests.get(f"{BASE_URL}/antimalwareconfigurations/{val}", headers=headers)
                    if manual_r.ok:
                        manual_config = manual_r.json()
                        manual_name   = manual_config.get('name', 'N/A')
                        extracted = {field: manual_config.get(field, 'N/A') for field in AM_CONFIG_FIELDS}

                        excluded_dirs_list_id = manual_config.get('excludedDirectoryListID')
                        if excluded_dirs_list_id and int(excluded_dirs_list_id) != 0:
                            excl_dirs_r = requests.get(f"{BASE_URL}/directorylists/{excluded_dirs_list_id}", headers=headers)
                            if excl_dirs_r.ok:
                                excl_dirs_data    = excl_dirs_r.json()
                                dir_excl_dir_name = excl_dirs_data.get('name', 'N/A')
                                excl_dirs         = excl_dirs_data.get('directories', [])
                                extracted['excludedDirectoryListID'] = dir_excl_dir_name
                                print(f"  Excluded Directory List: {dir_excl_dir_name}")
                                for d in excl_dirs:
                                    print(f"    - {d}")
                        else:
                            extracted['excludedDirectoryListID'] = 'None'
                        
                        excluded_files_list_id = manual_config.get('excludedFileListID')
                        if excluded_files_list_id and int(excluded_files_list_id) != 0:
                            excl_files_r = requests.get(f"{BASE_URL}/filelists/{excluded_files_list_id}", headers=headers)
                            if excl_files_r.ok:
                                excl_files_data    = excl_files_r.json()
                                file_excl_file_name = excl_files_data.get('name', 'N/A')
                                excl_files         = excl_files_data.get('files', [])
                                extracted['excludedFileListID'] = file_excl_file_name
                                print(f"  Excluded File List: {file_excl_file_name}")
                                for f in excl_files:
                                    print(f"    - {f}")
                        else:
                            extracted['excludedFileListID'] = 'None'
                        
                        excluded_file_ext_list_id = manual_config.get('excludedFileExtensionListID')
                        if excluded_file_ext_list_id and int(excluded_file_ext_list_id) != 0:
                            excl_file_ext_r = requests.get(f"{BASE_URL}/fileextensionlists/{excluded_file_ext_list_id}", headers=headers)
                            if excl_file_ext_r.ok:
                                excl_file_ext_data    = excl_file_ext_r.json()
                                file_ext_excl_name   = excl_file_ext_data.get('name', 'N/A')
                                excl_file_exts       = excl_file_ext_data.get('fileExtensions', [])
                                extracted['excludedFileExtensionListID'] = file_ext_excl_name
                                print(f"  Excluded File Extension List: {file_ext_excl_name}")
                                for fe in excl_file_exts:
                                    print(f"    - {fe}")
                        else:
                            extracted['excludedFileExtensionListID'] = 'None'
                        
                        excluded_process_image_file_list_id = manual_config.get('excludedProcessImageFileListID')
                        if excluded_process_image_file_list_id and int(excluded_process_image_file_list_id) != 0:
                            excl_process_image_file_r = requests.get(f"{BASE_URL}/filelists/{excluded_process_image_file_list_id}", headers=headers)
                            if excl_process_image_file_r.ok:
                                excl_process_image_file_data    = excl_process_image_file_r.json()
                                process_image_excl_file_name   = excl_process_image_file_data.get('name', 'N/A')
                                excl_process_image_files       = excl_process_image_file_data.get('files', [])
                                extracted['excludedProcessImageFileListID'] = process_image_excl_file_name
                                print(f"  Excluded Process Image File List: {process_image_excl_file_name}")
                                for fe in excl_process_image_files:
                                    print(f"    - {fe}")
                        else:
                            extracted['excludedProcessImageFileListID'] = 'None'
                        print(f"Policy : {name} | Manual Scan Config ID: {val} | Name: {manual_name}")
                        for field, value in extracted.items():
                            print(f"  {field}: {value}")
                    else:
                        print(f"Error fetching anti-malware configuration for Policy: {name}, Setting: {key}, Value: {value} - Status Code: {manual_r.status_code}, Response: {manual_r.text}")

                if 'scheduledScanConfigurationID' in key:
                    sched_scan_r = requests.get(f"{BASE_URL}/antimalwareconfigurations/{val}", headers=headers)
                    if sched_scan_r.ok:
                        sched_scan_config = sched_scan_r.json()
                        sched_scan_name   = sched_scan_config.get('name', 'N/A')
                        extracted = {field: sched_scan_config.get(field, 'N/A') for field in AM_CONFIG_FIELDS}
                        excluded_dirs_list_id = sched_scan_config.get('excludedDirectoryListID')
                        if excluded_dirs_list_id and int(excluded_dirs_list_id) != 0:
                            excl_dirs_r = requests.get(f"{BASE_URL}/directorylists/{excluded_dirs_list_id}", headers=headers)
                            if excl_dirs_r.ok:
                                excl_dirs_data    = excl_dirs_r.json()
                                dir_excl_dir_name = excl_dirs_data.get('name', 'N/A')
                                excl_dirs         = excl_dirs_data.get('directories', [])
                                extracted['excludedDirectoryListID'] = dir_excl_dir_name
                                print(f"  Excluded Directory List: {dir_excl_dir_name}")
                                for d in excl_dirs:
                                    print(f"    - {d}")
                        else:
                            extracted['excludedDirectoryListID'] = 'None'
                        
                        excluded_files_list_id = sched_scan_config.get('excludedFileListID')
                        if excluded_files_list_id and int(excluded_files_list_id) != 0:
                            excl_files_r = requests.get(f"{BASE_URL}/filelists/{excluded_files_list_id}", headers=headers)
                            if excl_files_r.ok:
                                excl_files_data    = excl_files_r.json()
                                file_excl_file_name = excl_files_data.get('name', 'N/A')
                                excl_files         = excl_files_data.get('files', [])
                                extracted['excludedFileListID'] = file_excl_file_name
                                print(f"  Excluded File List: {file_excl_file_name}")
                                for f in excl_files:
                                    print(f"    - {f}")
                        else:
                            extracted['excludedFileListID'] = 'None'
                        excluded_file_ext_list_id = sched_scan_config.get('excludedFileExtensionListID')
                        if excluded_file_ext_list_id and int(excluded_file_ext_list_id) != 0:
                            excl_file_ext_r = requests.get(f"{BASE_URL}/fileextensionlists/{excluded_file_ext_list_id}", headers=headers)
                            if excl_file_ext_r.ok:
                                excl_file_ext_data    = excl_file_ext_r.json()
                                file_ext_excl_name   = excl_file_ext_data.get('name', 'N/A')
                                excl_file_exts       = excl_file_ext_data.get('fileExtensions', [])
                                extracted['excludedFileExtensionListID'] = file_ext_excl_name
                                print(f"  Excluded File Extension List: {file_ext_excl_name}")
                                for fe in excl_file_exts:
                                    print(f"    - {fe}")
                        else:
                            extracted['excludedFileExtensionListID'] = 'None'

                        excluded_process_image_file_list_id = sched_scan_config.get('excludedProcessImageFileListID')
                        if excluded_process_image_file_list_id and int(excluded_process_image_file_list_id) != 0:
                            excl_process_image_file_r = requests.get(f"{BASE_URL}/filelists/{excluded_process_image_file_list_id}", headers=headers)
                            if excl_process_image_file_r.ok:
                                excl_process_image_file_data    = excl_process_image_file_r.json()
                                process_image_excl_file_name   = excl_process_image_file_data.get('name', 'N/A')
                                excl_process_image_files       = excl_process_image_file_data.get('files', [])
                                extracted['excludedProcessImageFileListID'] = process_image_excl_file_name
                                print(f"  Excluded Process Image File List: {process_image_excl_file_name}")
                                for fe in excl_process_image_files:
                                    print(f"    - {fe}")
                        else:
                            extracted['excludedProcessImageFileListID'] = 'None'   
                        print(f"Policy : {name} | Scheduled Scan Config ID: {val} | Name: {sched_scan_name}")
                        for field, value in extracted.items():
                            print(f"  {field}: {value}")
                    else:
                        print(f"Error fetching anti-malware configuration for Policy: {name}, Setting: {key}, Value: {value} - Status Code: {sched_scan_r.status_code}, Response: {sched_scan_r.text}")

#                print(f"Policy: {name}, Setting: {key}, Value: {value}")
                # if 'antiMalware' in key or 'AntiMalware' in key:
                #     value = val.get('value', '') if isinstance(val, dict) else val
                #     writer.writerow([name, key, value])

    print(f'Done — saved to {output_file}')
else:
    print(f'Error {r.status_code}: {r.text}')