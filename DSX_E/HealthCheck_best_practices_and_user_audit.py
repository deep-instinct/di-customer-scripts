import deepinstinct4 as di
import datetime, pandas, json, re
import json
import requests
import collections
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)


def main():

    include_user_account_list, account_management_api_key = prompt_user_for_config()
     
    print('\nGathering Windows policy data using API\n')
    policies = di.get_policies(os_list = ['WINDOWS'], include_policy_data=True,)

    print('\nChecking if server is multi-tenancy')
    mt = di.is_server_multitenancy_enabled()
    print(mt)

    print('\nChecking if we have policy data from >1 MSP')
    multi_msp = data_from_more_than_one_msp(policies)
    print(multi_msp)

    # Error checking new policy data output for DI 4
    #print('\nPolicy dictionary:\n')
    #print(policies)

    print('\nBuilding results')
    results = build_results(policies, multi_msp)

    print('\nAdding group count information to results\n')
    results, groups = add_group_counts(results)

    print('\nAdding device count information to results\n')
    results, devices = add_device_counts(results)

    print('\nConverting results to DataFrame')
    results_df = pandas.DataFrame(results)

    print('\nSorting results')
    if multi_msp:
        results_df.sort_values(by=['MSP Name','Name'], inplace=True)
    else:
        results_df.sort_values(by=['Name'], inplace=True)

    print('\nModifying column order')
    if multi_msp:
        results_df = move_df_column_to_position(results_df, 'Group Count', 4)
        results_df = move_df_column_to_position(results_df, 'Device Count', 5)
    else:
        results_df = move_df_column_to_position(results_df, 'Group Count', 2)
        results_df = move_df_column_to_position(results_df, 'Device Count', 3)

    print('\nComparing Data to Best Practices and applying conditional formatting to DataFrame')
    results_df_stylized = evaluate_and_apply_conditional_formatting(results_df)

    print('\nBuilding Group List (used for Configuration Document at project closure)')
    groups_df = generate_group_list(groups, devices, policies, mt)

    if include_user_account_list:
        print('\nGetting list of users (used for Configuration Document at project closure)')
        di.key = account_management_api_key
        users = di.get_users()
        users_df = pandas.DataFrame(users)

        #workaround to inconsistencies in columns returned by get_users depending upon data and server config
        if 'msp_id' not in users_df.columns:
            users_df.insert(0,'msp_id','')
        if 'msp_name' not in users_df.columns:
            users_df.insert(0,'msp_name','')
        if 'tenant_id' not in users_df.columns:
            users_df.insert(0,'tenant_id','')

        users_df['last_login'] = pandas.to_datetime(users_df.last_login, format='%Y-%m-%d %H:%M:%S').dt.strftime('%Y-%m-%d')
        users_df['role'] = users_df['role'].str.title()
        users_df.pop('auth_type')
        users_df.pop('id')
        users_df.pop('email')
        users_df['role'] = users_df['role'].str.replace('_', ' ')
        users_df['last_login_days_ago'] = (pandas.to_datetime(pandas.to_datetime('now').strftime('%Y-%m-%d')) - pandas.to_datetime(users_df['last_login'])).dt.days
        users_df.sort_values(by=['role', 'username'], inplace=True)
        users_df = users_df.fillna('')
        users_df = move_df_column_to_position(users_df, 'role', 0)
        users_df = move_df_column_to_position(users_df, 'username', 1)
        users_df = move_df_column_to_position(users_df, 'first_name', 2)
        users_df = move_df_column_to_position(users_df, 'last_name', 3)
        users_df = move_df_column_to_position(users_df, 'last_login', 4)
        users_df = move_df_column_to_position(users_df, 'last_login_days_ago', 5)
        users_df.rename(columns={'role': 'Role', 'username': 'User Name', 'first_name': 'First Name', 'last_name': 'Last Name', 'last_login': 'Last Login', 'last_login_days_ago': 'Days Ago'}, inplace=True)
    else:
        users_df = pandas.DataFrame([])
    users_df_styliyzed = users_df.style.applymap(highlight_days_ago, subset=['Days Ago'])

    print('\nExporting data to disk\n')
    folder_name = di.create_export_folder()
    file_name = calculate_export_file_name(policies, mt, multi_msp)
    export_results(results_df, results_df_stylized, f'{folder_name}/{file_name}', groups_df, include_user_account_list, users_df, users_df_styliyzed, mt, multi_msp)


def highlight_days_ago(actual):
    if actual == '': #never logged in
        color = '#FFB3BA' #light red
    elif actual >= 60: #last login 2+ months ago
        color = '#FFB3BA' #light red
    elif actual >= 30: #last login 1+ month ago
        color = '#FFFF8F' #yellow
    else: #last login is less than 1 month ago
        color = '#FFFFFF' #white
    return 'background-color: {}'.format(color)


def generate_group_list(groups, devices, policies, mt):
    group_table = []
    if mt:
        msps = di.get_msps()
    for group in groups:
        if group['os'] == 'WINDOWS':
            group['devices'] = 0
            for device in devices:
                if group['id'] == device['group_id']:
                    group['devices'] += 1
            for policy in policies:
                if group['policy_id'] == policy['id']:
                    group['policy_name'] = policy ['name']
            result = {}
            if mt:
                for msp in msps:
                    if group['msp_id'] == msp['id']:
                        group['msp_name'] = msp['name']
                result['MSP Name'] =  group['msp_name']
            result['Group Name'] = group['name']
            result['Policy Name'] = group['policy_name']
            result['Device Count'] = group['devices']
            group_table.append(result)
    groups_df = pandas.DataFrame(group_table)
    return groups_df

def prompt_user_for_config():
    di.fqdn = input('FQDN: ')
    if di.fqdn == '':
        di.fqdn = 'di-service.customers.deepinstinctweb.com'
    di.key = input('API Key 1 of 2- Full Access or Read Only): ')
    account_management_api_key = input('API Key 2 of 2 - Account Management (to skip export of Administrator Account list, leave blank): ')
    if len(account_management_api_key) > 0:
        return True, account_management_api_key
    else:
        return False, account_management_api_key

def data_from_more_than_one_msp(policies):
    policy_msp_ids = []
    for policy in policies:
        if policy['msp_id'] not in policy_msp_ids:
            policy_msp_ids.append(policy['msp_id'])
    if len(policy_msp_ids) > 1:
        return True
    else:
        return False


def highlight_cells(actual, expected):
    if str(expected).lower() == str(actual).lower():
        color = '#BAFFC9' #light green
    else:
        color = '#FFB3BA' #light red
    return 'background-color: {}'.format(color)


def evaluate_and_apply_conditional_formatting(df):

    #define lists of fields that are expected to have particular values
    should_be_prevent = ['Known PUA', 'Ransomware Behavior', 'Arbitrary Shellcode', 'Remote Code Injection',
                        'Reflective DLL Injection', '.Net Reflection', 'AMSI Bypass', 'Credential Dumping', 'Known Payload Executionn',
                        'HTML Applications', 'ActiveScript Execution - If allowed by Windows, action when non-allow-listed script runs',
                        'Suspicious Script Execution', 'Malicious PowerShell Command Execution', 'Malicious JavaScript Execution']
    should_be_allow = ['Dual use tools', 'Suspicious PowerShell Command Execution', 'PowerShell execution', 'Embedded DDE in Office files']
    should_be_true = ['Enable D-Cloud Services', 'Scan Files Accessed from Network', 'In-Memory Protection']
    should_be_false = ['Upgrades Enabled','Suspicious Activity Detection']
    should_be_moderate = ['PE Detection Threshold', 'PE Prevention Threshold']
    should_be_use_d_brain = ['Macro Execution']
    should_be_default_windows_action = ['ActiveScript Execution - When ActiveScripts are executed']

    #for each of the lists above, check actual versus expected and apply conditional formatting
    s = df.style.applymap(highlight_cells, expected='prevent', subset=should_be_prevent)
    s = s.applymap(highlight_cells, expected='allow', subset=should_be_allow)
    s = s.applymap(highlight_cells, expected='true', subset=should_be_true)
    s = s.applymap(highlight_cells, expected='false', subset=should_be_false)
    s = s.applymap(highlight_cells, expected='moderate', subset=should_be_moderate)
    s = s.applymap(highlight_cells, expected='use_d_brain', subset=should_be_use_d_brain)
    s = s.applymap(highlight_cells, expected='default windows action', subset=should_be_default_windows_action)


    return s


def build_results(policies, multi_msp):
    results = []
    for policy in policies:
        result = {}
        if multi_msp:
            result['MSP ID'] = policy['msp_id']
            result['MSP Name'] = policy['msp_name']
        result['ID'] = policy['id']
        result['Name'] = policy['name']
        if 'automatic_upgrade' in policy.keys():
            result['Upgrades Enabled'] = str(policy['automatic_upgrade']).capitalize()
        
        if 'enable_dcloud_services' in policy.keys():
            result['Enable D-Cloud Services'] = str(policy['enable_dcloud_services']).capitalize()
            if result['Enable D-Cloud Services'] == '1':
                result['Enable D-Cloud Services'] = 'True'
        
        if 'scan_network_drives' in policy.keys():
            result['Scan Files Accessed from Network'] = str(policy['scan_network_drives']).capitalize()

        if 'detection_level' in policy.keys():
            result['PE Detection Threshold'] = policy['detection_level'].capitalize()
            if result['PE Detection Threshold'] == 'Medium':
                result['PE Detection Threshold'] = 'Moderate'

        if 'prevention_level' in policy.keys():
            result['PE Prevention Threshold'] = policy['prevention_level'].capitalize()
            if result['PE Prevention Threshold'] == 'Medium':
                result['PE Prevention Threshold'] = 'Moderate'

        if 'protection_level_pua' in policy.keys():
            result['Known PUA'] = str(policy['protection_level_pua']).capitalize()

        if 'dual_use' in policy.keys():
            result['Dual use tools'] = str(policy['dual_use']).capitalize()

        if 'embedded_dde_object_in_office_document' in policy.keys():
            result['Embedded DDE in Office files'] = str(policy['embedded_dde_object_in_office_document']).capitalize()

        if 'office_macro_script_action' in policy.keys():
            result['Macro Execution'] = str(policy['office_macro_script_action']).capitalize()

        if 'suspicious_activity_detection' in policy.keys():
            result['Suspicious Activity Detection'] = str(policy['suspicious_activity_detection']).capitalize()

        if 'in_memory_protection' in policy.keys():
            result['In-Memory Protection'] = str(policy['in_memory_protection']).capitalize()

        if 'ransomware_behavior' in policy.keys():
            result['Ransomware Behavior'] = policy['ransomware_behavior'].capitalize()

        if 'arbitrary_shellcode_execution' in policy.keys():    
            result['Arbitrary Shellcode'] = policy['arbitrary_shellcode_execution'].capitalize()

        if 'remote_code_injection' in policy.keys():
            result['Remote Code Injection'] = policy['remote_code_injection'].capitalize()

        if 'reflective_dll_loading' in policy.keys():
            result['Reflective DLL Injection'] = policy['reflective_dll_loading'].capitalize()

        if 'reflective_dotnet_injection' in policy.keys():  
            result['.Net Reflection'] = policy['reflective_dotnet_injection'].capitalize()

        if 'amsi_bypass' in policy.keys():
            result['AMSI Bypass'] = policy['amsi_bypass'].capitalize()
        
        if 'credentials_dump' in policy.keys():
            result['Credential Dumping'] = policy['credentials_dump'].capitalize()
        
        if 'known_payload_execution' in policy.keys():
            result['Known Payload Executionn'] = policy['known_payload_execution'].capitalize()

        if 'suspicious_script_execution' in policy.keys():
            result['Suspicious Script Execution'] = policy['suspicious_script_execution'].capitalize()

        if 'malicious_powershell_command_execution' in policy.keys():
            result['Malicious PowerShell Command Execution'] = policy['malicious_powershell_command_execution'].capitalize()

        if 'malicious_js_command_execution' in policy.keys():
            result['Malicious JavaScript Execution'] = str(policy['malicious_js_command_execution']).capitalize()

        if 'suspicious_powershell_command_execution' in policy.keys():
            result['Suspicious PowerShell Command Execution'] = policy['suspicious_powershell_command_execution'].capitalize()

        if 'powershell_script_action' in policy.keys():
            result['PowerShell execution'] = policy['powershell_script_action'].capitalize()

        if 'html_applications_action' in policy.keys():
            result['HTML Applications'] = policy['html_applications_action'].capitalize()

        if 'prevent_all_activescript_usage' in policy.keys():
            if policy['prevent_all_activescript_usage'] == 'PREVENT':
                result['ActiveScript Execution - When ActiveScripts are executed'] = 'Block all using windows'
            else:
                result['ActiveScript Execution - When ActiveScripts are executed'] = 'Default Windows action'

        if 'activescript_action' in policy.keys():
            result['ActiveScript Execution - If allowed by Windows, action when non-allow-listed script runs'] = policy['activescript_action'].capitalize()


        results.append(result)
    return results


def calculate_export_file_name(policies, mt, multi_msp):
    if mt and not multi_msp:
        server_shortname = re.sub(r'[^a-z0-9]','',policies[0]['msp_name'].lower())
    else:
        server_shortname = di.fqdn.split(".",1)[0]
    file_name = f'policy_audit_{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H.%M")}_UTC_{server_shortname}.xlsx'
    return file_name


def move_df_column_to_position(df, column_name, new_position):
    column_to_move = df.pop(column_name)
    df.insert(new_position, column_name, column_to_move)
    return df


def export_results(results_df, results_df_stylized, file_name, groups_df, include_user_account_list, users_df, users_df_styliyzed, mt, multi_msp):

    with pandas.ExcelWriter(file_name) as writer:

        results_df_stylized.to_excel(writer, sheet_name='Policy Audit', index=False, na_rep='')
        for column in results_df:
            column_width = max(results_df[column].astype(str).map(len).max(), len(column)) + 1
            col_idx = results_df.columns.get_loc(column)
            writer.sheets['Policy Audit'].set_column(col_idx, col_idx, column_width)

        groups_df.to_excel(writer, sheet_name='Group List', index=False, na_rep='')
        for column in groups_df:
            column_width = max(groups_df[column].astype(str).map(len).max(), len(column)) + 1
            col_idx = groups_df.columns.get_loc(column)
            writer.sheets['Group List'].set_column(col_idx, col_idx, column_width)

        if mt and multi_msp:
            policy_list_df = results_df[['MSP Name', 'Name', 'Group Count', 'Device Count']].copy()
        else:
            policy_list_df = results_df[['Name', 'Group Count', 'Device Count']].copy()
        policy_list_df.rename(columns={'Name': 'Policy Name'}, inplace=True)

        policy_list_df.to_excel(writer, sheet_name='Policy List', index=False, na_rep='')
        for column in policy_list_df:
            column_width = max(policy_list_df[column].astype(str).map(len).max(), len(column)) + 1
            col_idx = policy_list_df.columns.get_loc(column)
            writer.sheets['Policy List'].set_column(col_idx, col_idx, column_width)

        if include_user_account_list:
            users_df_styliyzed.to_excel(writer, sheet_name='Administrator Accounts', index=False, na_rep='')
            for column in users_df:
                column_width = max(users_df[column].astype(str).map(len).max(), len(column)) + 1
                col_idx = users_df.columns.get_loc(column)
                writer.sheets['Administrator Accounts'].set_column(col_idx, col_idx, column_width)


    print('Results written to disk as', file_name, '\n')


def add_device_counts(policy_list):
    print('Collecting device data')

    device_method = input("Bulk-Get devices? [True/False] (Only chose false when prompted by script failure): ")

    if device_method == 'True':
        devices = di.get_devices()
    else:
        devices = di.get_devices_by_one()
    device_counts = di.count_data_by_field(devices, 'policy_id')
    print('Adding device counts to policies')
    for policy in policy_list:
        if policy['ID'] not in device_counts.keys():
            policy['Device Count'] = 0
        else:
            policy['Device Count'] = device_counts[policy['ID']]
        print('Policy', policy['ID'], 'has', policy['Device Count'], 'devices' )
    return policy_list, devices


def add_group_counts(policy_list):
    print('Collecting group data')
    groups = di.get_groups()
    group_counts = di.count_data_by_field(groups, 'policy_id')
    print('Adding group counts to policies')
    for policy in policy_list:
        if policy['ID'] not in group_counts.keys():
            policy['Group Count'] = 0
        else:
            policy['Group Count'] = group_counts[policy['ID']]
        print('Policy', policy['ID'], 'is used by', policy['Group Count'], 'groups' )
    return policy_list, groups


if __name__ == "__main__":
    main()
