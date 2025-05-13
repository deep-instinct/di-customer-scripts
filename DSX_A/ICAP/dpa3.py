# Library file which defines methods for sending files to agentless for scanning
# and returns verdict.
# For DPA 3.X
#
# DEEP INSTINCT MAKES NO WARRANTIES OR REPRESENTATIONS REGARDING DEEP INSTINCT’S 
# PROGRAMMING SCRIPTS. TO THE FULLEST EXTENT PERMITTED BY APPLICABLE LAW, 
# DEEP INSTINCT DISCLAIMS ALL OTHER WARRANTIES, REPRESENTATIONS AND CONDITIONS, 
# WHETHER EXPRESS, STATUTORY, OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, ANY 
# IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR 
# NON-INFRINGEMENT, AND ANY WARRANTIES ARISING OUT OF COURSE OF DEALING OR USAGE 
# OF TRADE. DEEP INSTINCT’S PROGRAMMING SCRIPTS ARE PROVIDED ON AN "AS IS" BASIS, 
# WITHOUT WARRANTY OF ANY KIND, AND DEEP INSTINCT DISCLAIMS ALL OTHER WARRANTIES, 
# EXPRESS, IMPLIED OR STATUTORY, INCLUDING ANY IMPLIED WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.
#
#

#Import required libraries
import requests, base64, json, urllib3

#Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Primary method which accepts file name and optional config data, submits scan, simplifies it, and returns result
def scan_file(file_name, scanner_ip, simplified=False, encoded=False, scanner_port=80, protocol='http'):

    # read file from disk (rb means opens the file in binary format for reading)
    with open(file_name, 'rb') as f:
        #read file
        data = f.read()
        #close file
        f.close()

    if encoded:
        #encode data and set URL to match
        data = base64.b64encode(data)
        request_url = f'{protocol}://{scanner_ip}:{scanner_port}/scan/base64'
    else:
        #leave data as-is and set URL to match
        request_url = f'{protocol}://{scanner_ip}:{scanner_port}/scan/binary'

    # send scan request, capture response
    response = requests.post(request_url, data=data, timeout=20, verify=False)

    # validate response code and proceed if expected value 200
    if response.status_code == 200:
        #convert to Python dictionary
        verdict = response.json()
        if simplified:
            #Call function to simplify the verdict
            verdict = simplify_verdict(verdict)
        #Return [simplified] verdict
        return verdict
    else:
        print('ERROR: Unexpected return code', response.status_code, 'on POST to', request_url)
        return None


#Wrapper which invokes scan_file with the parameter to use encoding
def scan_file_encoded(file_name, scanner_ip, simplified=False):
    return scan_file(file_name=file_name, scanner_ip=scanner_ip, simplified=simplified, encoded=True)


# A method used to convert the raw verdict received from DI Agentless into a simplified/more user-friendly format
# --> Recommend to use this with an Agentless Policy where "prevention" is enabled at Threat Severity "Low" and above
# --> This method introduces the concept of a "Suspicious" verdict, which is for files that score Low or Moderate
def simplify_verdict(verdict):

    if 'verdict' not in verdict.keys():
        print('ERROR: The verdict passed to simplify_verdict is missing or corrupt:\n', verdict)
        return None

    else:
        #remove the redundent text 'filetype' from the file type value, if present
        if 'file_type' in verdict.keys():
            verdict['file_type'] = verdict['file_type'].replace('FileType','')

        if verdict['verdict'] == 'Malicious':

            if verdict['severity'] in ['VERY_HIGH', 'HIGH']:

                return {'verdict': 'Malicious',
                        'file_type': verdict['file_type'],
                        'threat_severity': verdict['severity'],
                        'file_hash': verdict['file_hash'],
                        'scan_guid': verdict['scan_guid']}

            else:

                return {'verdict': 'Suspicious',
                        'file_type': verdict['file_type'],
                        'threat_severity': verdict['severity'],
                        'file_hash': verdict['file_hash'],
                        'scan_guid': verdict['scan_guid']}

        elif verdict['verdict'] == 'Benign':

            return {'verdict': 'Benign',
                    'file_type': verdict['file_type'],
                    'file_hash': verdict['file_hash'],
                    'scan_guid': verdict['scan_guid']}

        elif verdict['verdict'] == 'Not Classified':
            return {'verdict': 'Unsupported',
                    'file_type': 'Other',
                    'scan_guid': verdict['scan_guid']}

        else:
            print('WARNING: Error in processing verfict passed to simplify_verdict:\n', verdict)
            return None

#Console functions for DPA Deployment

def create_scanner_cluster(name, comment, default_protected_entity_id, policy_id, msp_id):
    headers = {'accept': 'application/json', 'Authorization': key}
    request_url = f'https://{fqdn}/api/v1/application-security/scanners/'
    payload = {'name': name, 'comment': comment, 'default_protected_entity_id': default_protected_entity_id, 'policy_id': policy_id, 'msp_id': msp_id}
    
    response = requests.post(request_url, json=payload, headers=headers)
    
    #return data
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401:
        print('UNAUTHORIZED')
    elif response.status_code == 403:
        print('FORBIDDEN')
    elif response.status_code == 404:
        print('Policy not found/MSP not found')
    elif response.status_code == 409:
        print('Scanner with that name already exists')
    elif response.status_code == 422:
        print('Invalid scanner name (must contain 2-50 characters)/Policy OS must be application security')
    else:
        return []
        
def create_protected_entity(name, msp_id, tenant_id, comment):
    headers = {'accept': 'application/json', 'Authorization': key}
    request_url = f'https://{fqdn}/api/v1/application-security/protected_entities/'
    payload = {'name': name, 'msp_id': msp_id, 'tenant_id': tenant_id, 'comment': comment}
    
    response = requests.post(request_url, json=payload, headers=headers)
    
    #return data
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401:
        print('UNAUTHORIZED')
    elif response.status_code == 403:
        print('FORBIDDEN')
    elif response.status_code == 404:
        print('Policy not found/MSP not found')
    elif response.status_code == 409:
        print('Protected entity with that name already exists')
    elif response.status_code == 422:
        print('Invalid protected entity name (must contain 2-50 characters)')
    else:
        return []
        
def get_policies(include_policy_data=False, include_allow_deny_lists=False, keep_data_encapsulated=False, msp_id='ALL', os_list = ['ANDROID', 'IOS', 'WINDOWS', 'MAC', 'CHROME', 'NETWORK_AGENTLESS', 'LINUX']):
    # GET POLICIES (basic data only)

    # Calculate headers and URL
    headers = {'accept': 'application/json', 'Authorization': key}
    request_url = f'https://{fqdn}/api/v1/policies/'

    # Get data, convert to Python list
    response = requests.get(request_url, headers=headers)
    policies = response.json()

    # Apply filter based on msp, if enabled
    if msp_id != 'ALL':
        filtered_policies = []
        for policy in policies:
            if policy['msp_id'] == msp_id:
                filtered_policies.append(policy)
        policies = filtered_policies

    # Apply filter based on os_list
    filtered_policies = []
    for policy in policies:
        if policy['os'] in os_list:
            filtered_policies.append(policy)
    policies = filtered_policies

    # APPEND POLICY DATA (IF ENABLED)
    if include_policy_data:
        print('INFO: Collecting policy data for', len(policies), 'policies')
        # Iterate through policy list
        for policy in policies:
            # Extract ID, calculate URL, and pull policy data from server
            policy_id = policy['id']
            request_url = f'https://{fqdn}/api/v1/policies/{policy_id}/data'
            response = requests.get(request_url, headers=headers)
            #if not quiet_mode:
            #    print(request_url, 'returned', response.status_code)
            # Check response code (for some platforms, no policy data available)
            if response.status_code == 200:
                print(request_url, 'returned', response.status_code)
                # Extract policy data from response and append it to policy
                if keep_data_encapsulated:
                    policy_data = response.json()
                else:
                    policy_data = response.json()['data']
                policy.update(policy_data)
        if not quiet_mode:
            print('\n')

    # APPEND ALLOW-LIST, DENY-LIST, AND EXCLUSION DATA (IF ENABLED)
    if include_allow_deny_lists:

        allow_deny_and_exclusion_list_types = [
            'allow-list/hashes',
            'allow-list/paths',
            'allow-list/certificates',
            'allow-list/process_paths',
            'allow-list/scripts',
            'deny-list/hashes',
            'exclusion-list/folder_path',
            'exclusion-list/process_path'
        ]

        print('INFO: Collecting', len(allow_deny_and_exclusion_list_types), 'allow, deny, and exclusion list data types for', len(policies), 'policies')
        # Iterate through policy list
        for policy in policies:

            # Extract the policy id, which is used in subsequent requests
            policy_id = policy['id']

            #create a dictionary in the policy to store this data
            policy['allow_deny_and_exclusion_lists'] = {}

            #iterate through list types to migrate
            for list_type in allow_deny_and_exclusion_list_types:

                request_url = f'https://{fqdn}/api/v1/policies/{policy_id}/{list_type}'
                response = requests.get(request_url, headers=headers)
                print(request_url, 'returned', response.status_code, end='\r')
                if response.status_code == 200:
                    response = response.json()
                    policy['allow_deny_and_exclusion_lists'][list_type] = response
        if not quiet_mode:
            print('\n')

    # RETURN THE COLLECTED DATA
    return policies
    
def get_protected_entity_ids():

    # Calculate headers and URL
    headers = {'accept': 'application/json', 'Authorization': key}
    request_url = f'https://{fqdn}/api/v1/application-security/protected_entities/'
    # Get Protected Entities from server
    response = requests.get(request_url, headers=headers)
    #Check response code
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        print('Scanner Not Found')
    else:
        #in case of error getting data, return error
        print('Invalid Request')