import deepinstinct6 as di
import requests, sys, json

# Define which platform(s) of policies to migrate
platforms_to_migrate = ['WINDOWS', 'MAC']

# Define the type(s) of allow list, deny list, and exclusions to migrate
allow_deny_and_exclusion_list_types = [
    'allow-list/hashes', 'allow-list/paths', 'allow-list/certificates', 
    'allow-list/process_paths', 'allow-list/scripts', 'deny-list/hashes', 
    'exclusion-list/folder_path', 'exclusion-list/process_path'
]

#configuration parameters (optionally hardcode them here)
source_fqdn = 'FOO.customers.deepinstinctweb.com'
source_key = 'api_key_for_foo'
destination_fqdn = 'BAR.customers.deepinstinctweb.com'
destination_key = 'api_key_for_bar'

#prompt for configuration (unless hardcded values were provided above)
if source_fqdn == 'FOO.customers.deepinstinctweb.com':
    source_fqdn = input('FQDN of source DI Server? ')
if source_key == 'api_key_for_foo':
    source_key = input('API key for source server? ')
if destination_fqdn == 'BAR.customers.deepinstinctweb.com':
    destination_fqdn = input('FQDN of destination DI Server? ')
if destination_key == 'api_key_for_bar':
    destination_key = input('API key for source server (must be Full Access)? ')

# Get policies from source server
di.fqdn = source_fqdn
di.key = source_key
source_server_policies = di.get_policies(include_policy_data=True, keep_data_encapsulated=True, include_allow_deny_lists=True)

# Ensure single MSP policy migration
source_server_msp_ids = list(set(policy['msp_id'] for policy in source_server_policies))
if len(source_server_msp_ids) != 1:
    print(f'ERROR: Source server {source_fqdn} contains policies from multiple MSPs ({len(source_server_msp_ids)}).')
    sys.exit(0)

# Get policies from source server
di.fqdn = source_fqdn
di.key = source_key
source_server_policies = di.get_policies(include_policy_data=True, keep_data_encapsulated=True, include_allow_deny_lists=True)

# Ensure single MSP policy migration
source_server_msp_ids = list(set(policy['msp_id'] for policy in source_server_policies))
if len(source_server_msp_ids) != 1:
    print(f'ERROR: Source server {source_fqdn} contains policies from multiple MSPs ({len(source_server_msp_ids)}).')
    sys.exit(0)

# Get policies from destination server
di.fqdn = destination_fqdn
di.key = destination_key
destination_server_policies = di.get_policies(include_policy_data=True, keep_data_encapsulated=True)

destination_server_msp_ids = list(set(policy['msp_id'] for policy in destination_server_policies))
if len(destination_server_msp_ids) != 1:
    print(f'ERROR: Destination server {destination_fqdn} contains policies from multiple MSPs.')
    sys.exit(0)

# Check for cross-platform policy name collisions
for source_policy in source_server_policies:
    for destination_policy in destination_server_policies:
        if source_policy['name'] == destination_policy['name'] and source_policy['os'] != destination_policy['os']:
            print(f'ERROR: Policy name conflict for "{source_policy["name"]}" between different OS types.')
            sys.exit(0)

# List of policy names on destination server
destination_server_policy_names = [policy['name'] for policy in destination_server_policies]

# Dictionary of default policy IDs by platform
destination_default_policy_ids = {
    policy['os']: policy['id'] for policy in destination_server_policies if policy['is_default_policy']
}

# List policies to migrate
policies_to_migrate = [policy for policy in source_server_policies if policy['os'] in platforms_to_migrate]

print(f'INFO: Ready to migrate {len(policies_to_migrate)} policies from {source_fqdn} to {destination_fqdn}.')
user_response = input('Proceed? [YES | NO]: ').lower()
if user_response != 'yes':
    print('Terminating script. No changes made.')
    sys.exit(0)

# Fields to exclude from migration
fields_to_exclude = ['uninstall_password', 'disable_password']

# Migrate policies
for counter, policy in enumerate(policies_to_migrate, start=1):
    print(f'INFO: Migrating policy {counter} of {len(policies_to_migrate)}: {policy["name"]}')
    
    # Determine if policy already exists on destination
    if policy['name'] in destination_server_policy_names:
        new_policy = next(p for p in destination_server_policies if p['name'] == policy['name'])
        print(f'      Reusing existing policy: {new_policy["id"]}')
    else:
        new_policy = di.create_policy(policy['name'], destination_default_policy_ids[policy['os']], quiet_mode=True)
        print(f'      Created new policy: {new_policy["id"]}')
    
    # Filter out excluded fields
    filtered_policy_data = {k: v for k, v in policy['data'].items() if k not in fields_to_exclude}
    
    # Overwrite policy data on new policy
    request_url = f'https://{di.fqdn}/api/v1/policies/{new_policy["id"]}/data'
    headers = {'accept': 'application/json', 'Authorization': di.key}
    response = requests.put(request_url, json={'data': filtered_policy_data}, headers=headers)
    
    if response.status_code == 204:
        print(f'      Successfully updated policy {new_policy["id"]}')
    else:
        print(f'ERROR: Failed to update policy {new_policy["id"]}. HTTP {response.status_code}')
        sys.exit(0)
    
    # Copy allow list, deny list, and exclusions
    for list_type in allow_deny_and_exclusion_list_types:
        if list_type in policy.get('allow_deny_and_exclusion_lists', {}):
            if policy['allow_deny_and_exclusion_lists'][list_type].get('items'):
                payload = policy['allow_deny_and_exclusion_lists'][list_type]
                request_url = f'https://{di.fqdn}/api/v1/policies/{new_policy["id"]}/{list_type}'
                response = requests.post(request_url, headers=headers, json=payload)
                
                if response.status_code == 204:
                    print(f'      Copied {len(payload["items"])} entries for {list_type}')
                elif response.status_code == 404:
                    print(f'      WARNING: No API method available for {list_type} on destination server.')
                else:
                    print(f'ERROR: Failed to copy {list_type}. HTTP {response.status_code}')
                    sys.exit(0)
    
    print(f'INFO: Completed migration of policy {counter}/{len(policies_to_migrate)}: {policy["name"]}')

print(f'INFO: Successfully migrated {len(policies_to_migrate)} policies from {source_fqdn} to {destination_fqdn}.')
