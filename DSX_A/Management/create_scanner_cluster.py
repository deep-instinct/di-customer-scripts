import dpa3 as di
import json

#set server name
di.fqdn = input("D-Appliance name: ")
di.key = input("Full access key: ")

name = input("Scanner Cluster Name: ")
comment = input("Comment: ")
protected_entities = di.get_protected_entity_ids()
print(json.dumps(protected_entities, indent=4))
default_protected_entity_id = int(input("Protected Entity ID: "))
policies = di.get_policies(os_list = ['APPLICATION_SECURITY'])
print(json.dumps(policies, indent=4))
policy_id = int(input("Policy ID: "))
msp_id = 1

scanner_id = di.create_scanner_cluster(name, comment, default_protected_entity_id, policy_id, msp_id)

print(json.dumps(scanner_id, indent=4))