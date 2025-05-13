import dpa3 as di
import json

#set server name
di.fqdn = input("D-Appliance name: ")
di.key = input("Full access key: ")

while True:

    name = input("Protected Entity Name: ")
    msp_id = 1
    tenant_id = 1
    comment = input("Comment: ")

    protected_entity = di.create_protected_entity(name, msp_id, tenant_id, comment)

    print(json.dumps(protected_entity, indent=4))

    user_input = input("Do you want to create another Protected Entity? (yes/no): ").lower()
    if user_input == 'no':
        break
    elif user_input == 'yes':
        continue
    else:
        print('Invalid Input')
        break
