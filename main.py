import yaml
from collectors.firewall import get_firewall_information
from collectors.firewall import get_Input_policy
from collectors.firewall import get_input_rules
from engine.policy_engine import check_input_policy
from engine.policy_engine import check_ssh_rule

firewall=get_firewall_information()

print("\n=== Firewall Rules ===")

print(firewall)

#This will return current machine is accept or drop
get_input_default=get_Input_policy()
print(get_input_default)

# Read our security policies from policies.yamal file
with open("policies/policies.yaml","r") as file:
    policies=yaml.safe_load(file)

expected_policy=policies["firewall"]["input_policy"]

result = check_input_policy(get_input_default, expected_policy)

print("Current INPUT policy:", get_input_default)
print("Expected INPUT policy:", expected_policy)
print("Result:", result)


rules = get_input_rules()

print("\n === INPUT Rules ===")

for rule in rules:
    print("Action:", rule["action"])
    print("Protocol:", rule["protocol"])
    print("Source:", rule["source"])
    print("Destination:", rule["destination"])
    print("Port:", rule["port"])
    print()


firewall_policy = policies["firewall"]["rules"]

#getting from policies.yaml
for policy in firewall_policy:
    firewall_result = check_ssh_rule(rules,policy["port"],policy["allowed"])
    print("Firewall Policy Result::", firewall_result)
