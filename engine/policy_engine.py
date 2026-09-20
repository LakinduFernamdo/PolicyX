def check_input_policy(actual, expected):
    if actual == expected:
        return "PASS"

    return "VIOLATION"


#create policy for ssh rule

def check_ssh_rule(rules,expected_port,should_be_allowed):
    for rule in rules:
        if rule["protocol"]=="tcp" and rule["port"]== str(expected_port):
            if rule["action"]=="ACCEPT":
                if should_be_allowed:
                    return "PASS"
                else:
                    return "VIOLATION"
                
    return "PASS or No matching ACCEPT rule" 