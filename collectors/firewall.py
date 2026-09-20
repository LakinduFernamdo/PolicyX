import subprocess

def get_firewall_information():
    result=subprocess.run(["sudo", "iptables", "-L", "-n"],capture_output=True,text=True)
    return result.stdout



# This is check fairewall's default rule for incoming traffic.INPUT policy = ACCEPT means By default, incoming traffic is allowed unless another rule blocks it.
# IF INPUT_policy=DROP  By default, incoming traffic is blocked unless another rule allows it.

def get_Input_policy():
    input_policy=subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n"],capture_output=True,text=True)
   
    first_line = input_policy.stdout.splitlines()[0]
    #Chain INPUT (policy ACCEPT)
    
    if "policy DROP" in first_line:
        return "DROP"
    
    if "policy ACCEPT" in first_line:
        return "ACCEPT"
    
    return "UNKNOWN"



def get_input_rules():
    result=subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n","-v"],capture_output=True,text=True)
    lines = result.stdout.splitlines()
    rules=[]

    for line in lines[2:]:
        parts = line.split()

        if len(parts) < 9:
            continue

        rule = {
            "action": parts[2],
            "protocol": parts[3],
            "source": parts[7],
            "destination": parts[8]
        }

        port = None

        for part in parts:
            if part.startswith("dpt:"):
                port = part.split(":")[1]

        rule["port"] = port
        rules.append(rule)

    return rules

        