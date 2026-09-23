import subprocess
import re
import pwd

POLICY = {
    "kali": {
        "allowed_commands": [
            "whoami",
            "id",
            "systemctl"
        ]
    }
}

def get_audit_events():
    result = subprocess.run(
        ["sudo", "ausearch", "-m", "USER_CMD", "-ts", "recent"],
        capture_output=True,
        text=True
    )

    return result.stdout


def parse_event(event):
    uid_match = re.search(r"uid=(\d+)", event)
    cmd_match = re.search(r'cmd="([^"]+)"|cmd=([0-9A-Fa-f]+)', event)
    result_match = re.search(r"res=(\w+)", event)

    if not uid_match or not cmd_match or not result_match:
        return None

    uid = int(uid_match.group(1))
    username = pwd.getpwuid(uid).pw_name

    if cmd_match.group(1):
        command = cmd_match.group(1)
    else:
        command = bytes.fromhex(cmd_match.group(2)).decode(
            "utf-8",
            errors="replace"
        )

    result = result_match.group(1)

    return {
        "user": username,
        "command": command,
        "result": result
    }

def check_policy(user, command):

    if user not in POLICY:
        return "VIOLATION"

    command_name = command.split()[0]

    if command_name in POLICY[user]["allowed_commands"]:
        return "PASS"

    return "VIOLATION"


output = get_audit_events()

events = output.split("----")

for event in events:

    parsed = parse_event(event)

    if parsed:

        policy_result = check_policy(
            parsed["user"],
            parsed["command"]
        )

        print("User:", parsed["user"])
        print("Command:", parsed["command"])
        print("Result:", parsed["result"])
        print("Policy:", policy_result)
        print("--------------------")
