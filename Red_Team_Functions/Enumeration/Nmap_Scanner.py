import subprocess

def run_nmap(target):
    command = ["nmap -A -o output.txt", target]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

target = "8.8.8.8"
output = run_nmap(target)
print(output)