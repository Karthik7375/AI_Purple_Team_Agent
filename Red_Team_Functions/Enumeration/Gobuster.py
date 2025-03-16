import subprocess

from openpyxl.styles.builtins import output


def run_gobuster(target, wordlist, output_file):
    command = [
        r"C:\Tools\gobuster\gobuster.exe", "dir", "-u", target, "-w", wordlist,
        "-t", "50",  # Number of threads
        "-s", "200,204,301,302,307,403",  # Status codes to follow
        "-o", output_file  # Output file
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


target = "8.8.8.8/"
wordlist = "Dirbuster.txt"
output_file = "Gobuster.xlsx"
output = run_gobuster(target, wordlist, output_file)
print(output)