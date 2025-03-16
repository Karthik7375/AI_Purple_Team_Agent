import subprocess

import os



def Nikto_Scan(url):

    command = ['nikto','-h',url]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout