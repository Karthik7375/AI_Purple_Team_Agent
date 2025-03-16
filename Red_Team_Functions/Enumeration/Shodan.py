import re
import shodan
import os
import subprocess


#Implementing a search with the shodan api key

"""
Note: This is done with only a shodan api key available for a free account here.
If a subscription account is used, you can search anything with their limitations to the subscription you have purchased
"""
import requests

ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Matches xxx.xxx.xxx.xxx
ipv6_pattern = r"\b(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+\b"  # Matches IPv6 format

def extract_ipv4(website_url):

    try:
        hostname = "google.com"
        result = subprocess.run(["nslookup", hostname], capture_output=True, text=True)
        #print(result.stdout)
        return result.stdout
    except Exception as e:
        print("Exception occured", e)
        return None

public_ip = extract_ipv4("https://google.com")
if public_ip:
    print("\n\n\nPublic IP")
    print(public_ip,type(public_ip),list(public_ip.split("\n")))


information = list(public_ip.split("\n"))

#Extract the relevant info alone
Server = information[0]
Server_address = information[1]
Website = information[3]
Website_address_ipv6 = information[4]
Website_address_ipv4 = information[5]

ipv4_addr = ipv4_pattern.find(Website_address_ipv4)
print(Website_address_ipv4)

def Shodan_Scan(content):
    target = content
    try:
        api = shodan.Shodan("Tq5vJrqxqNAZ0BLSsOmWEO1Dhvby1XCy")
        account_info = api.info()  # Check API details
        print(account_info)
    except shodan.APIError as e:
        print("Exception occured: ",e)
        return e

Shodan_Scan('nginx')