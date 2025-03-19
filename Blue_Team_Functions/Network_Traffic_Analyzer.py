import scapy
import pyshark



def Network_Traffic_Analysis(file):
    #Only analyze the file if the file is a wirshark or tshark file
    if file.endswith(".pcap") or file.endswith(".pcapng"):
        pass
    else:
        return None
