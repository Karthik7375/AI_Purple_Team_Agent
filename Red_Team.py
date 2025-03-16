import socket
import requests
import psutil

class Red_Team_Agent:
    def __init__(self):
        pass

    def get_ip_addresses(self, domain):
        """Get IPv4 and IPv6 addresses for a given domain."""
        try:
            # Get IPv4 addresses
            ipv4_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
            ipv4_list = [addr[4][0] for addr in ipv4_addresses]

            # Get IPv6 addresses
            ipv6_addresses = socket.getaddrinfo(domain, None, socket.AF_INET6)
            ipv6_list = [addr[4][0] for addr in ipv6_addresses]

            return ipv4_list, ipv6_list
        except socket.gaierror as e:
            print(f"Error retrieving IP addresses: {e}")
            return [], []

    def get_public_ip(self):
        """Get the public IPv4 and IPv6 addresses."""
        try:
            # Get public IPv4 address
            ipv4_response = requests.get('https://api.ipify.org?format=json')
            ipv4 = ipv4_response.json().get('ip')

            # Get public IPv6 address
            ipv6_response = requests.get('https://api64.ipify.org?format=json')
            ipv6 = ipv6_response.json().get('ip')

            return ipv4, ipv6
        except requests.RequestException as e:
            print(f"Error retrieving public IP: {e}")
            return None, None

    def get_private_ip(self):
        """Get the private IP address of the machine."""
        try:
            # Create a socket connection to an external address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Connect to a public DNS server
            private_ip = s.getsockname()[0]
            s.close()
            return private_ip
        except Exception as e:
            print(f"Error retrieving private IP address: {e}")
            return None

    def get_all_private_ips(self):
        """Get all private IP addresses associated with the machine's network interfaces."""
        private_ips = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    private_ips.append(addr.address)
        return private_ips

# Example usage
if __name__ == "__main__":
    agent = Red_Team_Agent()

    # Get IP addresses for a domain
    domain = 'example.com'
    ipv4, ipv6 = agent.get_ip_addresses(domain)
    print("IPv4 Addresses:", ipv4)
    print("IPv6 Addresses:", ipv6)

    # Get public IP addresses
    public_ipv4, public_ipv6 = agent.get_public_ip()
    print("Public IPv4 Address:", public_ipv4)
    print("Public IPv6 Address:", public_ipv6)

    # Get private IP address
    private_ip = agent.get_private_ip()
    print("Private IP Address:", private_ip)

    # Get all private IP addresses
    all_private_ips = agent.get_all_private_ips()
    print("All Private IP Addresses:", all_private_ips)