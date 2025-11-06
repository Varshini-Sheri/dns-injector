import sys
import argparse
import netifaces as nif
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, IP, TCP, UDP
import time


resp_cache = {}

def log_attack(txid, qname, valid_ips, spoofed_ips):
    """Append DNS poisoning detection details to a log file."""
    with open("attack_log.txt", "a") as log_file:
        log_file.write(f"{time.strftime('%B %d %Y %H:%M:%S')}\n")
        log_file.write(f"TXID 0x{txid:x} Request {qname.decode().rstrip('.')}\n")
        log_file.write(f"Answer1 [Legit IPs: {', '.join(valid_ips)}]\n")
        log_file.write(f"Answer2 [Malicious IPs: {', '.join(spoofed_ips)}]\n\n")

def detect_dns(pkt):
    """Check for DNS poisoning attempts in the captured packets."""
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 1:  # Ensuring it's a DNS response
                txid = pkt[DNS].id
                qd = pkt[DNS].qd
                qname = qd.qname
                
        
                valid_ips = set()
                spoofed_ips = set()

                # Check if we have a previous response for this transaction ID
                if txid in resp_cache:
                    prev_pkt = resp_cache[txid]
                    prev_ips = {prev_pkt[DNSRR][i].rdata for i in range(prev_pkt[DNS].ancount)}

                    # Analyze current DNS response for potential spoofing
                    for i in range(pkt[DNS].ancount):
                        if pkt[DNSRR][i].type == 1:  # Check for A records
                            curr_ip = pkt[DNSRR][i].rdata
                            if curr_ip not in prev_ips:
                                # DNS spoofing detected
                                print(time.strftime("%Y-%m-%d %H:%M") + " DNS poisoning attempt detected")
                                print("TXID [%s] Request [%s]" % (txid, qname.decode().rstrip('.')))
                                
                                # Collect legitimate and malicious responses
                                valid_ips.update(prev_ips)
                                spoofed_ips.add(curr_ip)
                                
                                # Log the attack details
                                log_attack(txid, qname, valid_ips, spoofed_ips)

                # Store the current DNS response in the cache
                resp_cache[txid] = pkt

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DNS Poisoning Detector")
    default_iface = nif.gateways()['default'][nif.AF_INET][1]  # Default network interface
    parser.add_argument("-i", "--interface", help="Specify the network interface to listen on")
    parser.add_argument("-r", "--tracefile", help="Read packets from a trace file (tcpdump format)")
    parser.add_argument("expr", nargs='*', action="store", default='', help="BPF Filter for packet capturing")
    
    args = parser.parse_args()
    
    # Packet sniffing based on provided arguments
    if args.tracefile:
        sniff(filter=str(args.expr), offline=str(args.tracefile), store=0, prn=detect_dns)
    elif args.interface:
        sniff(filter=str(args.expr), iface=str(args.interface), store=0, prn=detect_dns)
    else:
        sniff(filter=str(args.expr), store=0, prn=detect_dns)

