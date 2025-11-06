# DNS Injector

A comprehensive Python-based toolkit for DNS security research, featuring both attack and defense capabilities. This project includes a DNS injection tool for demonstrating on-path attacks and a detection system for identifying DNS poisoning attempts.

## Overview

This toolkit demonstrates DNS vulnerability exploitation and detection, providing security researchers with tools to understand DNS poisoning attacks from both offensive and defensive perspectives. The suite includes two main components: a DNS injector and a DNS poisoning detector.

## Components

### 1. DNS Injector (`dnsinject.py`)
An on-path DNS packet injector that monitors network traffic and injects forged DNS responses, demonstrating how attackers can redirect users to malicious servers.

### 2. DNS Detector (`dnsdetect.py`)
A detection system that identifies DNS poisoning attempts by analyzing duplicate responses with conflicting answers, helping network defenders identify active attacks.

## Features

### DNS Injection Tool
- **Promiscuous Mode Monitoring**: Captures DNS queries on network interfaces
- **Selective Response Forging**: Targets specific hostnames or all DNS requests
- **Custom IP Mapping**: Uses hostname files for sophisticated redirections
- **Race Condition Exploitation**: Injects responses faster than legitimate servers
- **Protocol Compliance**: Generates properly formatted DNS responses

### DNS Detection Tool
- **Real-time Monitoring**: Analyzes live network traffic for poisoning attempts
- **PCAP Analysis**: Processes captured traffic files for forensic investigation
- **Duplicate Detection**: Identifies conflicting responses for identical queries
- **False Positive Avoidance**: Handles legitimate scenarios like DNS load balancing
- **Comprehensive Logging**: Records all attack details with timestamps

## Requirements

- Python 3.5 or later
- Scapy or similar packet manipulation library
- Root/Administrator privileges (for promiscuous mode)
- Network interface with packet capture capabilities

## Installation

```bash
git clone https://github.com/yourusername/dns-injector.git
cd dns-injector
```

## Usage

### DNS Injector

```bash
python dnsinject.py [-i interface] [-h hostnames]
```

**Arguments:**
- `-i interface`: Network interface to monitor (e.g., `eth0`, `wlan0`)
  - If not specified, uses default interface
- `-h hostnames`: Path to file containing IP-hostname pairs
  - If not specified, responds to all queries with local machine's IP

**Hostname File Format:**
```
192.168.1.100 example.com
10.0.0.50 banking.com
172.16.0.10 social-media.com
```

**Examples:**

Monitor default interface and hijack all DNS queries:
```bash
sudo python dnsinject.py
```

Monitor specific interface with custom hostname mappings:
```bash
sudo python dnsinject.py -i eth0 -h targets.txt
```

### DNS Detector

```bash
python dnsdetect.py [-i interface] [-r tracefile]
```

**Arguments:**
- `-i interface`: Network interface to monitor in real-time
  - If not specified, uses default interface
- `-r tracefile`: PCAP file to analyze (tcpdump format)
  - If not specified, monitors live traffic

**Examples:**

Real-time monitoring:
```bash
sudo python dnsdetect.py -i eth0
```

Analyze captured traffic:
```bash
python dnsdetect.py -r captured_traffic.pcap
```

## How It Works

### DNS Injection Attack

1. **Packet Capture**: The tool listens in promiscuous mode for DNS queries
2. **Query Analysis**: Extracts transaction ID, source port, and queried hostname
3. **Response Crafting**: Generates forged DNS response with:
   - Matching transaction ID (TXID)
   - Correct source port
   - Specified or default IP address
   - Proper DNS headers and flags
4. **Race Condition**: Injects response before legitimate server replies
5. **Client Acceptance**: If injected packet arrives first, client accepts forged IP

**Key Security Mechanisms Bypassed:**
- TXID randomization (visible to on-path attacker)
- Source port randomization (visible to on-path attacker)
- Query/response matching (properly replicated)

### DNS Poisoning Detection

1. **Traffic Monitoring**: Captures all DNS traffic on the interface
2. **Response Tracking**: Maintains state of queries and responses
3. **Duplicate Analysis**: Identifies multiple answers to same query
4. **Conflict Detection**: Compares IP addresses in duplicate responses
5. **Attack Identification**: Flags mismatches as potential poisoning
6. **Log Generation**: Records all relevant details in `attack_log.txt`

**Detection Logic:**
- Tracks DNS responses by transaction ID
- Identifies legitimate vs. spoofed responses
- Handles timing variations (attack-first or server-first scenarios)
- Filters false positives from load balancing

## Output Files

### injection.pcap
Packet capture file containing successful DNS injection attack traffic. Filtered to show only relevant packets demonstrating the attack.

### attack_log.txt
Detection log with the following format:
```
October 20 2024 18:34:02
TXID 0x5cce Request www.example.com
Answer1 [93.184.216.34]
Answer2 [192.168.1.100]
```

Each entry includes:
- Timestamp of detection
- DNS transaction ID
- Targeted domain name
- Legitimate IP address(es)
- Malicious IP address(es)

### spoofed.txt
Detailed analysis comparing legitimate and spoofed DNS responses:
- Header field comparisons
- Modified vs. unchanged fields
- Timing characteristics
- Detection methodology

## Testing

### Testing DNS Injection

**Setup 1: VM Environment (Recommended)**
1. Run DNS injector on host OS
2. Generate DNS queries from guest VM
3. Monitor packet acceptance

**Setup 2: Local Testing**
1. Run DNS injector on local machine:
   ```bash
   sudo python dnsinject.py -i lo
   ```
2. Make DNS queries in another terminal:
   ```bash
   dig @8.8.8.8 example.com
   # or
   nslookup example.com 8.8.8.8
   ```
3. Observe injected responses

**Validation:**
- Use non-existent DNS resolver to prevent legitimate responses
- Check if `dig`/`nslookup` accepts forged response
- Verify response contains expected IP address

### Testing DNS Detection

1. **Generate attack traffic**:
   ```bash
   sudo python dnsinject.py -h targets.txt
   ```

2. **Run detector** (in separate terminal):
   ```bash
   sudo python dnsdetect.py -i eth0
   ```

3. **Make DNS queries** to trigger injection and detection

4. **Verify** `attack_log.txt` contains detected attacks

## Technical Details

### DNS Protocol Implementation

**Query Structure:**
- Transaction ID (2 bytes)
- Flags (2 bytes)
- Question count (2 bytes)
- Answer count (2 bytes)
- Authority count (2 bytes)
- Additional count (2 bytes)
- Question section
- Answer section (in responses)

**Critical Fields:**
- **TXID**: Must match query
- **QR Flag**: 0 for query, 1 for response
- **Opcode**: Standard query (0)
- **AA**: Authoritative answer
- **RD**: Recursion desired
- **RA**: Recursion available

### Performance Considerations

**Injection Speed:**
- Packet filtering reduces processing overhead
- Fast response crafting wins race condition
- Tested against Google DNS (8.8.8.8) and local resolvers

**Detection Efficiency:**
- Minimal memory footprint for query tracking
- Efficient duplicate detection algorithms
- Real-time processing with low latency

## Project Structure

```
dns-injector/
├── dnsinject.py         # DNS injection tool
├── dnsdetect.py         # DNS poisoning detector
├── injection.pcap       # Sample attack capture
├── attack_log.txt       # Detection output
├── spoofed.txt          # Analysis of spoofed responses
├── explanation1.txt     # Injection methodology
├── explanation2.txt     # Detection methodology
└── README.md           # This file
```

## Defense Strategies

Understanding these attacks enables implementation of defenses:

### Network Level
- **DNSSEC**: Cryptographic authentication of DNS responses
- **DNS-over-HTTPS (DoH)**: Encrypted DNS queries
- **DNS-over-TLS (DoT)**: Encrypted DNS transport
- **VPN**: Encrypted tunnel for all traffic

### Monitoring
- Deploy DNS poisoning detectors
- Monitor for duplicate responses
- Alert on suspicious DNS behavior
- Log all DNS transactions

### Configuration
- Use trusted DNS resolvers
- Enable DNSSEC validation
- Implement response validation
- Monitor DNS query patterns

## Known Limitations

### Injection Tool
- Cannot defeat DNSSEC
- Requires winning race condition
- Limited effectiveness against encrypted DNS
- Depends on network position

### Detection Tool
- May generate false positives with aggressive load balancing
- Requires complete traffic visibility
- Cannot detect attacks on encrypted DNS
- Timing-dependent detection

## Ethical and Legal Considerations

⚠️ **CRITICAL WARNINGS**:

### Legal Requirements
- **Authorization Required**: Only use on networks you own or have written permission to test
- **Federal Law**: DNS spoofing may violate Computer Fraud and Abuse Act (CFAA)
- **State Laws**: May violate state-specific computer crime statutes
- **Civil Liability**: Unauthorized use may result in lawsuits

### Ethical Use
- **Research Only**: Tool designed for security research and education
- **Isolated Environments**: Test in VMs, labs, or segregated networks
- **No Production Use**: Never deploy against production systems
- **Responsible Disclosure**: Report vulnerabilities through proper channels

## Future Enhancements

### Injection Tool
- [ ] Support for additional DNS record types (AAAA, MX, CNAME)
- [ ] Multi-threaded packet injection
- [ ] Advanced evasion techniques
- [ ] IPv6 support
- [ ] Configuration file support

### Detection Tool
- [ ] Machine learning-based anomaly detection
- [ ] Integration with SIEM systems
- [ ] Real-time alerting (email, SMS)
- [ ] Statistical analysis dashboard
- [ ] Historical attack pattern analysis

## Troubleshooting

### Common Issues

**"Permission denied" errors:**
- Requires root/admin privileges
- Use `sudo` on Linux/Mac

**No packets captured:**
- Verify interface name is correct
- Check promiscuous mode is enabled
- Ensure network has DNS traffic

**Injection not working:**
- Verify hostname file format
- Check network interface is active
- Ensure attacker has network path visibility
- Confirm legitimate response is slower

## Resources

- RFC 1035: Domain Names - Implementation and Specification
- DNSSEC specifications (RFC 4033-4035)
- Wireshark DNS dissector documentation
- Scapy documentation
- DNS Security Extensions (DNSSEC)
