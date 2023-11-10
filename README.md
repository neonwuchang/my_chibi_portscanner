# Port scanner (Linux)
A basic recon tool used for scanning ports on networks (can be used for attack or defense). Made using scapy in python, with a simple driver function for demo.
Scan 200 most common ports (list from nmap) or scan custom ports. 
Implements the following scans:
- SYN scan (TCP half-open connection)
- FIN scan
- NULL scan
- XMAS scan
- DNS scan on standard dns port (53) to check if dns server indeed exists there

