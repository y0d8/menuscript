#!/usr/bin/env python3
"""Test nmap parser"""
from menuscript.parsers.nmap_parser import parse_nmap_text

# Sample nmap output
sample_output = """
Starting Nmap 7.94 ( https://nmap.org ) at 2025-10-20 23:00 UTC
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.065s latency).
Not shown: 996 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp    open  http       Apache httpd 2.4.7
443/tcp   open  https      Apache httpd 2.4.7
9929/tcp  open  nping-echo Nping echo

Nmap scan report for 127.0.0.1
Host is up (0.00010s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http

Nmap done: 2 IP addresses (2 hosts up) scanned in 5.23 seconds
"""

result = parse_nmap_text(sample_output)

print("Parsed Results:")
print(f"Found {len(result['hosts'])} hosts\n")

for host in result['hosts']:
    print(f"Host: {host['ip']} ({host.get('hostname', 'N/A')})")
    print(f"  Status: {host['status']}")
    print(f"  Services: {len(host['services'])}")
    for svc in host['services']:
        print(f"    - {svc['port']}/{svc['protocol']} {svc['service']} {svc.get('version', '')}")
    print()
