#!/usr/bin/env python3
"""Test full integration: parse nmap -> store in database"""
from menuscript.parsers.nmap_parser import parse_nmap_text
from menuscript.storage.workspaces import WorkspaceManager
from menuscript.storage.hosts import HostManager

# Sample nmap output
sample_output = """
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.065s latency).
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1p1 Ubuntu
80/tcp    open  http       Apache httpd 2.4.7
443/tcp   open  https      Apache httpd 2.4.7
"""

print("1. Creating test workspace...")
wm = WorkspaceManager()
try:
    ws_id = wm.create("parser-test", "Testing parser integration")
except:
    # Already exists
    ws = wm.get("parser-test")
    ws_id = ws['id']

print(f"   Workspace ID: {ws_id}")

print("\n2. Parsing nmap output...")
parsed = parse_nmap_text(sample_output)
print(f"   Found {len(parsed['hosts'])} hosts")

print("\n3. Importing to database...")
hm = HostManager()
result = hm.import_nmap_results(ws_id, parsed)
print(f"   Hosts added: {result['hosts_added']}")
print(f"   Services added: {result['services_added']}")

print("\n4. Querying database...")
hosts = hm.list_hosts(ws_id)
for host in hosts:
    print(f"\n   Host: {host['ip_address']} ({host.get('hostname', 'N/A')})")
    services = hm.get_host_services(host['id'])
    print(f"   Services: {len(services)}")
    for svc in services:
        print(f"     - {svc['port']}/{svc['protocol']} {svc['service_name']} {svc.get('service_version', '')}")

print("\n✓ Integration test complete!")
