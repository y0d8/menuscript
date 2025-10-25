#!/usr/bin/env python3
"""
Quick test of credential tester functionality
"""
from menuscript.core.credential_tester import CredentialTester
from menuscript.storage.credentials import CredentialsManager
from menuscript.storage.hosts import HostManager
from menuscript.storage.engagements import EngagementManager

# Get current engagement
em = EngagementManager()
current = em.get_current()

if not current:
    print("No engagement selected!")
    exit(1)

engagement_id = current['id']
print(f"Testing credentials for engagement: {current['name']}")
print()

# Show current credentials
cm = CredentialsManager()
creds = cm.list_credentials(engagement_id)
print(f"Found {len(creds)} credentials:")
for cred in creds[:10]:
    print(f"  - {cred.get('service', '?')}: {cred.get('username', '?')} / {'***' if cred.get('password') else '(no password)'}")
print()

# Show hosts with SMB/SSH
hm = HostManager()
hosts = hm.list_hosts(engagement_id)
active_hosts = [h for h in hosts if h.get('status') == 'up']
print(f"Found {len(active_hosts)} active hosts")
print()

# Count testable credentials (with passwords)
testable = [c for c in creds if c.get('password')]
print(f"Testable credentials (have passwords): {len(testable)}")
print()

if not testable:
    print("❌ No credentials with passwords to test!")
    print()
    print("You can add a test credential with:")
    print("  menuscript interactive -> Credential Management -> Add New Credential")
    exit(0)

# Ask to run test
response = input("Run credential testing? (y/n): ")
if response.lower() != 'y':
    print("Cancelled.")
    exit(0)

print()
print("Testing credentials...")
print()

tester = CredentialTester()
results = tester.test_all_credentials(engagement_id)

print()
print("=" * 60)
print("RESULTS")
print("=" * 60)
print(f"Total tests:      {results['total_tests']}")
print(f"✓ Successful:     {results['successful']}")
print(f"✗ Failed:         {results['failed']}")
print(f"📋 Findings:      {results['findings_created']}")
print()

if results['successful'] > 0:
    print("Successful authentications:")
    for test in results['results']:
        if test['success']:
            print(f"  ✓ {test['service']}: cred {test['credential_id']} on host {test['host_id']} - {test['message']}")
    print()
    print("Check Findings Management to see the auto-created findings!")
