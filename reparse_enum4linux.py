#!/usr/bin/env python3
"""
Quick script to re-parse enum4linux job #125 and extract users
"""
import sys
from menuscript.storage.engagements import EngagementManager
from menuscript.engine.background import get_job
from menuscript.engine.result_handler import parse_enum4linux_job

# Get current engagement
em = EngagementManager()
engagement = em.get_current()

if not engagement:
    print("No active engagement found!")
    sys.exit(1)

engagement_id = engagement['id']

# Get job #125
job = get_job(125)

if not job:
    print("Job #125 not found!")
    sys.exit(1)

print(f"Re-parsing job #{job['id']} - {job['tool']} on {job['target']}")

# Re-parse the job
result = parse_enum4linux_job(engagement_id, job['log'], job)

if 'error' in result:
    print(f"Error: {result['error']}")
else:
    print(f"✓ Successfully parsed!")
    print(f"  - Users found: {result.get('users_found', 0)}")
    print(f"  - Credentials added: {result.get('credentials_added', 0)}")
    print(f"  - Findings added: {result.get('findings_added', 0)}")
    print(f"  - Shares found: {result.get('shares_found', 0)}")
