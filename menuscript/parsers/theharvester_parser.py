#!/usr/bin/env python3
"""
menuscript.parsers.theharvester_parser

Parses theHarvester OSINT output into structured data.
"""
import re
from typing import Dict, List, Any


def parse_theharvester_output(output: str, target: str = "") -> Dict[str, Any]:
    """
    Parse theHarvester text output and extract OSINT data.

    theHarvester output format:
    [*] Target: domain.com
    [*] Searching Source.
    [*] ASNS found: N
    --------------------
    AS12345
    [*] Interesting Urls found: N
    --------------------
    http://example.com/path
    [*] IPs found: N
    -------------------
    1.2.3.4
    [*] Emails found: N
    -------------------
    email@example.com
    [*] Hosts found: N
    ---------------------
    subdomain.example.com

    Args:
        output: Raw theHarvester output text
        target: Target domain from job

    Returns:
        Dict with structure:
        {
            'target': str,
            'emails': [str, ...],
            'hosts': [str, ...],
            'ips': [str, ...],
            'urls': [str, ...],
            'asns': [str, ...]
        }
    """
    result = {
        'target': target,
        'emails': [],
        'hosts': [],
        'ips': [],
        'urls': [],
        'asns': []
    }

    lines = output.split('\n')
    current_section = None

    for line in lines:
        line = line.strip()

        # Detect target
        if line.startswith('[*] Target:'):
            target_match = re.search(r'\[?\*\]?\s*Target:\s*(\S+)', line)
            if target_match:
                result['target'] = target_match.group(1)

        # Detect section headers
        elif '[*] ASNS found:' in line or 'ASNs found:' in line:
            current_section = 'asns'
        elif '[*] Interesting Urls found:' in line or '[*] URLs found:' in line:
            current_section = 'urls'
        elif '[*] IPs found:' in line:
            current_section = 'ips'
        elif '[*] Emails found:' in line or 'Email addresses found:' in line:
            current_section = 'emails'
        elif '[*] Hosts found:' in line or 'Hosts found:' in line:
            current_section = 'hosts'
        elif '[*] People found:' in line or '[*] No people found' in line:
            current_section = 'people'  # We'll skip this for now

        # Skip separator lines and empty lines
        elif line.startswith('---') or not line:
            continue

        # Skip "No X found" messages
        elif '[*] No' in line:
            current_section = None
            continue

        # Skip header/banner lines
        elif line.startswith('*') or line.startswith('[*] Searching'):
            continue

        # Parse data based on current section
        elif current_section == 'asns':
            # ASN format: AS12345
            if line.startswith('AS') and line[2:].isdigit():
                result['asns'].append(line)

        elif current_section == 'urls':
            # URL format: http(s)://...
            if line.startswith('http://') or line.startswith('https://'):
                # Clean up trailing punctuation
                url = line.rstrip('.,;)')
                if url not in result['urls']:
                    result['urls'].append(url)

        elif current_section == 'ips':
            # IP format: N.N.N.N
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                if line not in result['ips']:
                    result['ips'].append(line)

        elif current_section == 'emails':
            # Email format: user@domain
            if '@' in line and '.' in line:
                # Basic email validation
                if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                    if line not in result['emails']:
                        result['emails'].append(line)

        elif current_section == 'hosts':
            # Host format: subdomain.domain.tld
            if '.' in line and not line.startswith('http'):
                # Clean and validate hostname
                host = line.strip().lower()
                # Basic validation: has at least one dot and no invalid chars
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', host):
                    if host not in result['hosts']:
                        result['hosts'].append(host)

    return result


def get_osint_stats(parsed: Dict[str, Any]) -> Dict[str, int]:
    """
    Get statistics from parsed theHarvester results.

    Args:
        parsed: Output from parse_theharvester_output()

    Returns:
        Dict with counts: {'emails': 5, 'hosts': 10, ...}
    """
    return {
        'emails': len(parsed.get('emails', [])),
        'hosts': len(parsed.get('hosts', [])),
        'ips': len(parsed.get('ips', [])),
        'urls': len(parsed.get('urls', [])),
        'asns': len(parsed.get('asns', []))
    }
