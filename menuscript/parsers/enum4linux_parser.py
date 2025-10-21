#!/usr/bin/env python3
"""
menuscript.parsers.enum4linux_parser

Parses enum4linux SMB enumeration output into structured data.
"""
import re
from typing import Dict, List, Any


def parse_enum4linux_output(output: str, target: str = "") -> Dict[str, Any]:
    """
    Parse enum4linux output and extract SMB information.

    enum4linux output format:
    - Target Information section
    - Workgroup/Domain enumeration
    - Share Enumeration section with sharenames
    - User/Group enumeration sections
    - Password policy
    - Etc.

    Args:
        output: Raw enum4linux output text
        target: Target IP/hostname from job

    Returns:
        Dict with structure:
        {
            'target': str,
            'workgroup': str,
            'domain_sid': str,
            'shares': [
                {
                    'name': str,
                    'type': str,
                    'comment': str,
                    'mapping': str,  # OK, DENIED, N/A
                    'listing': str,  # OK, N/A
                    'writing': str   # OK, N/A
                },
                ...
            ],
            'users': [str, ...],
            'groups': [str, ...]
        }
    """
    result = {
        'target': target,
        'workgroup': None,
        'domain_sid': None,
        'shares': [],
        'users': [],
        'groups': []
    }

    lines = output.split('\n')
    current_section = None
    in_share_table = False
    share_table_started = False

    for i, line in enumerate(lines):
        # Remove ANSI color codes
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        line = line.strip()

        # Extract target
        if line.startswith('Target ...........'):
            target_match = re.search(r'Target\s+\.+\s+(\S+)', line)
            if target_match:
                result['target'] = target_match.group(1)

        # Extract workgroup/domain
        elif '[+] Got domain/workgroup name:' in line:
            wg_match = re.search(r'Got domain/workgroup name:\s+(\S+)', line)
            if wg_match:
                result['workgroup'] = wg_match.group(1)

        # Extract domain SID
        elif line.startswith('Domain Sid:'):
            sid_match = re.search(r'Domain Sid:\s+(.+)', line)
            if sid_match:
                sid = sid_match.group(1).strip()
                if sid != '(NULL SID)':
                    result['domain_sid'] = sid

        # Detect share enumeration section
        elif 'Share Enumeration on' in line:
            current_section = 'shares'
            in_share_table = False
            share_table_started = False

        # Parse share table header
        elif current_section == 'shares' and 'Sharename' in line and 'Type' in line:
            in_share_table = True
            share_table_started = False
            continue

        # Parse share separator line
        elif current_section == 'shares' and line.startswith('---'):
            if in_share_table:
                share_table_started = True
            continue

        # Parse share lines
        elif current_section == 'shares' and in_share_table and share_table_started:
            # Check if we've left the table
            if not line or line.startswith('Reconnecting') or line.startswith('Server') or line.startswith('Workgroup') or line.startswith('['):
                in_share_table = False
                continue

            # Parse share line: "sharename   Type   Comment"
            share = _parse_share_line(line)
            if share:
                result['shares'].append(share)

        # Parse share mapping results
        elif current_section == 'shares' and line.startswith('//'):
            mapping_info = _parse_share_mapping(line)
            if mapping_info:
                # Find and update the matching share
                for share in result['shares']:
                    if mapping_info['name'] in line:
                        share.update(mapping_info)
                        break

        # Parse users section
        elif 'Users on' in line or 'user(s) returned' in line:
            current_section = 'users'

        # Parse groups section
        elif 'Groups on' in line or 'group(s) returned' in line:
            current_section = 'groups'

        # Parse user lines (simplified - would need more context)
        elif current_section == 'users' and line and not line.startswith('[') and not line.startswith('='):
            # User lines typically start with username or have specific format
            # This is simplified and may need refinement based on actual output
            pass

    return result


def _parse_share_line(line: str) -> Dict[str, Any]:
    """
    Parse a share table line.

    Example: "print$          Disk      Printer Drivers"
    Example: "tmp             Disk      oh noes!"
    """
    # Split on multiple whitespace
    parts = re.split(r'\s{2,}', line.strip())

    if len(parts) >= 2:
        share_name = parts[0].strip()
        share_type = parts[1].strip()
        comment = parts[2].strip() if len(parts) > 2 else ''

        return {
            'name': share_name,
            'type': share_type,
            'comment': comment,
            'mapping': None,
            'listing': None,
            'writing': None
        }
    return None


def _parse_share_mapping(line: str) -> Dict[str, Any]:
    """
    Parse share mapping result line.

    Example: "//10.0.0.82/tmp	Mapping: OK Listing: OK Writing: N/A"
    Example: "//10.0.0.82/print$	Mapping: DENIED Listing: N/A Writing: N/A"
    """
    try:
        # Extract share name from path
        share_match = re.search(r'//[^/]+/(\S+)', line)
        if not share_match:
            return None

        share_name = share_match.group(1)

        # Extract mapping status
        mapping_match = re.search(r'Mapping:\s*(\S+)', line)
        listing_match = re.search(r'Listing:\s*(\S+)', line)
        writing_match = re.search(r'Writing:\s*(\S+)', line)

        return {
            'name': share_name,
            'mapping': mapping_match.group(1) if mapping_match else None,
            'listing': listing_match.group(1) if listing_match else None,
            'writing': writing_match.group(1) if writing_match else None
        }
    except Exception:
        return None


def get_smb_stats(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics from parsed enum4linux results.

    Returns:
        Dict with counts and summary info
    """
    accessible_shares = sum(1 for s in parsed.get('shares', [])
                           if s.get('mapping') == 'OK')

    writable_shares = sum(1 for s in parsed.get('shares', [])
                         if s.get('writing') == 'OK')

    return {
        'total_shares': len(parsed.get('shares', [])),
        'accessible_shares': accessible_shares,
        'writable_shares': writable_shares,
        'workgroup': parsed.get('workgroup'),
        'has_domain_sid': parsed.get('domain_sid') is not None
    }


def categorize_share(share: Dict[str, Any]) -> str:
    """
    Categorize a share's security posture.

    Returns: 'open', 'readable', 'restricted', 'denied'
    """
    mapping = share.get('mapping', 'N/A')
    listing = share.get('listing', 'N/A')
    writing = share.get('writing', 'N/A')

    if writing == 'OK':
        return 'open'  # Writable = high risk
    elif listing == 'OK':
        return 'readable'  # Readable = medium risk
    elif mapping == 'OK':
        return 'restricted'  # Accessible but limited
    else:
        return 'denied'  # Not accessible
