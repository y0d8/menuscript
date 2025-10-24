#!/usr/bin/env python3
"""
menuscript.parsers.smbmap_parser

Parses smbmap SMB share enumeration output into structured data.
"""
import re
from typing import Dict, List, Any


def parse_smbmap_output(output: str, target: str = "") -> Dict[str, Any]:
    """
    Parse smbmap output and extract SMB shares with permissions.

    smbmap output format:
    [+] IP: 10.0.0.82:445	Name: 10.0.0.82           	Status: Authenticated
        Disk                                                  	Permissions	Comment
        ----                                                  	-----------	-------
        print$                                            	NO ACCESS	Printer Drivers
        tmp                                               	READ, WRITE	oh noes!
        opt                                               	NO ACCESS
        IPC$                                              	NO ACCESS	IPC Service

    Args:
        output: Raw smbmap output text
        target: Target IP/hostname from job

    Returns:
        Dict with structure:
        {
            'target': str,
            'status': str,  # Authenticated, Guest, etc.
            'shares': [
                {
                    'name': str,
                    'type': str,  # Disk, IPC, etc.
                    'permissions': str,  # READ, WRITE, READ/WRITE, NO ACCESS
                    'comment': str,
                    'readable': bool,
                    'writable': bool
                },
                ...
            ],
            'files': [  # If -R was used
                {
                    'share': str,
                    'path': str,
                    'size': int,
                    'timestamp': str
                },
                ...
            ]
        }
    """
    result = {
        'target': target,
        'status': None,
        'shares': [],
        'files': []
    }

    lines = output.split('\n')
    in_share_table = False
    current_share = None

    for i, line in enumerate(lines):
        # Remove ANSI color codes and control characters
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        line = re.sub(r'[\[\]\|/\\-]', '', line, count=1)  # Remove progress indicators
        line = line.strip()

        # Extract target and status
        # [+] IP: 10.0.0.82:445	Name: 10.0.0.82           	Status: Authenticated
        if line.startswith('+') and 'IP:' in line and 'Status:' in line:
            status_match = re.search(r'Status:\s+(\w+)', line)
            if status_match:
                result['status'] = status_match.group(1)

            # Extract target IP if not provided
            if not result['target']:
                ip_match = re.search(r'IP:\s+([\d\.]+)', line)
                if ip_match:
                    result['target'] = ip_match.group(1)

        # Detect share table header
        # Disk                                                  	Permissions	Comment
        elif 'Disk' in line and 'Permissions' in line and 'Comment' in line:
            in_share_table = True
            continue

        # Skip separator line
        elif line.startswith('----') or line.startswith('==='):
            continue

        # Parse share entries
        elif in_share_table and line and not line.startswith('*') and not line.startswith('Closed'):
            # Try to parse share line
            # Format: sharename <tabs> permissions <tabs> comment
            # tmp                                               	READ, WRITE	oh noes!

            parts = re.split(r'\t+', line)
            if len(parts) >= 2:
                share_name = parts[0].strip()
                permissions = parts[1].strip() if len(parts) > 1 else 'UNKNOWN'
                comment = parts[2].strip() if len(parts) > 2 else ''

                # Skip empty lines or non-share lines
                if not share_name or share_name in ['Disk', 'IPC', '', '*']:
                    continue

                # Skip separator lines (----, ===, etc.)
                if re.match(r'^[\-=]+$', share_name):
                    continue

                # Determine share type (Disk vs IPC)
                share_type = 'IPC' if share_name.endswith('$') and 'IPC' in comment else 'Disk'

                # Parse permissions
                readable = 'READ' in permissions.upper()
                writable = 'WRITE' in permissions.upper()

                share_info = {
                    'name': share_name,
                    'type': share_type,
                    'permissions': permissions,
                    'comment': comment,
                    'readable': readable,
                    'writable': writable
                }

                result['shares'].append(share_info)
                current_share = share_name

        # Parse file listings (if -R was used)
        # dr--r--r--                0 Sat May 16 14:06:55 2009	.
        # dr--r--r--                0 Sat May 16 14:06:55 2009	..
        # fr--r--r--              512 Sat May 16 14:06:55 2009	script.sh
        elif current_share and re.match(r'^[df]r', line):
            # File listing format: permissions size timestamp filename
            file_match = re.match(r'^([df]r[\-rwx]+)\s+(\d+)\s+(.+?)\s{2,}(.+)$', line)
            if file_match:
                perms, size, timestamp, filename = file_match.groups()

                # Skip . and .. entries
                if filename in ['.', '..']:
                    continue

                file_info = {
                    'share': current_share,
                    'path': filename,
                    'size': int(size),
                    'timestamp': timestamp.strip(),
                    'is_directory': perms.startswith('d')
                }
                result['files'].append(file_info)

        # Detect end of output
        elif 'Closed' in line and 'connections' in line:
            in_share_table = False
            current_share = None

    return result


def extract_findings(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract security findings from parsed smbmap data.

    Returns:
        List of finding dictionaries with:
        {
            'title': str,
            'severity': str,  # high, medium, low, info
            'description': str,
            'evidence': str
        }
    """
    findings = []

    # Finding 1: Writable shares (HIGH severity)
    writable_shares = [s for s in parsed_data['shares'] if s['writable']]
    if writable_shares:
        share_names = ', '.join([s['name'] for s in writable_shares])
        findings.append({
            'title': 'Writable SMB Shares Detected',
            'severity': 'high',
            'description': f"Found {len(writable_shares)} SMB share(s) with WRITE permissions: {share_names}. "
                          "Writable shares can be exploited to upload malicious files, plant ransomware, "
                          "or exfiltrate sensitive data.",
            'evidence': '\n'.join([
                f"- {s['name']}: {s['permissions']} ({s['comment']})"
                for s in writable_shares
            ])
        })

    # Finding 2: Readable shares (MEDIUM severity)
    readable_shares = [s for s in parsed_data['shares']
                      if s['readable'] and not s['writable'] and s['type'] == 'Disk']
    if readable_shares:
        share_names = ', '.join([s['name'] for s in readable_shares])
        findings.append({
            'title': 'Readable SMB Shares Detected',
            'severity': 'medium',
            'description': f"Found {len(readable_shares)} SMB share(s) with READ permissions: {share_names}. "
                          "These shares may contain sensitive information accessible without proper authentication.",
            'evidence': '\n'.join([
                f"- {s['name']}: {s['permissions']} ({s['comment']})"
                for s in readable_shares
            ])
        })

    # Finding 3: Anonymous access (MEDIUM severity)
    if parsed_data.get('status') in ['Guest', 'Anonymous']:
        accessible_shares = [s for s in parsed_data['shares']
                           if s['readable'] or s['writable']]
        if accessible_shares:
            findings.append({
                'title': 'Anonymous SMB Access Allowed',
                'severity': 'medium',
                'description': f"Anonymous/guest access is permitted, allowing access to {len(accessible_shares)} share(s) "
                              "without authentication. This violates the principle of least privilege.",
                'evidence': f"Authentication Status: {parsed_data.get('status')}\n" +
                           '\n'.join([f"- {s['name']}: {s['permissions']}" for s in accessible_shares])
            })

    # Finding 4: Sensitive files exposed (if files were enumerated)
    sensitive_patterns = [
        (r'\.config$', 'Configuration files'),
        (r'password|passwd|pwd', 'Password files'),
        (r'\.key|\.pem|\.crt', 'Cryptographic keys/certificates'),
        (r'backup|\.bak|\.old', 'Backup files'),
        (r'\.sql|\.db|\.sqlite', 'Database files'),
        (r'id_rsa|id_dsa|\.ssh', 'SSH private keys')
    ]

    for pattern, desc in sensitive_patterns:
        matching_files = [f for f in parsed_data['files']
                         if re.search(pattern, f['path'], re.IGNORECASE)]
        if matching_files:
            findings.append({
                'title': f'Sensitive Files Exposed: {desc}',
                'severity': 'high',
                'description': f"Found {len(matching_files)} potentially sensitive file(s) ({desc}) "
                              "accessible via SMB shares.",
                'evidence': '\n'.join([
                    f"- {f['share']}/{f['path']} ({f['size']} bytes)"
                    for f in matching_files[:10]  # Limit to first 10
                ]) + (f"\n... and {len(matching_files) - 10} more" if len(matching_files) > 10 else "")
            })

    # Finding 5: Info - All shares enumerated
    if parsed_data['shares']:
        findings.append({
            'title': 'SMB Share Enumeration Successful',
            'severity': 'info',
            'description': f"Successfully enumerated {len(parsed_data['shares'])} SMB share(s) on target.",
            'evidence': '\n'.join([
                f"- {s['name']} ({s['type']}): {s['permissions']}"
                for s in parsed_data['shares']
            ])
        })

    return findings
