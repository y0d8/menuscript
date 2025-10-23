#!/usr/bin/env python3
"""
menuscript.parsers.msf_parser - Parse Metasploit auxiliary module output
"""
import re
from typing import Dict, Any, List


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def parse_msf_ssh_version(output: str, target: str) -> Dict[str, Any]:
    """
    Parse MSF ssh_version module output.

    Returns:
        {
            'services': [],  # Service info (version, etc.)
            'findings': []   # Security findings (deprecated crypto, etc.)
        }
    """
    services = []
    findings = []

    # Strip ANSI color codes first
    clean_output = strip_ansi_codes(output)

    # Extract SSH version
    version_match = re.search(r'SSH server version:\s*(.+)', clean_output)
    if version_match:
        ssh_version = version_match.group(1).strip()

        # Extract just the version number and product
        # e.g., "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"
        product_match = re.search(r'SSH-[\d.]+-(\S+)', ssh_version)
        if product_match:
            product = product_match.group(1)

            services.append({
                'port': 22,
                'protocol': 'tcp',
                'service_name': 'ssh',
                'service_version': product
            })

    # Extract OS information
    os_version = None
    os_match = re.search(r'os\.version\s+(.+)', clean_output)
    if os_match:
        os_version = os_match.group(1).strip()

    os_vendor = None
    vendor_match = re.search(r'os\.vendor\s+(.+)', clean_output)
    if vendor_match:
        os_vendor = vendor_match.group(1).strip()

    if os_vendor and os_version:
        findings.append({
            'title': f'SSH OS Detection: {os_vendor} {os_version}',
            'severity': 'info',
            'description': f'SSH banner reveals OS: {os_vendor} {os_version}',
            'port': 22,
            'service': 'ssh'
        })

    # Extract deprecated encryption algorithms
    deprecated_algos = []
    for line in clean_output.split('\n'):
        if 'Deprecated' in line and 'encryption.encryption' in line:
            # Extract algorithm name
            parts = line.split()
            if len(parts) >= 2:
                algo = parts[1]
                deprecated_algos.append(algo)

    if deprecated_algos:
        findings.append({
            'title': 'SSH Deprecated Encryption Algorithms',
            'severity': 'medium',
            'description': f'SSH server supports deprecated encryption: {", ".join(deprecated_algos[:5])}{"..." if len(deprecated_algos) > 5 else ""}',
            'port': 22,
            'service': 'ssh'
        })

    # Extract deprecated HMAC algorithms
    deprecated_hmac = []
    for line in clean_output.split('\n'):
        if 'Deprecated' in line and 'encryption.hmac' in line:
            parts = line.split()
            if len(parts) >= 2:
                algo = parts[1]
                deprecated_hmac.append(algo)

    if deprecated_hmac:
        findings.append({
            'title': 'SSH Deprecated HMAC Algorithms',
            'severity': 'low',
            'description': f'SSH server supports deprecated HMAC: {", ".join(deprecated_hmac[:3])}{"..." if len(deprecated_hmac) > 3 else ""}',
            'port': 22,
            'service': 'ssh'
        })

    # Extract weak key exchange methods
    weak_kex = []
    for line in clean_output.split('\n'):
        if 'Deprecated' in line and 'encryption.key_exchange' in line:
            parts = line.split()
            if len(parts) >= 2:
                algo = parts[1]
                weak_kex.append(algo)

    if weak_kex:
        findings.append({
            'title': 'SSH Weak Key Exchange Methods',
            'severity': 'medium',
            'description': f'SSH server supports weak key exchange: {", ".join(weak_kex)}',
            'port': 22,
            'service': 'ssh'
        })

    return {
        'services': services,
        'findings': findings
    }


def parse_msf_login_success(output: str, target: str, module: str) -> Dict[str, Any]:
    """
    Parse MSF login module output for successful authentication.

    Returns:
        {
            'findings': []  # Successful login attempts
        }
    """
    findings = []

    # Strip ANSI color codes first
    clean_output = strip_ansi_codes(output)

    # Extract successful logins
    # Format: [+] 10.0.0.82:22 - Success: 'username:password' 'additional info'
    success_pattern = r'\[\+\]\s+[\d.]+:(\d+)\s+-\s+Success:\s+[\'"]([^:]+):([^\'\"]+)[\'"]'

    for match in re.finditer(success_pattern, clean_output):
        port = int(match.group(1))
        username = match.group(2)
        password = match.group(3)

        # Determine service name from module
        service = 'unknown'
        if 'ssh' in module:
            service = 'ssh'
        elif 'telnet' in module:
            service = 'telnet'
        elif 'mysql' in module:
            service = 'mysql'
        elif 'vnc' in module:
            service = 'vnc'
        elif 'rlogin' in module:
            service = 'rlogin'
        elif 'smb' in module:
            service = 'smb'
        elif 'rdp' in module:
            service = 'rdp'

        findings.append({
            'title': f'{service.upper()} Valid Credentials Found',
            'severity': 'critical',
            'description': f'Valid {service} credentials: {username}:{password}',
            'port': port,
            'service': service
        })

    return {
        'findings': findings
    }


def parse_msf_smb_enumshares(output: str, target: str) -> Dict[str, Any]:
    """
    Parse SMB share enumeration output.

    Returns:
        {
            'findings': []  # Discovered SMB shares
        }
    """
    findings = []
    clean_output = strip_ansi_codes(output)

    # Parse share lines
    # Format: [+] 10.0.0.82:445 - ADMIN$ - (DISK) Remote Admin
    # Format: [+] 10.0.0.82:445 - IPC$ - (IPC) Remote IPC
    share_pattern = r'\[\+\]\s+[\d.]+:(\d+)\s+-\s+(\S+)\s+-\s+\((\w+)\)\s*(.*)'

    shares = []
    for match in re.finditer(share_pattern, clean_output):
        port = int(match.group(1))
        share_name = match.group(2)
        share_type = match.group(3)
        comment = match.group(4).strip()

        shares.append({
            'name': share_name,
            'type': share_type,
            'comment': comment,
            'port': port
        })

    if shares:
        # Determine severity based on share types
        severity = 'info'
        if any(s['name'] not in ['IPC$', 'ADMIN$', 'C$'] for s in shares):
            severity = 'medium'  # Non-default shares found

        share_list = ', '.join([s['name'] for s in shares])
        findings.append({
            'title': f'SMB Shares Discovered ({len(shares)} shares)',
            'severity': severity,
            'description': f'Found {len(shares)} SMB shares: {share_list}',
            'port': 445,
            'service': 'smb',
            'data': {'shares': shares}
        })

    return {
        'findings': findings
    }


def parse_msf_ssh_enumusers(output: str, target: str) -> Dict[str, Any]:
    """
    Parse SSH user enumeration output.

    Returns:
        {
            'findings': []  # Discovered SSH users
        }
    """
    findings = []
    clean_output = strip_ansi_codes(output)

    # Parse user enumeration results
    # Format: [+] 10.0.0.82:22 - SSH - User 'root' found
    # Format: [+] 10.0.0.82:22 - SSH - User 'admin' found
    user_pattern = r'\[\+\]\s+[\d.]+:(\d+)\s+-\s+SSH\s+-\s+User\s+[\'"]([^\'\"]+)[\'"]'

    users = []
    for match in re.finditer(user_pattern, clean_output):
        port = int(match.group(1))
        username = match.group(2)
        users.append(username)

    if users:
        user_list = ', '.join(users)
        findings.append({
            'title': f'SSH Users Enumerated ({len(users)} users)',
            'severity': 'medium',
            'description': f'Found {len(users)} SSH users: {user_list}',
            'port': 22,
            'service': 'ssh',
            'data': {'users': users}
        })

    return {
        'findings': findings
    }


def parse_msf_smtp_enum(output: str, target: str) -> Dict[str, Any]:
    """
    Parse SMTP user enumeration output.

    Returns:
        {
            'findings': []  # Discovered SMTP users
        }
    """
    findings = []
    clean_output = strip_ansi_codes(output)

    # Parse SMTP user enumeration (VRFY/EXPN/RCPT)
    # Format: [+] 10.0.0.82:25 - Users found: admin, root, user
    users = []

    # Method 1: Users found line
    users_found_pattern = r'Users found:\s*(.+)'
    match = re.search(users_found_pattern, clean_output)
    if match:
        user_list = match.group(1).strip()
        users = [u.strip() for u in user_list.split(',')]

    # Method 2: Individual user lines
    # Format: [+] 10.0.0.82:25 - Found user: root
    user_pattern = r'\[\+\]\s+[\d.]+:(\d+)\s+-\s+Found user:\s+(\S+)'
    for match in re.finditer(user_pattern, clean_output):
        username = match.group(2)
        if username not in users:
            users.append(username)

    if users:
        user_list = ', '.join(users)
        findings.append({
            'title': f'SMTP Users Enumerated ({len(users)} users)',
            'severity': 'medium',
            'description': f'Found {len(users)} SMTP users: {user_list}',
            'port': 25,
            'service': 'smtp',
            'data': {'users': users}
        })

    return {
        'findings': findings
    }


def parse_msf_nfs_mount(output: str, target: str) -> Dict[str, Any]:
    """
    Parse NFS mount enumeration output.

    Returns:
        {
            'findings': []  # Discovered NFS mounts
        }
    """
    findings = []
    clean_output = strip_ansi_codes(output)

    # Parse NFS exports
    # Format: [+] 10.0.0.82:111 - /home *
    # Format: [+] 10.0.0.82:2049 - /var/nfs *(rw,sync,no_subtree_check)
    export_pattern = r'\[\+\]\s+[\d.]+:(\d+)\s+-\s+(\S+)\s+(.*)'

    exports = []
    for match in re.finditer(export_pattern, clean_output):
        port = int(match.group(1))
        mount_path = match.group(2)
        permissions = match.group(3).strip()

        exports.append({
            'path': mount_path,
            'permissions': permissions,
            'port': port
        })

    if exports:
        # Determine severity based on permissions
        severity = 'medium'
        if any('rw' in e['permissions'] for e in exports):
            severity = 'high'  # Writable mounts are more severe

        export_list = ', '.join([e['path'] for e in exports])
        findings.append({
            'title': f'NFS Exports Discovered ({len(exports)} mounts)',
            'severity': severity,
            'description': f'Found {len(exports)} NFS exports: {export_list}',
            'port': 2049,
            'service': 'nfs',
            'data': {'exports': exports}
        })

    return {
        'findings': findings
    }


def parse_msf_log(log_path: str) -> Dict[str, Any]:
    """
    Parse an MSF auxiliary module log file.

    Args:
        log_path: Path to MSF log file

    Returns:
        Parsed data with services and findings
    """
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # Extract module and target from header
        module_match = re.search(r'^Module:\s*(.+)$', content, re.MULTILINE)
        target_match = re.search(r'^Target:\s*(.+)$', content, re.MULTILINE)

        if not module_match or not target_match:
            return {"error": "Could not parse MSF log header"}

        module = module_match.group(1).strip()
        target = target_match.group(1).strip()

        # Route to appropriate parser based on module
        if 'ssh_version' in module:
            return parse_msf_ssh_version(content, target)
        elif 'ssh_enumusers' in module:
            return parse_msf_ssh_enumusers(content, target)
        elif 'smb_enumshares' in module:
            return parse_msf_smb_enumshares(content, target)
        elif 'smtp_enum' in module:
            return parse_msf_smtp_enum(content, target)
        elif 'nfsmount' in module:
            return parse_msf_nfs_mount(content, target)
        elif any(x in module for x in ['_login', 'brute']):
            # Any login/brute force module
            return parse_msf_login_success(content, target, module)
        else:
            # Generic parser - just look for success/failure
            return {"findings": [], "services": []}

    except FileNotFoundError:
        return {"error": f"File not found: {log_path}"}
    except Exception as e:
        return {"error": str(e)}
