#!/usr/bin/env python3
"""
menuscript.parsers.msf_parser - Parse Metasploit auxiliary module output
"""
import re
from typing import Dict, Any, List


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

    # Extract SSH version
    version_match = re.search(r'SSH server version:\s*(.+)', output)
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
    os_match = re.search(r'os\.version\s+(.+)', output)
    if os_match:
        os_version = os_match.group(1).strip()

    os_vendor = None
    vendor_match = re.search(r'os\.vendor\s+(.+)', output)
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
    for line in output.split('\n'):
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
    for line in output.split('\n'):
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
    for line in output.split('\n'):
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

    # Extract successful logins
    # Format: [+] 10.0.0.82:22 - Success: 'username:password' 'additional info'
    success_pattern = r'\[\+\]\s+[\d.]+:(\d+)\s+-\s+Success:\s+[\'"]([^:]+):([^\'\"]+)[\'"]'

    for match in re.finditer(success_pattern, output):
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
        elif 'ssh_login' in module or 'telnet_login' in module or 'mysql_login' in module or 'vnc_login' in module or 'rlogin_login' in module:
            return parse_msf_login_success(content, target, module)
        else:
            # Generic parser - just look for success/failure
            return {"findings": [], "services": []}

    except FileNotFoundError:
        return {"error": f"File not found: {log_path}"}
    except Exception as e:
        return {"error": str(e)}
