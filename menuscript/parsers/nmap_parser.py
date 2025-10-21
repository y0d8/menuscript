#!/usr/bin/env python3
"""
menuscript.parsers.nmap_parser - Parse nmap output into structured data
"""
import re
from typing import List, Dict, Any, Optional


def parse_nmap_text(output: str) -> Dict[str, Any]:
    """
    Parse nmap text output into structured data.
    
    Returns:
        {
            'hosts': [
                {
                    'ip': '10.0.0.5',
                    'hostname': 'example.com',
                    'status': 'up',
                    'os': 'Linux 5.x',
                    'services': [
                        {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2'}
                    ]
                }
            ]
        }
    """
    hosts = []
    current_host = None
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Parse host line: "Nmap scan report for 10.0.0.5" or "Nmap scan report for example.com (10.0.0.5)"
        if line.startswith("Nmap scan report for"):
            if current_host:
                hosts.append(current_host)
            
            # Extract IP and hostname
            match = re.search(r'for (.+?)(?:\s+\((.+?)\))?$', line)
            if match:
                target = match.group(1)
                paren_content = match.group(2)
                
                # Determine if target is IP or hostname
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                    ip = target
                    hostname = paren_content if paren_content else None
                else:
                    hostname = target
                    ip = paren_content if paren_content else None
                
                current_host = {
                    "ip": ip,
                    "hostname": hostname,
                    "status": "unknown",
                    "os": None,
                    "services": []
                }
        
        # Parse host status
        elif "Host is up" in line and current_host:
            current_host["status"] = "up"
        
        elif "Host is down" in line and current_host:
            current_host["status"] = "down"
        
        # Parse service line: "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1"
        elif re.match(r'^\d+/(tcp|udp)', line) and current_host:
            parts = line.split(None, 4)  # Split on whitespace, max 5 parts
            if len(parts) >= 3:
                port_proto = parts[0].split('/')
                port = int(port_proto[0])
                protocol = port_proto[1] if len(port_proto) > 1 else 'tcp'
                state = parts[1]
                service_name = parts[2] if len(parts) > 2 else None
                
                # Everything after service name is version info
                version = ' '.join(parts[3:]) if len(parts) > 3 else None
                
                current_host["services"].append({
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "version": version
                })
        
        # Parse OS detection: "Running: Linux 4.X|5.X" or "OS details: Linux 5.4"
        elif ("Running:" in line or "OS details:" in line) and current_host:
            os_info = line.split(':', 1)[1].strip()
            current_host["os"] = os_info
    
    # Don't forget the last host
    if current_host:
        hosts.append(current_host)
    
    return {"hosts": hosts}


def parse_nmap_log(log_path: str) -> Dict[str, Any]:
    """
    Parse an nmap log file.
    
    Args:
        log_path: Path to nmap log file
        
    Returns:
        Parsed nmap data with hosts and services
    """
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        return parse_nmap_text(content)
    except FileNotFoundError:
        return {"hosts": [], "error": f"File not found: {log_path}"}
    except Exception as e:
        return {"hosts": [], "error": str(e)}
