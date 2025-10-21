#!/usr/bin/env python3
"""
menuscript.engine.result_handler - Auto-parse job results
"""
import os
from typing import Optional, Dict, Any


def handle_job_result(job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process completed job and parse results into database.
    
    Args:
        job: Job dict from background system
        
    Returns:
        Parse results or None if not applicable
    """
    tool = job.get('tool', '').lower()
    log_path = job.get('log')
    status = job.get('status')
    
    # Only process successful jobs
    if status != 'done' or not log_path or not os.path.exists(log_path):
        return None
    
    # Get current workspace
    try:
        from menuscript.storage.workspaces import WorkspaceManager
        wm = WorkspaceManager()
        workspace = wm.get_current()
        
        if not workspace:
            return None
        
        workspace_id = workspace['id']
    except Exception:
        return None
    
    # Route to appropriate parser
    if tool == 'nmap':
        return parse_nmap_job(workspace_id, log_path, job)
    elif tool == 'nikto':
        return parse_nikto_job(workspace_id, log_path, job)
    elif tool == 'theharvester':
        return parse_theharvester_job(workspace_id, log_path, job)
    elif tool == 'gobuster':
        return parse_gobuster_job(workspace_id, log_path, job)

    # Add more parsers here as we build them

    return None


def parse_nmap_job(workspace_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
    """Parse nmap job results."""
    try:
        from menuscript.parsers.nmap_parser import parse_nmap_log
        from menuscript.storage.hosts import HostManager
        
        # Parse the log file
        parsed = parse_nmap_log(log_path)
        
        if 'error' in parsed:
            return {'error': parsed['error']}
        
        # Import into database
        hm = HostManager()
        result = hm.import_nmap_results(workspace_id, parsed)
        
        return {
            'tool': 'nmap',
            'hosts_added': result['hosts_added'],
            'services_added': result['services_added']
        }
    except Exception as e:
        return {'error': str(e)}


def parse_nikto_job(workspace_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
    """Parse nikto job results."""
    try:
        from menuscript.parsers.nikto_parser import parse_nikto_output, format_finding_title
        from menuscript.storage.findings import FindingsManager
        from menuscript.storage.hosts import HostManager

        # Read the log file
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read()

        # Parse nikto output
        target = job.get('target', '')
        parsed = parse_nikto_output(log_content, target)

        # Get or create host
        hm = HostManager()
        host_id = None

        if parsed['target_ip']:
            # Add or update host
            host_id = hm.add_or_update_host(workspace_id, {
                'ip': parsed['target_ip'],
                'hostname': parsed.get('target_host'),
                'status': 'up'
            })

        # Store findings
        fm = FindingsManager()
        findings_added = 0

        for finding in parsed['findings']:
            title = format_finding_title(finding)

            fm.add_finding(
                workspace_id=workspace_id,
                host_id=host_id,
                title=title,
                finding_type='web_vulnerability',
                severity=finding['severity'],
                description=finding['description'],
                refs=finding.get('reference'),
                port=parsed.get('target_port'),
                path=finding.get('path'),
                tool='nikto'
            )
            findings_added += 1

        return {
            'tool': 'nikto',
            'findings_added': findings_added,
            'target_host': parsed.get('target_host'),
            'target_ip': parsed.get('target_ip')
        }
    except Exception as e:
        return {'error': str(e)}


def parse_theharvester_job(workspace_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
    """Parse theHarvester job results."""
    try:
        from menuscript.parsers.theharvester_parser import parse_theharvester_output, get_osint_stats
        from menuscript.storage.osint import OsintManager
        from menuscript.storage.hosts import HostManager

        # Read the log file
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read()

        # Parse theHarvester output
        target = job.get('target', '')
        parsed = parse_theharvester_output(log_content, target)

        # Store OSINT data
        om = OsintManager()
        osint_added = 0

        # Add emails
        if parsed['emails']:
            count = om.bulk_add_osint_data(workspace_id, 'email', parsed['emails'], 'theHarvester')
            osint_added += count

        # Add hosts/subdomains
        if parsed['hosts']:
            count = om.bulk_add_osint_data(workspace_id, 'host', parsed['hosts'], 'theHarvester')
            osint_added += count

        # Add IPs
        if parsed['ips']:
            count = om.bulk_add_osint_data(workspace_id, 'ip', parsed['ips'], 'theHarvester')
            osint_added += count

        # Add URLs
        if parsed['urls']:
            count = om.bulk_add_osint_data(workspace_id, 'url', parsed['urls'], 'theHarvester')
            osint_added += count

        # Add ASNs
        if parsed['asns']:
            count = om.bulk_add_osint_data(workspace_id, 'asn', parsed['asns'], 'theHarvester')
            osint_added += count

        # Also add discovered IPs and hosts to the hosts table if they look valid
        hm = HostManager()
        hosts_added = 0

        for ip in parsed['ips']:
            try:
                # Try to add IP as a host
                hm.add_or_update_host(workspace_id, {
                    'ip': ip,
                    'status': 'unknown'
                })
                hosts_added += 1
            except Exception:
                pass  # Skip if invalid

        stats = get_osint_stats(parsed)

        return {
            'tool': 'theHarvester',
            'osint_added': osint_added,
            'hosts_added': hosts_added,
            'stats': stats
        }
    except Exception as e:
        return {'error': str(e)}


def parse_gobuster_job(workspace_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
    """Parse gobuster job results."""
    try:
        from menuscript.parsers.gobuster_parser import parse_gobuster_output, get_paths_stats
        from menuscript.storage.web_paths import WebPathsManager
        from menuscript.storage.hosts import HostManager
        from urllib.parse import urlparse

        # Read the log file
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read()

        # Parse gobuster output
        target = job.get('target', '')
        parsed = parse_gobuster_output(log_content, target)

        # Get or create host from target URL
        hm = HostManager()
        host_id = None

        if parsed['target_url']:
            parsed_url = urlparse(parsed['target_url'])
            hostname = parsed_url.hostname

            if hostname:
                # Try to find existing host by hostname
                hosts = hm.list_hosts(workspace_id)
                for host in hosts:
                    if host.get('hostname') == hostname or host.get('ip_address') == hostname:
                        host_id = host['id']
                        break

                # Create host if not found
                if not host_id:
                    # Try to determine if it's an IP or hostname
                    import re
                    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname)

                    if is_ip:
                        host_id = hm.add_or_update_host(workspace_id, {
                            'ip': hostname,
                            'status': 'up'
                        })
                    else:
                        # It's a hostname - we need an IP, so skip host creation for now
                        # Just store paths without host_id (will need to fix schema)
                        pass

        # Store web paths
        wpm = WebPathsManager()
        paths_added = 0

        if host_id and parsed['paths']:
            paths_added = wpm.bulk_add_web_paths(host_id, parsed['paths'])

        stats = get_paths_stats(parsed)

        return {
            'tool': 'gobuster',
            'paths_added': paths_added,
            'total_paths': stats['total'],
            'by_status': stats['by_status'],
            'target_url': parsed.get('target_url')
        }
    except Exception as e:
        return {'error': str(e)}
