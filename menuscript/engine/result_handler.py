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

    # Some tools return non-zero exit codes even on success (nikto returns 1 when findings found)
    # Parse 'done' jobs and 'error' jobs for certain tools
    tools_with_nonzero_success = ['nikto']

    if status == 'done':
        # Always parse successful jobs
        pass
    elif status == 'error' and tool in tools_with_nonzero_success:
        # Parse error jobs for tools that can succeed with non-zero exit codes
        pass
    else:
        # Skip other error/failed jobs
        return None

    if not log_path or not os.path.exists(log_path):
        return None
    
    # Get current engagement
    try:
        from menuscript.storage.engagements import EngagementManager
        em = EngagementManager()
        engagement = em.get_current()

        if not engagement:
            return None

        engagement_id = engagement['id']
    except Exception:
        return None

    # Route to appropriate parser
    if tool == 'nmap':
        return parse_nmap_job(engagement_id, log_path, job)
    elif tool == 'nikto':
        return parse_nikto_job(engagement_id, log_path, job)
    elif tool == 'theharvester':
        return parse_theharvester_job(engagement_id, log_path, job)
    elif tool == 'gobuster':
        return parse_gobuster_job(engagement_id, log_path, job)
    elif tool == 'enum4linux':
        return parse_enum4linux_job(engagement_id, log_path, job)
    elif tool == 'msf_auxiliary':
        return parse_msf_auxiliary_job(engagement_id, log_path, job)
    elif tool == 'sqlmap':
        return parse_sqlmap_job(engagement_id, log_path, job)

    return None


def parse_nmap_job(engagement_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
    """Parse nmap job results."""
    try:
        from menuscript.parsers.nmap_parser import parse_nmap_log
        from menuscript.storage.hosts import HostManager
        from menuscript.storage.findings import FindingsManager
        from menuscript.core.cve_matcher import CVEMatcher

        # Parse the log file
        parsed = parse_nmap_log(log_path)

        if 'error' in parsed:
            return {'error': parsed['error']}

        # Import into database
        hm = HostManager()
        result = hm.import_nmap_results(engagement_id, parsed)

        # Check for CVEs and common issues
        fm = FindingsManager()
        cve_matcher = CVEMatcher()
        findings_added = 0
        
        for host_data in parsed.get('hosts', []):
            if host_data.get('status') == 'up':
                # Find host ID
                host = hm.get_host_by_ip(engagement_id, host_data.get('ip'))
                if not host:
                    continue
                    
                host_id = host['id']
                
                # Check each service for CVEs and common issues
                for svc in host_data.get('services', []):
                    service_info = {
                        'service_name': svc.get('service', ''),
                        'version': svc.get('version', ''),
                        'port': svc.get('port'),
                        'protocol': svc.get('protocol', 'tcp')
                    }
                    
                    # Also check database for stored version if not in parsed data
                    if not service_info['version']:
                        services = hm.get_host_services(host_id)
                        for stored_svc in services:
                            if stored_svc['port'] == svc.get('port'):
                                service_info['version'] = stored_svc.get('service_version', '')
                                break
                    
                    # Check for CVEs
                    cve_findings = cve_matcher.parse_nmap_service(service_info)
                    for finding in cve_findings:
                        fm.add_finding(
                            engagement_id=engagement_id,
                            host_id=host_id,
                            title=finding['title'],
                            finding_type='vulnerability',
                            severity=finding['severity'],
                            description=finding['description'],
                            cve_id=finding.get('cve_id'),
                            cvss_score=finding.get('cvss_score'),
                            port=finding.get('port'),
                            tool='nmap',
                            category='cve',
                            refs=f"https://nvd.nist.gov/vuln/detail/{finding.get('cve_id')}"
                        )
                        findings_added += 1
                    
                    # Check for common issues
                    issue_findings = cve_matcher.scan_for_common_issues(service_info)
                    for finding in issue_findings:
                        fm.add_finding(
                            engagement_id=engagement_id,
                            host_id=host_id,
                            title=finding['title'],
                            finding_type='misconfiguration',
                            severity=finding['severity'],
                            description=finding['description'],
                            port=finding.get('port'),
                            tool='nmap',
                            category=finding.get('category', 'misconfiguration'),
                            remediation=finding.get('remediation')
                        )
                        findings_added += 1

        # Build host details list for summary
        host_details = []
        for host_data in parsed.get('hosts', []):
            if host_data.get('status') == 'up':
                services = host_data.get('services', [])
                service_count = len(services)

                # Get top ports for detailed scans
                top_ports = []
                for svc in services[:5]:  # Top 5 ports
                    port = svc.get('port')
                    service_name = svc.get('service', 'unknown')
                    top_ports.append(f"{port}/{service_name}")

                host_details.append({
                    'ip': host_data.get('ip'),
                    'hostname': host_data.get('hostname'),
                    'os': host_data.get('os'),
                    'service_count': service_count,
                    'top_ports': top_ports
                })

        # Determine scan type based on job args
        args = job.get('args', [])
        is_discovery = '-sn' in args or '--discovery' in args
        is_full_scan = any(x in args for x in ['-sV', '-O', '-A', '-p1-65535'])

        return {
            'tool': 'nmap',
            'hosts_added': result['hosts_added'],
            'services_added': result['services_added'],
            'findings_added': findings_added,
            'host_details': host_details,
            'is_discovery': is_discovery,
            'is_full_scan': is_full_scan
        }
    except Exception as e:
        return {'error': str(e)}


def parse_nikto_job(engagement_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
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
            host_id = hm.add_or_update_host(engagement_id, {
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
                engagement_id=engagement_id,
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


def parse_theharvester_job(engagement_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
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
            count = om.bulk_add_osint_data(engagement_id, 'email', parsed['emails'], 'theHarvester')
            osint_added += count

        # Add hosts/subdomains
        if parsed['hosts']:
            count = om.bulk_add_osint_data(engagement_id, 'host', parsed['hosts'], 'theHarvester')
            osint_added += count

        # Add IPs
        if parsed['ips']:
            count = om.bulk_add_osint_data(engagement_id, 'ip', parsed['ips'], 'theHarvester')
            osint_added += count

        # Add URLs
        if parsed['urls']:
            count = om.bulk_add_osint_data(engagement_id, 'url', parsed['urls'], 'theHarvester')
            osint_added += count

        # Add ASNs
        if parsed['asns']:
            count = om.bulk_add_osint_data(engagement_id, 'asn', parsed['asns'], 'theHarvester')
            osint_added += count

        # Also add discovered IPs and hosts to the hosts table if they look valid
        hm = HostManager()
        hosts_added = 0

        for ip in parsed['ips']:
            try:
                # Try to add IP as a host
                hm.add_or_update_host(engagement_id, {
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


def parse_gobuster_job(engagement_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
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
                hosts = hm.list_hosts(engagement_id)
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
                        host_id = hm.add_or_update_host(engagement_id, {
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
            'paths_found': stats['total'],  # For dashboard display
            'by_status': stats['by_status'],
            'target_url': parsed.get('target_url')
        }
    except Exception as e:
        return {'error': str(e)}


def parse_enum4linux_job(engagement_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
    """Parse enum4linux job results."""
    try:
        from menuscript.parsers.enum4linux_parser import parse_enum4linux_output, get_smb_stats, categorize_share
        from menuscript.storage.findings import FindingsManager
        from menuscript.storage.hosts import HostManager

        # Read the log file
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read()

        # Parse enum4linux output
        target = job.get('target', '')
        parsed = parse_enum4linux_output(log_content, target)

        # Get or create host from target
        hm = HostManager()
        host_id = None

        if parsed['target']:
            # Try to find existing host
            import re
            is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed['target'])

            if is_ip:
                host = hm.get_host_by_ip(engagement_id, parsed['target'])
                if host:
                    host_id = host['id']
                else:
                    # Create host
                    host_id = hm.add_or_update_host(engagement_id, {
                        'ip': parsed['target'],
                        'status': 'up'
                    })

        # Store discovered users as credentials
        from menuscript.storage.credentials import CredentialsManager
        cm = CredentialsManager()
        credentials_added = 0

        for username in parsed['users']:
            # Store each discovered user as a credential
            cm.add_credential(
                engagement_id=engagement_id,
                host_id=host_id,
                username=username,
                password='',  # Unknown password
                credential_type='smb',
                service='smb',
                port=445,
                tool='enum4linux'
            )
            credentials_added += 1

        # Store SMB shares as findings
        fm = FindingsManager()
        findings_added = 0

        for share in parsed['shares']:
            # Determine severity based on access
            category = categorize_share(share)
            if category == 'open':
                severity = 'high'  # Writable share
            elif category == 'readable':
                severity = 'medium'  # Readable share
            elif category == 'restricted':
                severity = 'low'  # Accessible but limited
            else:
                severity = 'info'  # Denied/not accessible

            # Create finding title
            share_name = share['name']
            share_type = share.get('type', 'Unknown')
            mapping = share.get('mapping', 'N/A')

            if mapping == 'OK':
                listing = share.get('listing', 'N/A')
                writing = share.get('writing', 'N/A')
                access_desc = f"Mapping={mapping}, Listing={listing}, Writing={writing}"
            else:
                access_desc = f"Access denied (Mapping={mapping})"

            title = f"SMB Share: {share_name} ({share_type})"
            description = f"Share: {share_name}\nType: {share_type}\nComment: {share.get('comment', 'N/A')}\nAccess: {access_desc}"

            fm.add_finding(
                engagement_id=engagement_id,
                host_id=host_id,
                title=title,
                finding_type='smb_share',
                severity=severity,
                description=description,
                tool='enum4linux',
                port=445  # SMB default port
            )
            findings_added += 1

        stats = get_smb_stats(parsed)

        return {
            'tool': 'enum4linux',
            'findings_added': findings_added,
            'credentials_added': credentials_added,
            'users_found': len(parsed['users']),
            'shares_found': stats['total_shares'],
            'accessible_shares': stats['accessible_shares'],
            'writable_shares': stats['writable_shares'],
            'workgroup': stats.get('workgroup')
        }
    except Exception as e:
        return {'error': str(e)}


def parse_sqlmap_job(engagement_id: int, log_path: str, job: Dict[str, Any]) -> Dict[str, Any]:
    """Parse sqlmap job results."""
    try:
        from menuscript.parsers.sqlmap_parser import parse_sqlmap_output, get_sqli_stats
        from menuscript.storage.findings import FindingsManager
        from menuscript.storage.hosts import HostManager
        from urllib.parse import urlparse

        # Read the log file
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read()

        # Parse sqlmap output
        target = job.get('target', '')
        parsed = parse_sqlmap_output(log_content, target)

        # Get or create host from target URL
        hm = HostManager()
        host_id = None

        if parsed['target_url']:
            parsed_url = urlparse(parsed['target_url'])
            hostname = parsed_url.hostname

            if hostname:
                # Try to find existing host
                import re
                is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname)

                if is_ip:
                    host = hm.get_host_by_ip(engagement_id, hostname)
                    if host:
                        host_id = host['id']
                    else:
                        host_id = hm.add_or_update_host(engagement_id, {
                            'ip': hostname,
                            'status': 'up'
                        })
                else:
                    # Try to match by hostname
                    hosts = hm.list_hosts(engagement_id)
                    for h in hosts:
                        if h.get('hostname') == hostname:
                            host_id = h['id']
                            break

        # Store vulnerabilities as findings
        fm = FindingsManager()
        findings_added = 0

        for vuln in parsed['vulnerabilities']:
            # Determine severity
            vuln_type = vuln.get('vuln_type', 'unknown')
            if vuln_type == 'sqli' and vuln.get('injectable'):
                severity = 'critical'
                finding_type = 'sql_injection'
                title = f"SQL Injection in parameter '{vuln['parameter']}'"
            elif vuln_type == 'xss':
                severity = vuln.get('severity', 'medium')
                finding_type = 'xss'
                title = f"Possible XSS in parameter '{vuln['parameter']}'"
            elif vuln_type == 'file_inclusion':
                severity = vuln.get('severity', 'high')
                finding_type = 'file_inclusion'
                title = f"Possible File Inclusion in parameter '{vuln['parameter']}'"
            else:
                severity = 'medium'
                finding_type = 'web_vulnerability'
                title = f"Vulnerability in parameter '{vuln['parameter']}'"

            # Create description
            description = vuln.get('description', '')
            if vuln.get('technique'):
                description += f"\nTechnique: {vuln['technique']}"
            if vuln.get('dbms'):
                description += f"\nDBMS: {vuln['dbms']}"

            fm.add_finding(
                engagement_id=engagement_id,
                host_id=host_id,
                title=title,
                finding_type=finding_type,
                severity=severity,
                description=description,
                tool='sqlmap',
                path=vuln.get('url')
            )
            findings_added += 1

        stats = get_sqli_stats(parsed)

        return {
            'tool': 'sqlmap',
            'findings_added': findings_added,
            'sqli_confirmed': stats['sqli_confirmed'],
            'xss_possible': stats['xss_possible'],
            'fi_possible': stats['fi_possible'],
            'urls_tested': stats['urls_tested']
        }
    except Exception as e:
        return {'error': str(e)}

def parse_msf_auxiliary_job(engagement_id: int, log_path: str, job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse MSF auxiliary module job results."""
    try:
        from menuscript.parsers.msf_parser import parse_msf_log
        from menuscript.storage.hosts import HostManager
        from menuscript.storage.findings import FindingsManager

        # Parse the log
        parsed = parse_msf_log(log_path)

        if 'error' in parsed:
            return {'error': parsed['error']}

        target = job.get('target', '')
        hm = HostManager()
        fm = FindingsManager()

        services_added = 0
        findings_added = 0

        # Get or create host
        host = hm.get_host_by_ip(engagement_id, target)
        if not host:
            host_id = hm.add_host(engagement_id, target)
        else:
            host_id = host['id']

        # Add services if any
        for svc in parsed.get('services', []):
            hm.add_service(
                host_id=host_id,
                port=svc.get('port'),
                protocol=svc.get('protocol', 'tcp'),
                state=svc.get('state', 'open'),
                service_name=svc.get('service_name'),
                service_version=svc.get('service_version')
            )
            services_added += 1

        # Add findings
        for finding in parsed.get('findings', []):
            fm.add_finding(
                engagement_id=engagement_id,
                host_id=host_id,
                title=finding.get('title'),
                finding_type='credential' if 'credential' in finding.get('title', '').lower() else 'security_issue',
                severity=finding.get('severity', 'info'),
                description=finding.get('description'),
                tool='msf_auxiliary',
                port=finding.get('port')
            )
            findings_added += 1

        return {
            'tool': 'msf_auxiliary',
            'host': target,
            'services_added': services_added,
            'findings_added': findings_added
        }
    except Exception as e:
        return {'error': str(e)}
