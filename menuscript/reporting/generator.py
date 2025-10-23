#!/usr/bin/env python3
"""
menuscript.reporting.generator - Penetration Test Report Generator
"""
import datetime
import json
from typing import Dict, Any, List, Optional
from pathlib import Path


class ReportGenerator:
    """Generate penetration test reports in various formats."""

    def __init__(self, engagement_id: int):
        """Initialize report generator for an engagement."""
        from menuscript.storage.engagements import EngagementManager
        from menuscript.storage.hosts import HostManager
        from menuscript.storage.findings import FindingsManager
        from menuscript.storage.credentials import CredentialsManager
        from menuscript.storage.database import Database

        self.engagement_id = engagement_id
        self.em = EngagementManager()
        self.hm = HostManager()
        self.fm = FindingsManager()
        self.cm = CredentialsManager()
        self.db = Database()

        # Load engagement data
        self.engagement = self.em.get_by_id(engagement_id)
        if not self.engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

    def collect_data(self) -> Dict[str, Any]:
        """Collect all data needed for the report."""
        # Get hosts
        hosts = self.hm.list_hosts(self.engagement_id)

        # Get findings grouped by severity
        conn = self.db.get_connection()
        findings = conn.execute('''
            SELECT id, title, finding_type, severity, description,
                   host_id, tool, port, path, refs, created_at
            FROM findings
            WHERE engagement_id = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END,
                created_at DESC
        ''', (self.engagement_id,)).fetchall()

        # Convert to dicts
        findings_list = []
        for f in findings:
            findings_list.append({
                'id': f[0],
                'title': f[1],
                'finding_type': f[2],
                'severity': f[3],
                'description': f[4],
                'host_id': f[5],
                'tool': f[6],
                'port': f[7],
                'path': f[8],
                'refs': f[9],
                'created_at': f[10]
            })

        # Get credentials
        credentials = self.cm.list_credentials(self.engagement_id)

        # Get findings summary
        findings_summary = self.fm.get_findings_summary(self.engagement_id)

        # Build host details with services
        hosts_with_services = []
        for host in hosts:
            services = self.hm.get_host_services(host['id'])
            hosts_with_services.append({
                **host,
                'services': services
            })

        conn.close()

        return {
            'engagement': self.engagement,
            'hosts': hosts_with_services,
            'findings': findings_list,
            'findings_summary': findings_summary,
            'credentials': credentials,
            'generated_at': datetime.datetime.utcnow().isoformat()
        }

    def generate_markdown(self, output_file: str = None) -> str:
        """Generate Markdown report."""
        data = self.collect_data()

        md = []
        md.append(f"# Penetration Test Report")
        md.append(f"## {data['engagement']['name']}")
        md.append("")
        md.append(f"**Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        md.append("")
        md.append("---")
        md.append("")

        # Scope Section
        md.append("## Scope")
        md.append("")
        md.append(f"**Target Network:** {data['engagement']['name']}")
        md.append("")
        scope = data['engagement'].get('scope')
        if scope:
            md.append(scope)
            md.append("")

        # Show scan range (all IPs scanned)
        all_ips = [h.get('ip_address') for h in data['hosts'] if h.get('ip_address')]
        if all_ips:
            # Try to detect CIDR pattern
            from ipaddress import ip_address, ip_network, summarize_address_range

            try:
                sorted_ips = sorted(all_ips, key=lambda x: ip_address(x))
                first_ip = ip_address(sorted_ips[0])
                last_ip = ip_address(sorted_ips[-1])

                # Try to summarize as CIDR
                networks = list(summarize_address_range(first_ip, last_ip))

                md.append("**IP Ranges Scanned:**")
                md.append("")
                if len(networks) <= 3:
                    for network in networks:
                        md.append(f"- {network}")
                else:
                    md.append(f"- {sorted_ips[0]} - {sorted_ips[-1]} ({len(all_ips)} IPs)")
            except:
                md.append("**IPs Scanned:**")
                md.append("")
                md.append(f"- {len(all_ips)} IP addresses")
            md.append("")

        md.append("**Test Duration:** " + data['engagement'].get('created_at', 'N/A'))
        md.append("")
        md.append("---")
        md.append("")

        # Methodology & Tools (moved up)
        md.append("## Methodology & Tools")
        md.append("")
        md.append("**Testing Approach:** Black-box penetration testing")
        md.append("")
        md.append("This assessment utilized the following security tools:")
        md.append("")

        # Tool descriptions
        tool_descriptions = {
            'nmap': 'Network scanner for host discovery and port scanning. Used to identify live hosts and enumerate open services.',
            'enum4linux': 'SMB/Windows enumeration tool for gathering information about shares, users, and groups.',
            'gobuster': 'Web directory and DNS brute-forcing tool for discovering hidden files, directories, and subdomains.',
            'nikto': 'Web server vulnerability scanner that checks for thousands of known security issues and misconfigurations.',
            'sqlmap': 'Automated SQL injection detection and exploitation tool for identifying and exploiting database vulnerabilities.',
            'theharvester': 'OSINT (Open Source Intelligence) tool for gathering email addresses, subdomains, and public information.',
            'msf_auxiliary': 'Metasploit Framework auxiliary modules for enumeration, brute-forcing, and vulnerability scanning.',
            'smbmap': 'SMB share enumeration tool that identifies accessible shares and their permissions.',
            'hydra': 'Network authentication cracking tool for brute-force attacks against various services.',
            'wpscan': 'WordPress vulnerability scanner for identifying security issues in WordPress installations.',
        }

        tools = self.fm.get_unique_tools(self.engagement_id)
        for tool in tools:
            desc = tool_descriptions.get(tool, 'Security testing tool')
            md.append(f"- **{tool}**: {desc}")
        md.append("")
        md.append("---")
        md.append("")

        # Executive Summary
        md.append("## Executive Summary")
        md.append("")
        total_hosts = len(data['hosts'])
        critical = data['findings_summary'].get('critical', 0)
        high = data['findings_summary'].get('high', 0)
        medium = data['findings_summary'].get('medium', 0)
        low = data['findings_summary'].get('low', 0)

        # Generate narrative summary
        tools_used = self.fm.get_unique_tools(self.engagement_id)
        valid_creds = [c for c in data['credentials'] if c.get('status') == 'valid']
        hosts_with_services = [h for h in data['hosts'] if h.get('services')]
        active_hosts = [h for h in data['hosts'] if h.get('status') == 'up']

        # Build narrative based on findings
        narrative = f"During this penetration test, **{len(tools_used)} security tools** were employed to assess the target environment. "
        narrative += f"The assessment scanned **{total_hosts} hosts** and found **{len(active_hosts)} active hosts**, of which **{len(hosts_with_services)} hosts** had open services that were further enumerated. "

        if len(data['findings']) > 0:
            narrative += f"Through automated scanning and manual verification, **{len(data['findings'])} security findings** were discovered. "

        if valid_creds:
            narrative += f"Notably, **{len(valid_creds)} valid credential pair(s)** were successfully obtained through brute-force attacks and enumeration techniques, "
            narrative += "demonstrating weak password policies. "

        if critical > 0 or high > 0:
            narrative += f"The most critical discoveries include **{critical} critical** and **{high} high** severity issues that pose immediate risk to the organization's security posture."

        md.append(narrative)
        md.append("")
        md.append("")

        md.append("**Findings Breakdown:**")
        md.append("")
        md.append(f"- **{critical} Critical** - Immediate action required")
        md.append(f"- **{high} High** - Should be addressed urgently")
        md.append(f"- **{medium} Medium** - Should be remediated")
        md.append(f"- **{low} Low** - Consider remediation")
        md.append("")

        if critical > 0 or high > 0:
            md.append("**⚠️ CRITICAL/HIGH SEVERITY ISSUES REQUIRE IMMEDIATE ATTENTION**")
            md.append("")

        md.append("---")
        md.append("")

        # Findings
        md.append("## Findings")
        md.append("")

        # Group findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = [f for f in data['findings'] if f['severity'] == severity]
            if not severity_findings:
                continue

            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': '⚪'
            }

            md.append(f"### {severity_icon.get(severity, '')} {severity.upper()} Severity")
            md.append("")

            for idx, finding in enumerate(severity_findings, 1):
                md.append(f"#### {idx}. {finding['title']}")
                md.append("")
                md.append(f"**Severity:** {finding['severity'].upper()}")
                md.append(f"**Type:** {finding['finding_type']}")
                if finding.get('tool'):
                    md.append(f"**Discovered by:** {finding['tool']}")

                # Get host info
                if finding.get('host_id'):
                    host = next((h for h in data['hosts'] if h['id'] == finding['host_id']), None)
                    if host:
                        md.append(f"**Affected Host:** {host.get('ip_address', 'N/A')}")
                        if host.get('hostname'):
                            md.append(f"**Hostname:** {host['hostname']}")

                if finding.get('port'):
                    md.append(f"**Port:** {finding['port']}")
                if finding.get('path'):
                    md.append(f"**Path:** {finding['path']}")

                md.append("")
                md.append("**Description:**")
                md.append("")
                md.append(finding.get('description', 'No description available.'))
                md.append("")

                if finding.get('refs'):
                    md.append("**References:**")
                    md.append("")
                    md.append(finding['refs'])
                    md.append("")

                md.append("---")
                md.append("")

        # Ports & Services Summary
        md.append("## Ports & Services Summary")
        md.append("")

        # Collect all unique services
        all_services = {}
        for host in data['hosts']:
            for svc in host.get('services', []):
                port = svc.get('port')
                service_name = svc.get('service_name', 'unknown')
                key = f"{port}/{svc.get('protocol', 'tcp')}"

                if key not in all_services:
                    all_services[key] = {
                        'port': port,
                        'protocol': svc.get('protocol', 'tcp'),
                        'service': service_name,
                        'hosts': []
                    }
                all_services[key]['hosts'].append(host.get('ip_address', 'N/A'))

        if all_services:
            md.append("| Port | Protocol | Service | Host Count | Sample Hosts |")
            md.append("|------|----------|---------|------------|--------------|")

            # Sort by host count (descending), then by port number
            sorted_services = sorted(all_services.items(), key=lambda x: (-len(x[1]['hosts']), int(x[0].split('/')[0])))

            for key, svc in sorted_services:
                host_count = len(svc['hosts'])
                sample_hosts = ', '.join(svc['hosts'][:3])
                if host_count > 3:
                    sample_hosts += f", ... (+{host_count - 3} more)"

                md.append(f"| {svc['port']} | {svc['protocol']} | {svc['service']} | {host_count} | {sample_hosts} |")

            md.append("")
        else:
            md.append("No open ports/services discovered.")
            md.append("")

        # Most Vulnerable Hosts
        md.append("## Most Vulnerable Hosts")
        md.append("")

        # Create host_id to IP mapping
        host_id_to_ip = {h['id']: h.get('ip_address', 'Unknown') for h in data['hosts']}

        # Calculate vulnerability score per host (based on findings)
        host_vulnerabilities = {}
        for finding in data['findings']:
            host_id = finding.get('host_id')
            if not host_id:
                continue

            # Get IP address for this host
            host_ip = host_id_to_ip.get(host_id, f'Host-{host_id}')
            severity = finding.get('severity', 'info').lower()

            # Severity weights
            severity_weight = {
                'critical': 10,
                'high': 5,
                'medium': 2,
                'low': 1,
                'info': 0.5
            }.get(severity, 1)

            if host_ip not in host_vulnerabilities:
                host_vulnerabilities[host_ip] = {
                    'score': 0,
                    'findings': [],
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            host_vulnerabilities[host_ip]['score'] += severity_weight
            host_vulnerabilities[host_ip]['findings'].append(finding.get('title', 'Unknown'))
            host_vulnerabilities[host_ip][severity] = host_vulnerabilities[host_ip].get(severity, 0) + 1

        if host_vulnerabilities:
            # Sort hosts by vulnerability score
            sorted_vulnerable = sorted(host_vulnerabilities.items(), key=lambda x: x[1]['score'], reverse=True)

            md.append("| Rank | Host | Vulnerability Score | Critical | High | Medium | Low | Info |")
            md.append("|------|------|---------------------|----------|------|--------|-----|------|")

            for idx, (host_ip, vuln_data) in enumerate(sorted_vulnerable[:10], 1):  # Top 10
                md.append(f"| {idx} | {host_ip} | {vuln_data['score']:.1f} | {vuln_data['critical']} | {vuln_data['high']} | {vuln_data['medium']} | {vuln_data['low']} | {vuln_data['info']} |")

            md.append("")
        else:
            md.append("No vulnerabilities mapped to specific hosts.")
            md.append("")

        # Discovered Hosts (Detailed)
        md.append("## Discovered Hosts (Detailed)")
        md.append("")

        active_hosts = [h for h in data['hosts'] if h.get('status') == 'up']
        md.append(f"Active hosts: **{len(active_hosts)} / {len(data['hosts'])}**")
        md.append("")

        # Show ALL hosts with open ports (not limited to 20)
        hosts_with_services = [h for h in data['hosts'] if h.get('services')]

        # Sort hosts by number of open ports (descending)
        hosts_with_services.sort(key=lambda h: len(h.get('services', [])), reverse=True)

        if hosts_with_services:
            md.append(f"### Hosts with Open Services ({len(hosts_with_services)})")
            md.append("")

            for host in hosts_with_services:
                port_count = len(host.get('services', []))
                md.append(f"#### {host.get('ip_address', 'Unknown')} ({port_count} open ports)")
                if host.get('hostname'):
                    md.append(f"**Hostname:** {host['hostname']}")
                if host.get('os_name'):
                    md.append(f"**OS:** {host['os_name']}")

                md.append("")
                md.append("**Open Ports:**")
                md.append("")
                md.append("| Port | Protocol | Service | Version |")
                md.append("|------|----------|---------|---------|")

                for svc in host.get('services', []):
                    port = svc.get('port', 'N/A')
                    proto = svc.get('protocol', 'tcp')
                    service = svc.get('service_name', 'unknown')
                    version = svc.get('service_version', '')
                    md.append(f"| {port} | {proto} | {service} | {version} |")

                md.append("")

        # Credentials
        if data['credentials']:
            md.append("## Discovered Credentials")
            md.append("")

            valid_creds = [c for c in data['credentials'] if c.get('status') == 'valid']
            if valid_creds:
                md.append(f"### Valid Credentials ({len(valid_creds)})")
                md.append("")
                md.append("| Username | Password | Service | Host | Tool |")
                md.append("|----------|----------|---------|------|------|")

                for cred in valid_creds:
                    username = cred.get('username', '')
                    password = cred.get('password', '(empty)')
                    service = cred.get('service', 'N/A')

                    # Get host IP
                    host_ip = 'N/A'
                    if cred.get('host_id'):
                        host = next((h for h in data['hosts'] if h['id'] == cred['host_id']), None)
                        if host:
                            host_ip = host.get('ip_address', 'N/A')

                    tool = cred.get('tool', 'N/A')
                    md.append(f"| {username} | {password} | {service} | {host_ip} | {tool} |")

                md.append("")

            # Untested usernames
            untested = [c for c in data['credentials'] if c.get('status') == 'untested' and not c.get('password')]
            if untested and len(untested) <= 50:
                md.append(f"### Discovered Usernames ({len(untested)})")
                md.append("")
                usernames = [c.get('username') for c in untested if c.get('username')]
                md.append(", ".join(usernames[:50]))
                md.append("")

        # Footer
        md.append("---")
        md.append("")
        md.append(f"*Report generated with [Menuscript](https://github.com/yourusername/menuscript) on {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*")

        report_text = "\n".join(md)

        # Save to file if specified
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)

        return report_text

    def generate_html(self, output_file: str = None) -> str:
        """Generate HTML report with styling."""
        data = self.collect_data()

        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html lang='en'>")
        html.append("<head>")
        html.append("    <meta charset='UTF-8'>")
        html.append("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append(f"    <title>Penetration Test Report - {data['engagement']['name']}</title>")
        html.append("    <style>")
        html.append("""
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 40px; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; }
        h3 { color: #555; margin-top: 30px; }
        .severity-critical { background: #e74c3c; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
        .severity-high { background: #e67e22; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
        .severity-medium { background: #f39c12; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
        .severity-low { background: #3498db; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
        .severity-info { background: #95a5a6; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
        .finding {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .finding-critical { border-left-color: #e74c3c; }
        .finding-high { border-left-color: #e67e22; }
        .finding-medium { border-left-color: #f39c12; }
        .finding-low { border-left-color: #3498db; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #34495e;
            color: white;
            font-weight: 600;
        }
        tr:hover { background: #f5f5f5; }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 14px;
            text-transform: uppercase;
        }
        .meta { color: #7f8c8d; font-size: 14px; }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }
        """)
        html.append("    </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("    <div class='container'>")

        # Header
        html.append(f"        <h1>Penetration Test Report</h1>")
        html.append(f"        <h2>{data['engagement']['name']}</h2>")
        html.append(f"        <p class='meta'>Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>")

        # Scope Section
        html.append("        <h2>Scope</h2>")
        html.append(f"        <p><strong>Target Network:</strong> {data['engagement']['name']}</p>")
        scope = data['engagement'].get('scope')
        if scope:
            html.append(f"        <p>{scope}</p>")

        # Show scan range
        all_ips = [h.get('ip_address') for h in data['hosts'] if h.get('ip_address')]
        if all_ips:
            from ipaddress import ip_address, summarize_address_range

            try:
                sorted_ips = sorted(all_ips, key=lambda x: ip_address(x))
                first_ip = ip_address(sorted_ips[0])
                last_ip = ip_address(sorted_ips[-1])
                networks = list(summarize_address_range(first_ip, last_ip))

                html.append("        <p><strong>IP Ranges Scanned:</strong></p>")
                html.append("        <ul>")
                if len(networks) <= 3:
                    for network in networks:
                        html.append(f"            <li>{network}</li>")
                else:
                    html.append(f"            <li>{sorted_ips[0]} - {sorted_ips[-1]} ({len(all_ips)} IPs)</li>")
                html.append("        </ul>")
            except:
                html.append(f"        <p><strong>IPs Scanned:</strong> {len(all_ips)} IP addresses</p>")

        html.append(f"        <p><strong>Test Duration:</strong> {data['engagement'].get('created_at', 'N/A')}</p>")

        # Methodology & Tools (moved up)
        html.append("        <h2>Methodology & Tools</h2>")
        html.append("        <p><strong>Testing Approach:</strong> Black-box penetration testing</p>")
        html.append("        <p>This assessment utilized the following security tools:</p>")

        tool_descriptions = {
            'nmap': 'Network scanner for host discovery and port scanning. Used to identify live hosts and enumerate open services.',
            'enum4linux': 'SMB/Windows enumeration tool for gathering information about shares, users, and groups.',
            'gobuster': 'Web directory and DNS brute-forcing tool for discovering hidden files, directories, and subdomains.',
            'nikto': 'Web server vulnerability scanner that checks for thousands of known security issues and misconfigurations.',
            'sqlmap': 'Automated SQL injection detection and exploitation tool for identifying and exploiting database vulnerabilities.',
            'theharvester': 'OSINT (Open Source Intelligence) tool for gathering email addresses, subdomains, and public information.',
            'msf_auxiliary': 'Metasploit Framework auxiliary modules for enumeration, brute-forcing, and vulnerability scanning.',
            'smbmap': 'SMB share enumeration tool that identifies accessible shares and their permissions.',
            'hydra': 'Network authentication cracking tool for brute-force attacks against various services.',
            'wpscan': 'WordPress vulnerability scanner for identifying security issues in WordPress installations.',
        }

        tools_used = self.fm.get_unique_tools(self.engagement_id)
        html.append("        <ul>")
        for tool in tools_used:
            desc = tool_descriptions.get(tool, 'Security testing tool')
            html.append(f"            <li><strong>{tool}</strong>: {desc}</li>")
        html.append("        </ul>")

        # Executive Summary Stats
        html.append("        <h2>Executive Summary</h2>")

        # Calculate stats
        active_hosts_count = len([h for h in data['hosts'] if h.get('status') == 'up'])
        valid_creds_count = len([c for c in data['credentials'] if c.get('status') == 'valid'])

        html.append("        <div class='summary-stats'>")
        html.append(f"            <div class='stat-card'><div class='stat-number'>{len(data['hosts'])}</div><div class='stat-label'>Hosts Scanned</div></div>")
        html.append(f"            <div class='stat-card'><div class='stat-number'>{active_hosts_count}</div><div class='stat-label'>Active Hosts</div></div>")
        html.append(f"            <div class='stat-card'><div class='stat-number'>{len(data['findings'])}</div><div class='stat-label'>Findings</div></div>")
        html.append(f"            <div class='stat-card'><div class='stat-number'>{valid_creds_count}</div><div class='stat-label'>Valid Credentials</div></div>")
        html.append("        </div>")

        # Generate narrative summary
        tools_used = self.fm.get_unique_tools(self.engagement_id)
        valid_creds = [c for c in data['credentials'] if c.get('status') == 'valid']
        hosts_with_services = [h for h in data['hosts'] if h.get('services')]
        active_hosts = [h for h in data['hosts'] if h.get('status') == 'up']
        critical = data['findings_summary'].get('critical', 0)
        high = data['findings_summary'].get('high', 0)

        # Build narrative
        narrative = f"During this penetration test, <strong>{len(tools_used)} security tools</strong> were employed to assess the target environment. "
        narrative += f"The assessment scanned <strong>{len(data['hosts'])} hosts</strong> and found <strong>{len(active_hosts)} active hosts</strong>, of which <strong>{len(hosts_with_services)} hosts</strong> had open services that were further enumerated. "

        if len(data['findings']) > 0:
            narrative += f"Through automated scanning and manual verification, <strong>{len(data['findings'])} security findings</strong> were discovered. "

        if valid_creds:
            narrative += f"Notably, <strong>{len(valid_creds)} valid credential pair(s)</strong> were successfully obtained through brute-force attacks and enumeration techniques, "
            narrative += "demonstrating weak password policies. "

        if critical > 0 or high > 0:
            narrative += f"The most critical discoveries include <strong>{critical} critical</strong> and <strong>{high} high</strong> severity issues that pose immediate risk to the organization's security posture."

        html.append(f"        <p>{narrative}</p>")

        if critical > 0 or high > 0:
            html.append("        <div class='warning'>")
            html.append("            <strong>⚠️ WARNING:</strong> Critical or high severity issues require immediate attention.")
            html.append("        </div>")

        # Findings
        html.append("        <h2>Findings</h2>")

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = [f for f in data['findings'] if f['severity'] == severity]
            if not severity_findings:
                continue

            html.append(f"        <h3><span class='severity-{severity}'>{severity.upper()}</span> ({len(severity_findings)})</h3>")

            for finding in severity_findings:
                html.append(f"        <div class='finding finding-{severity}'>")
                html.append(f"            <h4>{finding['title']}</h4>")
                html.append(f"            <p><strong>Type:</strong> {finding['finding_type']}</p>")

                if finding.get('host_id'):
                    host = next((h for h in data['hosts'] if h['id'] == finding['host_id']), None)
                    if host:
                        html.append(f"            <p><strong>Host:</strong> {host.get('ip_address', 'N/A')}")
                        if finding.get('port'):
                            html.append(f":{finding['port']}")
                        html.append("</p>")

                if finding.get('tool'):
                    html.append(f"            <p><strong>Tool:</strong> {finding['tool']}</p>")

                desc = finding.get('description', 'No description').replace('\n', '<br>')
                html.append(f"            <p>{desc}</p>")
                html.append("        </div>")

        # Ports & Services Summary
        html.append("        <h2>Ports & Services Summary</h2>")

        # Collect all unique services
        all_services = {}
        for host in data['hosts']:
            for svc in host.get('services', []):
                port = svc.get('port')
                service_name = svc.get('service_name', 'unknown')
                key = f"{port}/{svc.get('protocol', 'tcp')}"

                if key not in all_services:
                    all_services[key] = {
                        'port': port,
                        'protocol': svc.get('protocol', 'tcp'),
                        'service': service_name,
                        'hosts': []
                    }
                all_services[key]['hosts'].append(host.get('ip_address', 'N/A'))

        if all_services:
            html.append("        <table>")
            html.append("            <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Host Count</th><th>Sample Hosts</th></tr>")

            # Sort by host count (descending), then by port number
            sorted_services = sorted(all_services.items(), key=lambda x: (-len(x[1]['hosts']), int(x[0].split('/')[0])))

            for key, svc in sorted_services:
                host_count = len(svc['hosts'])
                sample_hosts = ', '.join(svc['hosts'][:3])
                if host_count > 3:
                    sample_hosts += f", ... (+{host_count - 3} more)"

                html.append("            <tr>")
                html.append(f"                <td>{svc['port']}</td>")
                html.append(f"                <td>{svc['protocol']}</td>")
                html.append(f"                <td>{svc['service']}</td>")
                html.append(f"                <td>{host_count}</td>")
                html.append(f"                <td>{sample_hosts}</td>")
                html.append("            </tr>")

            html.append("        </table>")
        else:
            html.append("        <p>No open ports/services discovered.</p>")

        # Most Vulnerable Hosts
        html.append("        <h2>Most Vulnerable Hosts</h2>")

        # Create host_id to IP mapping
        host_id_to_ip = {h['id']: h.get('ip_address', 'Unknown') for h in data['hosts']}

        # Calculate vulnerability score per host (based on findings)
        host_vulnerabilities = {}
        for finding in data['findings']:
            host_id = finding.get('host_id')
            if not host_id:
                continue

            # Get IP address for this host
            host_ip = host_id_to_ip.get(host_id, f'Host-{host_id}')
            severity = finding.get('severity', 'info').lower()

            # Severity weights
            severity_weight = {
                'critical': 10,
                'high': 5,
                'medium': 2,
                'low': 1,
                'info': 0.5
            }.get(severity, 1)

            if host_ip not in host_vulnerabilities:
                host_vulnerabilities[host_ip] = {
                    'score': 0,
                    'findings': [],
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            host_vulnerabilities[host_ip]['score'] += severity_weight
            host_vulnerabilities[host_ip]['findings'].append(finding.get('title', 'Unknown'))
            host_vulnerabilities[host_ip][severity] = host_vulnerabilities[host_ip].get(severity, 0) + 1

        if host_vulnerabilities:
            # Sort hosts by vulnerability score
            sorted_vulnerable = sorted(host_vulnerabilities.items(), key=lambda x: x[1]['score'], reverse=True)

            html.append("        <table>")
            html.append("            <tr><th>Rank</th><th>Host</th><th>Vulnerability Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>")

            for idx, (host_ip, vuln_data) in enumerate(sorted_vulnerable[:10], 1):  # Top 10
                html.append("            <tr>")
                html.append(f"                <td>{idx}</td>")
                html.append(f"                <td>{host_ip}</td>")
                html.append(f"                <td>{vuln_data['score']:.1f}</td>")
                html.append(f"                <td>{vuln_data['critical']}</td>")
                html.append(f"                <td>{vuln_data['high']}</td>")
                html.append(f"                <td>{vuln_data['medium']}</td>")
                html.append(f"                <td>{vuln_data['low']}</td>")
                html.append(f"                <td>{vuln_data['info']}</td>")
                html.append("            </tr>")

            html.append("        </table>")
        else:
            html.append("        <p>No vulnerabilities mapped to specific hosts.</p>")

        # Hosts table (ALL hosts with services)
        hosts_with_services = [h for h in data['hosts'] if h.get('services')]

        # Sort hosts by number of open ports (descending)
        hosts_with_services.sort(key=lambda h: len(h.get('services', [])), reverse=True)

        if hosts_with_services:
            html.append(f"        <h2>Discovered Hosts ({len(hosts_with_services)} hosts with open services)</h2>")
            html.append("        <table>")
            html.append("            <tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Total Ports</th><th>Open Ports</th></tr>")

            for host in hosts_with_services:  # Show ALL, sorted by port count
                port_count = len(host.get('services', []))
                ports = ', '.join([str(s.get('port')) for s in host.get('services', [])[:10]])
                if len(host.get('services', [])) > 10:
                    ports += '...'

                html.append("            <tr>")
                html.append(f"                <td>{host.get('ip_address', 'N/A')}</td>")
                html.append(f"                <td>{host.get('hostname', '-')}</td>")
                html.append(f"                <td>{host.get('os_name', '-')}</td>")
                html.append(f"                <td>{port_count}</td>")
                html.append(f"                <td>{ports}</td>")
                html.append("            </tr>")

            html.append("        </table>")

        # Credentials
        valid_creds = [c for c in data['credentials'] if c.get('status') == 'valid']
        if valid_creds:
            html.append("        <h2>Compromised Credentials</h2>")
            html.append("        <table>")
            html.append("            <tr><th>Username</th><th>Password</th><th>Service</th><th>Host</th></tr>")

            for cred in valid_creds:
                host_ip = 'N/A'
                if cred.get('host_id'):
                    host = next((h for h in data['hosts'] if h['id'] == cred['host_id']), None)
                    if host:
                        host_ip = host.get('ip_address', 'N/A')

                html.append("            <tr>")
                html.append(f"                <td>{cred.get('username', '')}</td>")
                html.append(f"                <td>{cred.get('password', '(empty)')}</td>")
                html.append(f"                <td>{cred.get('service', 'N/A')}</td>")
                html.append(f"                <td>{host_ip}</td>")
                html.append("            </tr>")

            html.append("        </table>")

        # Footer
        html.append("        <hr>")
        html.append(f"        <p class='meta'>Report generated with Menuscript on {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>")
        html.append("    </div>")
        html.append("</body>")
        html.append("</html>")

        report_text = "\n".join(html)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)

        return report_text

    def generate_json(self, output_file: str = None) -> str:
        """Generate JSON export of all data."""
        data = self.collect_data()

        json_text = json.dumps(data, indent=2, default=str)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_text)

        return json_text
