#!/usr/bin/env python3
"""
menuscript.ui.dashboard - Live dashboard with real-time updates
"""
import click
import time
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

from menuscript.engine.background import list_jobs, get_job
from menuscript.storage.engagements import EngagementManager
from menuscript.storage.hosts import HostManager
from menuscript.storage.findings import FindingsManager
from menuscript.storage.credentials import CredentialsManager


def clear_screen():
    """Clear the terminal screen."""
    os.system('clear' if os.name != 'nt' else 'cls')


def get_terminal_size():
    """Get terminal dimensions."""
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except:
        return 80, 24


def render_header(engagement_name: str, engagement_id: int, width: int):
    """Render compact dashboard header with status bar and quick actions."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get workspace stats for header
    em = EngagementManager()
    stats = em.stats(engagement_id)

    lines = []

    # Top border
    lines.append("┌" + "─" * (width - 2) + "┐")

    # Title line with workspace and time
    title_left = f"│ MENUSCRIPT DASHBOARD │ Engagement: {engagement_name}"
    title_right = f"{timestamp} │"
    padding = width - len(title_left) - len(title_right)
    lines.append(title_left + " " * padding + title_right)

    # Stats line
    stats_content = f"│ 📊 Hosts: {stats['hosts']} │ Services: {stats['services']} │ Findings: {stats['findings']}"
    stats_padding = width - len(stats_content) - 1
    lines.append(stats_content + " " * stats_padding + "│")

    # Bottom border
    lines.append("└" + "─" * (width - 2) + "┘")

    # Quick actions bar (bold/highlighted)
    lines.append("┏" + "━" * (width - 2) + "┓")
    actions_text = " QUICK ACTIONS: [m] Menu  [h] Hosts  [s] Services  [f] Findings  [c] Creds  [j] Jobs  [q] Quit "
    actions_padding = width - len(actions_text) - 2
    lines.append("┃" + click.style(actions_text + " " * actions_padding, bold=True, fg='cyan') + "┃")
    lines.append("┗" + "━" * (width - 2) + "┛")

    return lines


def render_workspace_stats(engagement_id: int, width: int):
    """Render workspace statistics panel (removed - now integrated in header)."""
    # Stats are now shown in the header, so this function returns empty
    return []


def render_active_jobs(width: int):
    """Render active jobs panel."""
    jobs = list_jobs(limit=50)

    # Filter to running/pending jobs
    active_jobs = [j for j in jobs if j.get('status') in ('pending', 'running')]

    lines = []
    lines.append("")
    lines.append(click.style("⚡ ACTIVE JOBS", bold=True, fg='green'))
    lines.append("─" * width)

    if not active_jobs:
        lines.append("No active jobs")
    else:
        # Show up to 5 active jobs
        for job in active_jobs[:5]:
            jid = job.get('id', '?')
            tool = job.get('tool', 'unknown')[:10]
            target = job.get('target', '')[:30]
            status = job.get('status', 'unknown')

            # Color code status
            if status == 'running':
                status_str = click.style(status, fg='yellow')
            else:
                status_str = status

            # Calculate elapsed time
            created = job.get('created_at', '')
            started = job.get('started_at', '')

            elapsed = ""
            if started:
                try:
                    from dateutil import parser as date_parser
                    start_time = date_parser.parse(started)
                    now = datetime.now(start_time.tzinfo)
                    delta = now - start_time
                    elapsed_secs = int(delta.total_seconds())
                    mins, secs = divmod(elapsed_secs, 60)
                    elapsed = f"{mins}m{secs}s"
                except:
                    elapsed = "?"

            job_line = f"  [{jid:>3}] {tool:<10} {target:<30} {status_str:<10} {elapsed}"
            lines.append(job_line)

    return lines


def render_recent_hosts(engagement_id: int, width: int):
    """Render hosts with most open ports/services."""
    hm = HostManager()
    all_hosts = hm.list_hosts(engagement_id)

    # Filter to live hosts and get service counts
    live_hosts = [h for h in all_hosts if h.get('status') == 'up']

    # Build list with service counts for sorting
    hosts_with_counts = []
    for host in live_hosts:
        services = hm.get_host_services(host.get('id'))
        svc_count = len(services) if services else 0
        hosts_with_counts.append((host, svc_count))

    # Sort by service count descending (most services first), then by ID
    hosts_with_counts.sort(key=lambda x: (x[1], x[0].get('id', 0)), reverse=True)
    top_hosts = hosts_with_counts[:5]

    lines = []
    lines.append("")
    lines.append(click.style("🎯 TOP HOSTS BY SERVICES", bold=True, fg='green'))
    lines.append("─" * width)

    if not top_hosts:
        lines.append("No live hosts discovered yet")
    else:
        # Calculate dynamic column widths based on terminal width
        # Total needed: ID(8) + IP(18) + Services(10) + borders/padding(8) = 44
        # Remaining width goes to Description/OS
        desc_width = max(35, width - 48)  # Minimum 35, or use remaining space

        # Top border
        lines.append("  ┌" + "─" * 8 + "┬" + "─" * 18 + "┬" + "─" * desc_width + "┬" + "─" * 10 + "┐")

        # Table headers
        header = f"  │ {'ID':<6} │ {'IP Address':<16} │ {'Description/OS':<{desc_width-2}} │ {'Services':>8} │"
        lines.append(click.style(header, bold=True))

        # Header separator
        lines.append("  ├" + "─" * 8 + "┼" + "─" * 18 + "┼" + "─" * desc_width + "┼" + "─" * 10 + "┤")

        for i, (host, svc_count) in enumerate(top_hosts):
            hid = f"#{host.get('id', '?')}"
            ip = (host.get('ip_address') or 'unknown')[:15]
            hostname = (host.get('hostname') or '')[:30]
            os_info = (host.get('os_name') or '')[:30]

            # Build description
            if hostname:
                desc = hostname
            elif os_info:
                desc = os_info
            else:
                desc = "new host"

            # Truncate description if needed
            if len(desc) > desc_width - 2:
                desc = desc[:desc_width-5] + "..."

            host_line = f"  │ {hid:<6} │ {ip:<16} │ {desc:<{desc_width-2}} │ {svc_count:>8} │"
            lines.append(host_line)

        # Bottom border
        lines.append("  └" + "─" * 8 + "┴" + "─" * 18 + "┴" + "─" * desc_width + "┴" + "─" * 10 + "┘")

    return lines


def render_critical_findings(engagement_id: int, width: int):
    """Render critical and high severity findings."""
    fm = FindingsManager()
    findings = fm.list_findings(engagement_id)

    # Filter to critical/high severity
    critical = [f for f in findings if f.get('severity') in ('critical', 'high')]
    recent = sorted(critical, key=lambda x: x.get('id', 0), reverse=True)[:5]

    lines = []
    lines.append("")
    lines.append(click.style("🔍 CRITICAL/HIGH FINDINGS", bold=True, fg='red'))
    lines.append("─" * width)

    if not recent:
        lines.append("No critical/high findings")
    else:
        for finding in recent:
            fid = finding.get('id', '?')
            severity = finding.get('severity', 'info')
            title = (finding.get('title') or 'No title')[:50]

            # Color code severity
            if severity == 'critical':
                sev_str = click.style('CRIT', fg='red', bold=True)
            else:
                sev_str = click.style('HIGH', fg='red')

            finding_line = f"  [{fid:>3}] {sev_str} {title}"
            lines.append(finding_line)

    return lines


def render_top_ports(engagement_id: int, width: int):
    """Render most commonly discovered open ports with host IPs."""
    hm = HostManager()
    all_hosts = hm.list_hosts(engagement_id)

    # Track ports and which hosts have them
    port_data = {}  # key: "port/service" -> value: list of host IPs
    for host in all_hosts:
        host_ip = host.get('ip_address', 'unknown')
        services = hm.get_host_services(host.get('id'))
        if services:
            for svc in services:
                port = svc.get('port')
                service_name = svc.get('service_name', 'unknown')
                if port:
                    key = f"{port}/{service_name}"
                    if key not in port_data:
                        port_data[key] = []
                    port_data[key].append(host_ip)

    # Sort by host count and take top 5
    top_ports = sorted(port_data.items(), key=lambda x: len(x[1]), reverse=True)[:5]

    lines = []
    lines.append("")
    lines.append(click.style("🔌 TOP OPEN PORTS", bold=True, fg='cyan'))
    lines.append("─" * width)

    if not top_ports:
        lines.append("No ports discovered yet")
    else:
        # Calculate dynamic column widths to match hosts table width
        # Total needed: Port/Service(22) + Count(8) + borders/padding(8) = 38
        # Remaining width goes to Hosts column
        hosts_col_width = max(40, width - 40)  # Minimum 40, or use remaining space

        # Top border
        lines.append("  ┌" + "─" * 22 + "┬" + "─" * 8 + "┬" + "─" * hosts_col_width + "┐")

        # Table headers
        header = f"  │ {'Port/Service':<20} │ {'Count':>6} │ {'Hosts':<{hosts_col_width-2}} │"
        lines.append(click.style(header, bold=True))

        # Header separator
        lines.append("  ├" + "─" * 22 + "┼" + "─" * 8 + "┼" + "─" * hosts_col_width + "┤")

        for i, (port_service, host_ips) in enumerate(top_ports):
            count = len(host_ips)

            # Smart truncation: show first 4 IPs, then "+X more"
            if count <= 4:
                ip_list = ", ".join(host_ips)
            else:
                shown = host_ips[:4]
                remaining = count - 4
                ip_list = ", ".join(shown) + f" +{remaining} more"

            # Truncate hosts list if too long for column
            if len(ip_list) > hosts_col_width - 2:
                ip_list = ip_list[:hosts_col_width-5] + "..."

            lines.append(f"  │ {port_service:<20} │ {count:>6} │ {ip_list:<{hosts_col_width-2}} │")

        # Bottom border
        lines.append("  └" + "─" * 22 + "┴" + "─" * 8 + "┴" + "─" * hosts_col_width + "┘")

    return lines


def render_recent_findings(engagement_id: int, width: int):
    """Render recent findings/alerts."""
    fm = FindingsManager()
    findings = fm.list_findings(engagement_id)

    # Get most recent findings (by ID desc)
    recent = sorted(findings, key=lambda x: x.get('id', 0), reverse=True)[:5]

    lines = []
    lines.append("")
    lines.append(click.style("🔍 RECENT FINDINGS", bold=True, fg='red'))
    lines.append("─" * width)

    if not recent:
        lines.append("No findings yet")
    else:
        for finding in recent:
            fid = finding.get('id', '?')
            severity = finding.get('severity', 'info')
            title = (finding.get('title') or 'No title')[:50]

            # Color code severity
            sev_colors = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'blue',
                'info': 'white'
            }
            sev_str = click.style(severity[:4].upper(), fg=sev_colors.get(severity, 'white'))

            finding_line = f"  [{fid:>3}] {sev_str} {title}"
            lines.append(finding_line)

    return lines


def render_identified_users(engagement_id: int, width: int):
    """Render identified users and credentials from all scans."""
    cm = CredentialsManager()
    fm = FindingsManager()
    
    # Get actual credentials from CredentialsManager
    credentials = cm.list_credentials(engagement_id)
    findings = fm.list_findings(engagement_id)

    # Filter to credential/authentication related findings
    credential_keywords = ['credential', 'password', 'login', 'ssh_login', 'rdp_login', 'smb_login']
    user_enum_keywords = ['username', 'user enumeration', 'account found', 'valid user']

    user_findings = []
    for f in findings:
        title = (f.get('title', '') or '').lower()
        desc = (f.get('description', '') or '').lower()
        finding_type = (f.get('finding_type', '') or '').lower()

        # Check for credential-specific finding types
        if 'credential' in finding_type or 'authentication' in finding_type:
            user_findings.append(f)
            continue

        # Check for credential/user keywords (more specific matching)
        text = title + ' ' + desc
        if any(keyword in text for keyword in credential_keywords + user_enum_keywords):
            user_findings.append(f)

    lines = []
    lines.append("")
    lines.append(click.style("🔐 CREDENTIALS & AUTHENTICATION", bold=True, fg='red'))
    lines.append("─" * width)

    # Show actual credentials first
    if credentials:
        lines.append(click.style(f"  Discovered Credentials: {len(credentials)}", bold=True, fg='cyan'))
        
        # Group by host for cleaner display
        creds_by_host = {}
        for cred in credentials:
            host_ip = cred.get('ip_address', 'N/A')
            if host_ip not in creds_by_host:
                creds_by_host[host_ip] = []
            creds_by_host[host_ip].append(cred)
        
        # Show up to 5 hosts with credentials
        for idx, (host_ip, host_creds) in enumerate(list(creds_by_host.items())[:5]):
            service = host_creds[0].get('service', 'unknown')
            tool = host_creds[0].get('tool', 'unknown')
            usernames = [c.get('username', '?') for c in host_creds[:3]]
            
            if len(host_creds) > 3:
                display = f"{', '.join(usernames)}, +{len(host_creds)-3} more"
            else:
                display = ', '.join(usernames)
            
            status = host_creds[0].get('status', 'untested')
            status_color = 'green' if status == 'valid' else 'white'
            
            cred_line = f"  {host_ip:<15} {service:<10} {tool:<12} [{len(host_creds)} users] {click.style(display, fg=status_color)}"
            lines.append(cred_line)
        
        if len(creds_by_host) > 5:
            lines.append(f"  ... and {len(creds_by_host) - 5} more hosts")
    
    # Show authentication-related findings
    if user_findings:
        recent_findings = sorted(user_findings, key=lambda x: x.get('id', 0), reverse=True)[:3]
        if credentials:
            lines.append("")
            lines.append(click.style("  Related Findings:", bold=True, fg='cyan'))
        
        for finding in recent_findings:
            fid = finding.get('id', '?')
            title = finding.get('title', 'No title')
            severity = finding.get('severity', 'info')
            tool = finding.get('tool', 'unknown')
            ip = finding.get('ip_address', 'N/A')

            # Color code by severity
            if severity == 'critical':
                sev_color = 'red'
            elif severity == 'high':
                sev_color = 'red'
            elif severity == 'medium':
                sev_color = 'yellow'
            else:
                sev_color = 'white'

            display_title = title if len(title) <= 50 else title[:47] + "..."
            finding_line = f"  [{fid:>3}] {ip:<15} {tool:<12} {click.style(display_title, fg=sev_color)}"
            lines.append(finding_line)
    
    if not credentials and not user_findings:
        lines.append("No credentials or authentication findings yet")

    return lines


def render_live_log(job_id: Optional[int], width: int, height: int):
    """Render live log output from a running job, or summary if completed."""
    if not job_id:
        return []

    job = get_job(job_id)
    if not job:
        return []

    status = job.get('status', 'unknown')
    tool = job.get('tool', 'unknown')

    lines = []
    lines.append("")

    # If job is completed, show summary instead of raw log
    if status in ('done', 'error'):
        lines.append(click.style(f"📋 JOB #{job_id} SUMMARY - {tool}", bold=True, fg='green' if status == 'done' else 'red'))
        lines.append("─" * width)

        if status == 'error':
            lines.append(click.style("✗ Job failed", fg='red', bold=True))
        else:
            lines.append(click.style("✓ Scan completed successfully", fg='green', bold=True))

        lines.append("")

        # Try to get parsed results summary
        try:
            # First check if parse_result is already stored in the job
            result = job.get('parse_result')
            
            # If not stored, try to parse it now (for old jobs)
            if not result:
                from menuscript.engine.result_handler import handle_job_result
                result = handle_job_result(job)

            if result and 'error' not in result:
                lines.append(click.style("Results:", bold=True))

                # Show tool-specific summary
                if tool == 'nmap':
                    is_discovery = result.get('is_discovery', False)
                    is_full_scan = result.get('is_full_scan', False)
                    host_details = result.get('host_details', [])

                    if is_discovery:
                        # Discovery scan - just show count
                        hosts_added = result.get('hosts_added', 0)
                        lines.append(f"  • {hosts_added} live host(s) found")
                    elif is_full_scan:
                        # Full scan - show detailed info
                        if host_details:
                            lines.append("  Hosts discovered:")
                            for host in host_details:
                                ip = host.get('ip', 'unknown')
                                hostname = host.get('hostname', '')
                                os_info = host.get('os', '')
                                service_count = host.get('service_count', 0)
                                top_ports = host.get('top_ports', [])

                                # Header: IP (hostname)
                                if hostname:
                                    lines.append(f"    • {ip} ({hostname})")
                                else:
                                    lines.append(f"    • {ip}")

                                # OS info
                                if os_info:
                                    lines.append(f"      OS: {os_info}")

                                # Service count
                                lines.append(f"      Services: {service_count} open port(s)")

                                # Top ports
                                if top_ports:
                                    lines.append(f"      Top ports: {', '.join(top_ports)}")

                                lines.append("")  # Blank line between hosts
                        else:
                            hosts_added = result.get('hosts_added', 0)
                            lines.append(f"  • {hosts_added} live host(s) found (no services)")
                    else:
                        # Regular port scan - show each host with service count
                        if host_details:
                            lines.append("  Hosts discovered:")
                            for host in host_details:
                                ip = host.get('ip', 'unknown')
                                hostname = host.get('hostname', '')
                                service_count = host.get('service_count', 0)

                                # Format: IP (hostname) - N services
                                if hostname:
                                    lines.append(f"    • {ip} ({hostname}) - {service_count} service(s)")
                                else:
                                    lines.append(f"    • {ip} - {service_count} service(s)")
                        else:
                            hosts_added = result.get('hosts_added', 0)
                            lines.append(f"  • {hosts_added} live host(s) found (no services)")

                elif tool == 'msf_auxiliary':
                    host = result.get('host', 'N/A')
                    services_added = result.get('services_added', 0)
                    findings_added = result.get('findings_added', 0)
                    lines.append(f"  • Target: {host}")
                    if services_added > 0:
                        lines.append(f"  • {services_added} service(s) identified")
                    if findings_added > 0:
                        lines.append(click.style(f"  • {findings_added} finding(s) added", fg='red', bold=True))

                elif tool == 'gobuster':
                    paths_found = result.get('paths_found', 0)
                    lines.append(f"  • {paths_found} web path(s) discovered")

                else:
                    # Generic result display
                    for key, value in result.items():
                        if key not in ('tool', 'error'):
                            lines.append(f"  • {key}: {value}")

            elif result and 'error' in result:
                lines.append(click.style(f"✗ Parse error: {result['error']}", fg='yellow'))

        except Exception as e:
            lines.append(click.style(f"Could not parse results: {e}", fg='yellow'))

        lines.append("")
        lines.append(f"View full log: menuscript jobs show {job_id}")

    else:
        # Job is still running - show live log
        lines.append(click.style(f"📡 LIVE LOG - Job #{job_id} ({tool})", bold=True, fg='magenta'))
        lines.append("─" * width)

        log_path = job.get('log')
        if log_path and os.path.exists(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

                # Show last N lines (fit to screen)
                log_lines = content.split('\n')
                available = max(20, height - 23)

                if len(log_lines) > available:
                    log_lines = log_lines[-available:]

                # Track if we're in a fingerprint block to skip
                in_fingerprint_block = False

                for line in log_lines:
                    # Filter out noisy nmap TCP/IP fingerprint data
                    if 'TCP/IP fingerprint:' in line:
                        in_fingerprint_block = True
                        continue

                    # Skip lines that are part of fingerprint block (start with OS:, SEQ:, etc.)
                    if in_fingerprint_block:
                        # Fingerprint lines typically start with known prefixes
                        if line.startswith(('OS:', 'SEQ:', 'OPS:', 'WIN:', 'ECN:', 'T1:', 'T2:', 'T3:', 'T4:', 'T5:', 'T6:', 'T7:', 'U1:', 'IE:')):
                            continue
                        else:
                            # Empty line or new section means fingerprint block ended
                            in_fingerprint_block = False

                    # Truncate long lines
                    if len(line) > width:
                        line = line[:width-3] + '...'
                    lines.append(line)
            except Exception as e:
                lines.append(f"Error reading log: {e}")
        else:
            lines.append("No log available")

    return lines


def render_dashboard(engagement_id: int, engagement_name: str, follow_job_id: Optional[int] = None, refresh_interval: int = 5):
    """Render complete dashboard."""
    width, height = get_terminal_size()

    clear_screen()

    # Build all panels
    output = []

    # Header with status bar and quick actions
    output.extend(render_header(engagement_name, engagement_id, width))

    # Stats
    output.extend(render_workspace_stats(engagement_id, width))

    # Active jobs
    output.extend(render_active_jobs(width))

    # Top hosts by services (most interesting targets)
    output.extend(render_recent_hosts(engagement_id, width))

    # Top open ports (network overview)
    output.extend(render_top_ports(engagement_id, width))

    # Critical/High findings
    output.extend(render_critical_findings(engagement_id, width))

    # Identified Users & Credentials (from all scans)
    output.extend(render_identified_users(engagement_id, width))

    # Live log - auto-follow most recent running job if not explicitly following
    if not follow_job_id:
        # Auto-select most recent running job
        jobs = list_jobs(limit=20)
        running_jobs = [j for j in jobs if j.get('status') == 'running']
        if running_jobs:
            follow_job_id = running_jobs[0].get('id')

    if follow_job_id:
        output.extend(render_live_log(follow_job_id, width, height))

    # Footer
    output.append("")
    output.append("─" * width)
    if follow_job_id:
        footer_text = f"Following Job #{follow_job_id} | Refresh: {refresh_interval}s"
    else:
        footer_text = f"Auto-refresh: {refresh_interval}s"
    output.append(footer_text.center(width))

    # Print all lines
    for line in output:
        click.echo(line)


def run_dashboard(follow_job_id: Optional[int] = None, refresh_interval: int = 5):
    """Run the live dashboard with auto-refresh and interactive menu."""
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("✗ No workspace selected! Use 'menuscript workspace use <name>'", fg='red'))
        return

    engagement_id = current_ws['id']
    engagement_name = current_ws['name']

    click.echo(click.style(f"\nStarting live dashboard for workspace '{engagement_name}'...", fg='green'))
    click.echo(click.style("Press 'x' to refresh, 'm' for menu, 'r' for reports, 'q' to quit, or Ctrl+C to exit\n", fg='yellow'))
    time.sleep(1)

    last_followed_job_id = None
    job_completed = False
    last_seen_job_id = None  # Track the last job we've seen to detect new jobs
    auto_follow_job_id = follow_job_id  # Local variable we can modify

    try:
        while True:
            # Check if there are any active jobs
            jobs = list_jobs(limit=50)
            active_jobs = [j for j in jobs if j.get('status') in ('pending', 'running')]
            
            # Detect if a new job was created (auto-follow it)
            if jobs:
                latest_job = jobs[0]  # Most recent job
                latest_job_id = latest_job.get('id')
                # If this is a new job we haven't seen, and it's active, follow it
                if latest_job_id != last_seen_job_id:
                    if latest_job.get('status') in ('pending', 'running'):
                        # Auto-follow new jobs unless user specified a specific job
                        if not follow_job_id:  # Only auto-follow if user didn't specify -f
                            auto_follow_job_id = latest_job_id
                            last_followed_job_id = latest_job_id
                    last_seen_job_id = latest_job_id

            # If no active jobs and not following a specific job, show static dashboard
            if not active_jobs and not auto_follow_job_id:
                render_dashboard(engagement_id, engagement_name, None, refresh_interval)
                click.echo()
                click.echo(click.style("  ℹ️  No active scans running. Dashboard is in static mode.", fg='yellow', bold=True))
                click.echo(click.style("  💡 Launch a scan to enable auto-refresh monitoring.", fg='cyan'))
                click.echo()

                # Wait for user input without auto-refresh
                user_input = _wait_for_input(30)  # Longer timeout in static mode
                if user_input:
                    if user_input.lower() == 'q':
                        break
                    elif user_input.lower() == 'x':
                        # Manual refresh - just clear and loop
                        clear_screen()
                    elif user_input.lower() == 'm':
                        _show_dashboard_menu(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'h':
                        from menuscript.ui.interactive import view_hosts
                        view_hosts(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 's':
                        from menuscript.ui.interactive import view_services
                        view_services(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'f':
                        from menuscript.ui.interactive import view_findings
                        view_findings(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'c':
                        view_credentials(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'j':
                        from menuscript.ui.interactive import view_jobs_menu
                        view_jobs_menu()
                        clear_screen()
                    elif user_input.lower() == 'r':
                        from menuscript.ui.interactive import manage_reports_menu
                        manage_reports_menu()
                        clear_screen()
                continue

            # Track which job we're following
            current_follow_id = auto_follow_job_id

            # Auto-follow most recent running job if not explicitly set
            if not current_follow_id:
                running_jobs = [j for j in active_jobs if j.get('status') == 'running']
                if running_jobs:
                    current_follow_id = running_jobs[0].get('id')
                    last_followed_job_id = current_follow_id
                elif last_followed_job_id:
                    # Keep showing the last job we were following
                    current_follow_id = last_followed_job_id
                    # Check if it just completed
                    if not job_completed:
                        completed_job = get_job(last_followed_job_id)
                        if completed_job and completed_job.get('status') in ('done', 'error'):
                            job_completed = True

            render_dashboard(engagement_id, engagement_name, current_follow_id, refresh_interval)

            # If job just completed, stop auto-refresh and prompt
            if job_completed:
                click.echo()
                click.echo(click.style("Job completed! Output preserved above.", fg='green', bold=True))
                click.echo("Press ENTER to clear and continue monitoring, or Ctrl+C to exit...")
                try:
                    input()
                    job_completed = False
                    last_followed_job_id = None
                    auto_follow_job_id = None  # Reset to allow auto-follow of next job
                    clear_screen()
                except KeyboardInterrupt:
                    raise
            else:
                # Check for keyboard input with timeout
                user_input = _wait_for_input(refresh_interval)
                if user_input:
                    if user_input.lower() == 'q':
                        break
                    elif user_input.lower() == 'x':
                        # Manual refresh - just clear and loop
                        clear_screen()
                    elif user_input.lower() == 'm':
                        _show_dashboard_menu(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'h':
                        from menuscript.ui.interactive import view_hosts
                        view_hosts(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 's':
                        from menuscript.ui.interactive import view_services
                        view_services(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'f':
                        from menuscript.ui.interactive import view_findings
                        view_findings(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'c':
                        view_credentials(engagement_id)
                        clear_screen()
                    elif user_input.lower() == 'j':
                        from menuscript.ui.interactive import view_jobs_menu
                        view_jobs_menu()
                        clear_screen()
                    elif user_input.lower() == 'r':
                        from menuscript.ui.interactive import manage_reports_menu
                        manage_reports_menu()
                        clear_screen()

    except KeyboardInterrupt:
        click.echo("\n" + click.style("Dashboard stopped.", fg='green'))
        click.echo()


def _wait_for_input(timeout: int) -> Optional[str]:
    """Wait for keyboard input with timeout. Returns input or None."""
    import sys
    import select

    try:
        # Check if input is available (Unix-like systems)
        if hasattr(select, 'select'):
            rlist, _, _ = select.select([sys.stdin], [], [], timeout)
            if rlist:
                return sys.stdin.readline().strip()
        else:
            # Fallback for systems without select (just sleep)
            time.sleep(timeout)
        return None
    except Exception:
        time.sleep(timeout)
        return None


def _show_dashboard_menu(engagement_id: int):
    """Show interactive dashboard menu with clear instructions."""
    click.clear()

    # Header
    click.echo("\n┌" + "─" * 76 + "┐")
    click.echo("│" + click.style(" DASHBOARD NAVIGATION MENU ".center(76), bold=True, fg='cyan') + "│")
    click.echo("└" + "─" * 76 + "┘")
    click.echo()

    # Instructions
    click.echo(click.style("  💡 TIP: ", fg='yellow', bold=True) +
               "From the dashboard, press the shortcut key anytime (no menu needed)")
    click.echo()

    # Data Views section
    click.echo(click.style("  📊 DATA VIEWS", bold=True, fg='green'))
    click.echo("  ─" * 38)
    click.echo("    " + click.style("[h]", fg='cyan', bold=True) + " or " +
               click.style("[1]", fg='cyan') + "  🎯 Hosts          - View discovered hosts, add tags, filter")
    click.echo("    " + click.style("[s]", fg='cyan', bold=True) + " or " +
               click.style("[2]", fg='cyan') + "  🔌 Services       - Browse open ports and services")
    click.echo("    " + click.style("[f]", fg='cyan', bold=True) + " or " +
               click.style("[3]", fg='cyan') + "  🔍 Findings       - Review vulnerabilities and issues")
    click.echo("    " + click.style("[c]", fg='cyan', bold=True) + " or " +
               click.style("[4]", fg='cyan') + "  🔑 Credentials    - View discovered users and passwords")
    click.echo("    " + click.style("[j]", fg='cyan', bold=True) + " or " +
               click.style("[5]", fg='cyan') + "  ⚡ Jobs           - Manage scanning tasks")
    click.echo()
    click.echo("                " + click.style("[6]", fg='cyan') + "  🌐 Web Paths      - View discovered web directories")
    click.echo("                " + click.style("[7]", fg='cyan') + "  📡 OSINT Data     - View gathered intelligence")
    click.echo()

    # Actions section
    click.echo(click.style("  ⚙️  ACTIONS", bold=True, fg='yellow'))
    click.echo("  ─" * 38)
    click.echo("    " + click.style("[r]", fg='magenta', bold=True) + " or " +
               click.style("[8]", fg='magenta') + "  📄 Manage Reports  - View, generate, or delete reports")
    click.echo("    " + click.style("[q]", fg='red', bold=True) + " or " +
               click.style("[0]", fg='red') + "  ← Return to Live Dashboard")
    click.echo()

    # Footer instructions
    click.echo("  " + "─" * 76)
    click.echo(click.style("  Enter your choice: ", bold=True), nl=False)

    try:
        choice = input().strip().lower()

        # Map both letters and numbers
        choice_map = {
            'h': 1, '1': 1,
            's': 2, '2': 2,
            'f': 3, '3': 3,
            'c': 4, '4': 4,
            'j': 5, '5': 5,
            '6': 6,
            '7': 7,
            'r': 8, '8': 8,
            'q': 0, '0': 0, '': 0
        }

        choice_num = choice_map.get(choice, 0)

        if choice_num == 1:
            from menuscript.ui.interactive import view_hosts
            view_hosts(engagement_id)
        elif choice_num == 2:
            from menuscript.ui.interactive import view_services
            view_services(engagement_id)
        elif choice_num == 3:
            from menuscript.ui.interactive import view_findings
            view_findings(engagement_id)
        elif choice_num == 4:
            view_credentials(engagement_id)
        elif choice_num == 5:
            from menuscript.ui.interactive import view_jobs_menu
            view_jobs_menu()
        elif choice_num == 6:
            from menuscript.ui.interactive import view_web_paths
            view_web_paths(engagement_id)
        elif choice_num == 7:
            from menuscript.ui.interactive import view_osint
            view_osint(engagement_id)
        elif choice_num == 8:
            from menuscript.ui.interactive import manage_reports_menu
            manage_reports_menu()
    except (KeyboardInterrupt, EOFError):
        pass

    click.clear()

    # Header
    click.echo("\n┌" + "─" * 138 + "┐")
    click.echo("│" + click.style(f" CREDENTIALS - Engagement: {engagement_name} ".center(138), bold=True, fg='green') + "│")
    click.echo("└" + "─" * 138 + "┘")
    click.echo()

    cm = CredentialsManager()
    creds = cm.list_credentials(engagement_id)

    if not creds:
        click.echo(click.style("  No credentials found yet.", fg='yellow'))
        click.echo()
        click.echo("  💡 Credentials will appear here when discovered by:")
        click.echo("     • MSF auxiliary modules (ssh_enumusers, ssh_login, etc.)")
        click.echo("     • Brute force scans")
        click.echo("     • User enumeration modules")
        click.echo()
    else:
        # Show stats first - compact format
        stats = cm.get_stats(engagement_id)
        click.echo()
        click.echo(click.style("  📊 SUMMARY", bold=True, fg='cyan'))
        click.echo(f"     Total: {stats['total']}  |  " +
                   click.style(f"Valid: {stats['valid']}", fg='green', bold=True) +
                   f"  |  Usernames: {stats['users_only']}  |  Pairs: {stats['pairs']}")
        click.echo()

        # Separate valid and untested credentials
        valid_creds = [c for c in creds if c.get('status') == 'valid']
        untested_creds = [c for c in creds if c.get('status') != 'valid']

        # Show valid credentials prominently
        if valid_creds:
            click.echo(click.style("  🔓 VALID CREDENTIALS (Confirmed Working)", bold=True, fg='green'))
            click.echo("  " + "─" * 100)
            click.echo(f"     {'Username':<20} {'Password':<20} {'Service':<10} {'Host':<18} {'Tool':<15}")
            click.echo("  " + "─" * 100)

            for cred in valid_creds:
                username = cred.get('username', '')[:19]
                password = cred.get('password', '')[:19]
                service = cred.get('service', 'N/A')[:9]
                host = cred.get('ip_address', 'N/A')[:17]
                tool = cred.get('tool', 'N/A')[:14]

                click.echo(
                    "  " + click.style("✓", fg='green', bold=True) + " " +
                    click.style(f"{username:<20} {password:<20}", fg='green', bold=True) +
                    f" {service:<10} {host:<18} {tool:<15}"
                )

            click.echo("  " + "─" * 100)
            click.echo()

        # Show discovered usernames (untested) - minimal view
        if untested_creds:
            click.echo(click.style(f"  🔍 DISCOVERED USERNAMES ({len(untested_creds)} untested)", bold=True, fg='cyan'))
            click.echo("  " + "─" * 80)

            # Group by service
            by_service = {}
            for cred in untested_creds:
                service = cred.get('service', 'unknown')
                if service not in by_service:
                    by_service[service] = []
                by_service[service].append(cred.get('username', ''))

            # Show count only
            for service, usernames in sorted(by_service.items()):
                click.echo(f"     {service.upper():<8} ({len(usernames)} users)")

            click.echo("  " + "─" * 80)
            click.echo()
            click.echo(click.style("     💡 Press 'u' to view/manage untested usernames", fg='yellow'))
            click.echo()

    click.echo("  " + "─" * 76)
    click.echo(click.style("  [u] View Untested  [ENTER] Return to dashboard", fg='cyan'), nl=False)

    try:
        choice = input().strip().lower()
        if choice == 'u' and untested_creds:
            view_untested_usernames(engagement_id)
    except (KeyboardInterrupt, EOFError):
        pass


def view_credentials(engagement_id: int):
    """View all discovered credentials (similar to MSF's creds command)."""
    from menuscript.storage.credentials import CredentialsManager
    from menuscript.storage.engagements import EngagementManager

    em = EngagementManager()
    engagement = em.get_by_id(engagement_id)
    engagement_name = engagement['name'] if engagement else 'Unknown'

    click.clear()

    # Header
    click.echo("\n┌" + "─" * 138 + "┐")
    click.echo("│" + click.style(f" CREDENTIALS - Engagement: {engagement_name} ".center(138), bold=True, fg='green') + "│")
    click.echo("└" + "─" * 138 + "┘")
    click.echo()

    cm = CredentialsManager()
    creds = cm.list_credentials(engagement_id)
    untested_creds = []  # Initialize to avoid UnboundLocalError

    if not creds:
        click.echo(click.style("  No credentials found yet.", fg='yellow'))
        click.echo()
        click.echo("  💡 Credentials will appear here when discovered by:")
        click.echo("     • MSF auxiliary modules (ssh_enumusers, ssh_login, etc.)")
        click.echo("     • Brute force scans")
        click.echo("     • User enumeration modules")
        click.echo()
    else:
        # Show stats first - compact format
        stats = cm.get_stats(engagement_id)
        click.echo()
        click.echo(click.style("  📊 SUMMARY", bold=True, fg='cyan'))
        click.echo(f"     Total: {stats['total']}  |  " +
                   click.style(f"Valid: {stats['valid']}", fg='green', bold=True) +
                   f"  |  Usernames: {stats['users_only']}  |  Pairs: {stats['pairs']}")
        click.echo()

        # Separate valid and untested credentials
        valid_creds = [c for c in creds if c.get('status') == 'valid']
        untested_creds = [c for c in creds if c.get('status') != 'valid']

        # Show valid credentials prominently
        if valid_creds:
            click.echo(click.style("  🔓 VALID CREDENTIALS (Confirmed Working)", bold=True, fg='green'))
            click.echo("  " + "─" * 100)
            click.echo(f"     {'Username':<20} {'Password':<20} {'Service':<10} {'Host':<18} {'Tool':<15}")
            click.echo("  " + "─" * 100)

            for cred in valid_creds:
                username = cred.get('username', '')[:19]
                password = cred.get('password', '')[:19]
                service = cred.get('service', 'N/A')[:9]
                host = cred.get('ip_address', 'N/A')[:17]
                tool = cred.get('tool', 'N/A')[:14]

                click.echo(
                    "  " + click.style("✓", fg='green', bold=True) + " " +
                    click.style(f"{username:<20} {password:<20}", fg='green', bold=True) +
                    f" {service:<10} {host:<18} {tool:<15}"
                )

            click.echo("  " + "─" * 100)
            click.echo()

        # Show discovered usernames (untested) - minimal view
        if untested_creds:
            click.echo(click.style(f"  🔍 DISCOVERED USERNAMES ({len(untested_creds)} untested)", bold=True, fg='cyan'))
            click.echo("  " + "─" * 80)

            # Group by service
            by_service = {}
            for cred in untested_creds:
                service = cred.get('service', 'unknown')
                if service not in by_service:
                    by_service[service] = []
                by_service[service].append(cred.get('username', ''))

            # Show count only
            for service, usernames in sorted(by_service.items()):
                click.echo(f"     {service.upper():<8} ({len(usernames)} users)")

            click.echo("  " + "─" * 80)
            click.echo()
            click.echo(click.style("     💡 Press 'u' to view/manage untested usernames", fg='yellow'))
            click.echo()

    click.echo("  " + "─" * 76)
    click.echo(click.style("  [u] View Untested  [ENTER] Return to dashboard", fg='cyan'), nl=False)

    try:
        choice = input().strip().lower()
        if choice == 'u' and untested_creds:
            view_untested_usernames(engagement_id)
    except (KeyboardInterrupt, EOFError):
        pass


def view_untested_usernames(engagement_id: int):
    """View and manage untested usernames."""
    from menuscript.storage.credentials import CredentialsManager
    from menuscript.storage.engagements import EngagementManager

    em = EngagementManager()
    engagement = em.get_by_id(engagement_id)
    engagement_name = engagement['name'] if engagement else 'Unknown'

    click.clear()

    # Header
    click.echo("\n┌" + "─" * 78 + "┐")
    click.echo("│" + click.style(f" DISCOVERED USERNAMES - {engagement_name} ".center(78), bold=True, fg='cyan') + "│")
    click.echo("└" + "─" * 78 + "┘")
    click.echo()

    cm = CredentialsManager()
    all_creds = cm.list_credentials(engagement_id)
    untested = [c for c in all_creds if c.get('status') != 'valid' and c.get('username')]

    if not untested:
        click.echo(click.style("  No untested usernames found.", fg='yellow'))
        click.echo()
    else:
        # Group by service
        by_service = {}
        for cred in untested:
            service = cred.get('service', 'unknown')
            if service not in by_service:
                by_service[service] = []
            by_service[service].append(cred.get('username', ''))

        # Show each service with expandable view
        for service, usernames in sorted(by_service.items()):
            click.echo(click.style(f"  {service.upper()} ({len(usernames)} users)", bold=True, fg='cyan'))
            click.echo("  " + "─" * 76)

            # Show usernames in columns
            sorted_users = sorted(usernames)
            cols = 4
            col_width = 18

            for i in range(0, len(sorted_users), cols):
                row = sorted_users[i:i+cols]
                formatted_row = ''.join([f"{u[:17]:<{col_width}}" for u in row])
                click.echo(f"    {formatted_row}")

            click.echo()

    click.echo("  " + "─" * 76)
    click.echo(click.style("  Options:", bold=True))
    click.echo("    [1] Export to file")
    click.echo("    [2] Launch brute force attack with these users")
    click.echo("    [0] Return")
    click.echo()
    click.echo(click.style("  Select option: ", fg='cyan'), nl=False)

    try:
        choice = input().strip()

        if choice == '1':
            # Export to file
            export_usernames_to_file(engagement_id, untested)
            click.echo()
            click.echo(click.style("  Press ENTER to continue...", fg='cyan'), nl=False)
            input()

        elif choice == '2':
            # Launch brute force
            click.echo()
            click.echo(click.style("  Feature coming soon: Quick launch brute force", fg='yellow'))
            click.echo(click.style("  For now, use: menuscript interactive > MSF Auxiliary > SSH Brute Force", fg='cyan'))
            click.echo()
            click.echo(click.style("  Press ENTER to continue...", fg='cyan'), nl=False)
            input()

    except (KeyboardInterrupt, EOFError):
        pass


def export_usernames_to_file(engagement_id: int, untested_creds: list):
    """Export untested usernames to a file."""
    import os
    from menuscript.storage.engagements import EngagementManager

    em = EngagementManager()
    engagement = em.get_by_id(engagement_id)
    engagement_name = engagement['name'] if engagement else 'unknown'

    # Group by service
    by_service = {}
    for cred in untested_creds:
        service = cred.get('service', 'unknown')
        if service not in by_service:
            by_service[service] = []
        by_service[service].append(cred.get('username', ''))

    # Create filename
    filename = f"usernames_{engagement_name}_{int(time.time())}.txt"
    filepath = os.path.join(os.getcwd(), filename)

    try:
        with open(filepath, 'w') as f:
            for service, usernames in sorted(by_service.items()):
                f.write(f"# {service.upper()} ({len(usernames)} users)\n")
                for username in sorted(usernames):
                    f.write(f"{username}\n")
                f.write("\n")

        click.echo()
        click.echo(click.style(f"  ✓ Exported {len(untested_creds)} usernames to:", fg='green'))
        click.echo(f"    {filepath}")

    except Exception as e:
        click.echo()
        click.echo(click.style(f"  ✗ Error exporting: {e}", fg='red'))
