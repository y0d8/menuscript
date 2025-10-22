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
from menuscript.storage.workspaces import WorkspaceManager
from menuscript.storage.hosts import HostManager
from menuscript.storage.findings import FindingsManager


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


def render_header(workspace_name: str, width: int):
    """Render dashboard header."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("=" * width)
    title = "MENUSCRIPT LIVE DASHBOARD"
    lines.append(title.center(width))
    lines.append(f"Workspace: {workspace_name}".center(width))
    lines.append(timestamp.center(width))
    lines.append("=" * width)

    return lines


def render_workspace_stats(workspace_id: int, width: int):
    """Render workspace statistics panel."""
    wm = WorkspaceManager()
    stats = wm.stats(workspace_id)

    lines = []
    lines.append("")
    lines.append(click.style("WORKSPACE STATS", bold=True, fg='cyan'))
    lines.append("-" * width)

    # Create a compact stats view
    stats_line = (
        f"Hosts: {stats['hosts']:>4} | "
        f"Services: {stats['services']:>4} | "
        f"Findings: {stats['findings']:>4}"
    )
    lines.append(stats_line)

    return lines


def render_active_jobs(width: int):
    """Render active jobs panel."""
    jobs = list_jobs(limit=50)

    # Filter to running/pending jobs
    active_jobs = [j for j in jobs if j.get('status') in ('pending', 'running')]

    lines = []
    lines.append("")
    lines.append(click.style("ACTIVE JOBS", bold=True, fg='green'))
    lines.append("-" * width)

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


def render_recent_hosts(workspace_id: int, width: int):
    """Render hosts with most open ports/services."""
    hm = HostManager()
    all_hosts = hm.list_hosts(workspace_id)

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
    lines.append(click.style("TOP HOSTS BY SERVICES", bold=True, fg='green'))
    lines.append("-" * width)

    if not top_hosts:
        lines.append("No live hosts discovered yet")
    else:
        for host, svc_count in top_hosts:
            hid = host.get('id', '?')
            ip = (host.get('ip_address') or 'unknown')[:15]
            hostname = (host.get('hostname') or '')[:25]
            os_info = (host.get('os_name') or '')[:20]

            # Build description
            if hostname:
                desc = hostname
            elif os_info:
                desc = os_info
            else:
                desc = "new host"

            host_line = f"  [{hid:>3}] {ip:<15} {desc:<25} ({svc_count} svcs)"
            lines.append(host_line)

    return lines


def render_critical_findings(workspace_id: int, width: int):
    """Render critical and high severity findings."""
    fm = FindingsManager()
    findings = fm.list_findings(workspace_id)

    # Filter to critical/high severity
    critical = [f for f in findings if f.get('severity') in ('critical', 'high')]
    recent = sorted(critical, key=lambda x: x.get('id', 0), reverse=True)[:5]

    lines = []
    lines.append("")
    lines.append(click.style("CRITICAL/HIGH FINDINGS", bold=True, fg='red'))
    lines.append("-" * width)

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


def render_top_ports(workspace_id: int, width: int):
    """Render most commonly discovered open ports with host IPs."""
    hm = HostManager()
    all_hosts = hm.list_hosts(workspace_id)

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
    lines.append(click.style("TOP OPEN PORTS", bold=True, fg='cyan'))
    lines.append("-" * width)

    if not top_ports:
        lines.append("No ports discovered yet")
    else:
        for port_service, host_ips in top_ports:
            count = len(host_ips)

            # Smart truncation: show first 4 IPs, then "+X more"
            if count <= 4:
                ip_list = ", ".join(host_ips)
            else:
                shown = host_ips[:4]
                remaining = count - 4
                ip_list = ", ".join(shown) + f" +{remaining} more"

            port_label = f"{port_service} ({count} host{'s' if count != 1 else ''})"
            lines.append(f"  {port_label:<22} {ip_list}")

    return lines


def render_recent_findings(workspace_id: int, width: int):
    """Render recent findings/alerts."""
    fm = FindingsManager()
    findings = fm.list_findings(workspace_id)

    # Get most recent findings (by ID desc)
    recent = sorted(findings, key=lambda x: x.get('id', 0), reverse=True)[:5]

    lines = []
    lines.append("")
    lines.append(click.style("RECENT FINDINGS", bold=True, fg='red'))
    lines.append("-" * width)

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


def render_msf_credentials(workspace_id: int, width: int):
    """Render MSF credential findings (valid logins discovered)."""
    fm = FindingsManager()
    findings = fm.list_findings(workspace_id)

    # Filter to credential findings (critical severity with "Valid Credentials" in title)
    cred_findings = [
        f for f in findings
        if f.get('severity') == 'critical' and 'Valid Credentials' in f.get('title', '')
    ]
    recent_creds = sorted(cred_findings, key=lambda x: x.get('id', 0), reverse=True)[:5]

    lines = []
    lines.append("")
    lines.append(click.style("MSF VALID CREDENTIALS", bold=True, fg='red'))
    lines.append("-" * width)

    if not recent_creds:
        lines.append("No credentials found yet")
    else:
        for finding in recent_creds:
            fid = finding.get('id', '?')
            title = finding.get('title', 'No title')
            desc = finding.get('description', '')
            port = finding.get('port', '?')

            # Extract service from title (e.g., "SSH Valid Credentials Found" -> "SSH")
            service = 'unknown'
            if title:
                service = title.split()[0].lower() if title.split() else 'unknown'

            # Extract credentials from description
            # Format: "Valid ssh credentials: username:password"
            creds = "N/A"
            if ':' in desc and 'credentials:' in desc:
                creds_part = desc.split('credentials:')[-1].strip()
                creds = creds_part[:40]  # Truncate if too long

            cred_line = f"  [{fid:>3}] {service.upper():<8} {port:<6} {click.style(creds, fg='red', bold=True)}"
            lines.append(cred_line)

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
        lines.append(click.style(f"JOB #{job_id} SUMMARY - {tool}", bold=True, fg='green' if status == 'done' else 'red'))
        lines.append("-" * width)

        if status == 'error':
            lines.append(click.style("✗ Job failed", fg='red', bold=True))
        else:
            lines.append(click.style("✓ Scan completed successfully", fg='green', bold=True))

        lines.append("")

        # Try to get parsed results summary
        try:
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
        lines.append(click.style(f"LIVE LOG - Job #{job_id} ({tool})", bold=True, fg='magenta'))
        lines.append("-" * width)

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


def render_dashboard(workspace_id: int, workspace_name: str, follow_job_id: Optional[int] = None, refresh_interval: int = 5):
    """Render complete dashboard."""
    width, height = get_terminal_size()

    clear_screen()

    # Build all panels
    output = []

    # Header
    output.extend(render_header(workspace_name, width))

    # Stats
    output.extend(render_workspace_stats(workspace_id, width))

    # Active jobs
    output.extend(render_active_jobs(width))

    # Top hosts by services (most interesting targets)
    output.extend(render_recent_hosts(workspace_id, width))

    # Top open ports (network overview)
    output.extend(render_top_ports(workspace_id, width))

    # Critical/High findings
    output.extend(render_critical_findings(workspace_id, width))

    # MSF Valid Credentials
    output.extend(render_msf_credentials(workspace_id, width))

    # Live log - auto-follow most recent running job if not explicitly following
    if not follow_job_id:
        # Auto-select most recent running job
        jobs = list_jobs(limit=20)
        running_jobs = [j for j in jobs if j.get('status') == 'running']
        if running_jobs:
            follow_job_id = running_jobs[0].get('id')

    if follow_job_id:
        output.extend(render_live_log(follow_job_id, width, height))

    # Instructions
    output.append("")
    output.append("-" * width)
    if follow_job_id:
        output.append(f"Following Job #{follow_job_id} | Press Ctrl+C to exit | Refresh: {refresh_interval}s".center(width))
    else:
        output.append(f"Press Ctrl+C to exit | Refresh: {refresh_interval}s".center(width))

    # Print all lines
    for line in output:
        click.echo(line)


def run_dashboard(follow_job_id: Optional[int] = None, refresh_interval: int = 5):
    """Run the live dashboard with auto-refresh."""
    wm = WorkspaceManager()
    current_ws = wm.get_current()

    if not current_ws:
        click.echo(click.style("✗ No workspace selected! Use 'menuscript workspace use <name>'", fg='red'))
        return

    workspace_id = current_ws['id']
    workspace_name = current_ws['name']

    click.echo(click.style(f"\nStarting live dashboard for workspace '{workspace_name}'...", fg='green'))
    click.echo(click.style("Press Ctrl+C to exit\n", fg='yellow'))
    time.sleep(1)

    last_followed_job_id = None
    job_completed = False

    try:
        while True:
            # Track which job we're following
            current_follow_id = follow_job_id

            # Auto-follow most recent running job if not explicitly set
            if not current_follow_id:
                jobs = list_jobs(limit=20)
                running_jobs = [j for j in jobs if j.get('status') == 'running']
                if running_jobs:
                    current_follow_id = running_jobs[0].get('id')
                    last_followed_job_id = current_follow_id
                elif last_followed_job_id:
                    # Keep showing the last job we were following
                    current_follow_id = last_followed_job_id
                    # Check if it just completed
                    if not job_completed:
                        completed_job = get_job(last_followed_job_id)
                        if completed_job and completed_job.get('status') in ('completed', 'failed'):
                            job_completed = True

            render_dashboard(workspace_id, workspace_name, current_follow_id, refresh_interval)

            # If job just completed, stop auto-refresh and prompt
            if job_completed:
                click.echo()
                click.echo(click.style("Job completed! Output preserved above.", fg='green', bold=True))
                click.echo("Press ENTER to clear and continue monitoring, or Ctrl+C to exit...")
                try:
                    input()
                    job_completed = False
                    last_followed_job_id = None
                    clear_screen()
                except KeyboardInterrupt:
                    raise
            else:
                time.sleep(refresh_interval)

    except KeyboardInterrupt:
        click.echo("\n" + click.style("Dashboard stopped.", fg='green'))
        click.echo()
