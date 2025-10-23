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
    actions_text = " QUICK ACTIONS: [m] Menu  [h] Hosts  [s] Services  [f] Findings  [j] Jobs  [q] Quit "
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
    fm = FindingsManager()
    findings = fm.list_findings(engagement_id)

    # Filter to user/credential related findings
    # Include: valid credentials, user enumeration, account discoveries
    user_keywords = ['credential', 'user', 'username', 'login', 'account', 'valid', 'password']

    user_findings = []
    for f in findings:
        title = (f.get('title', '') or '').lower()
        desc = (f.get('description', '') or '').lower()

        # Check if title or description contains user-related keywords
        if any(keyword in title or keyword in desc for keyword in user_keywords):
            user_findings.append(f)

    recent_users = sorted(user_findings, key=lambda x: x.get('id', 0), reverse=True)[:5]

    lines = []
    lines.append("")
    lines.append(click.style("🔓 IDENTIFIED USERS & CREDENTIALS", bold=True, fg='red'))
    lines.append("─" * width)

    if not recent_users:
        lines.append("No users or credentials identified yet")
    else:
        for finding in recent_users:
            fid = finding.get('id', '?')
            title = finding.get('title', 'No title')
            desc = finding.get('description', '')
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

            # Truncate title if too long
            display_title = title[:50] + "..." if len(title) > 50 else title

            # Show IP, tool, and title
            finding_line = f"  [{fid:>3}] {ip:<15} {tool:<12} {click.style(display_title, fg=sev_color)}"
            lines.append(finding_line)

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
    click.echo(click.style("Press 'm' for menu, 'q' to quit, or Ctrl+C to exit\n", fg='yellow'))
    time.sleep(1)

    last_followed_job_id = None
    job_completed = False

    try:
        while True:
            # Check if there are any active jobs
            jobs = list_jobs(limit=50)
            active_jobs = [j for j in jobs if j.get('status') in ('pending', 'running')]

            # If no active jobs and not following a specific job, show static dashboard
            if not active_jobs and not follow_job_id:
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
                    elif user_input.lower() == 'j':
                        from menuscript.ui.interactive import view_jobs_menu
                        view_jobs_menu()
                        clear_screen()
                continue

            # Track which job we're following
            current_follow_id = follow_job_id

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
                    clear_screen()
                except KeyboardInterrupt:
                    raise
            else:
                # Check for keyboard input with timeout
                user_input = _wait_for_input(refresh_interval)
                if user_input:
                    if user_input.lower() == 'q':
                        break
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
                    elif user_input.lower() == 'j':
                        from menuscript.ui.interactive import view_jobs_menu
                        view_jobs_menu()
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
    click.echo("    " + click.style("[j]", fg='cyan', bold=True) + " or " +
               click.style("[4]", fg='cyan') + "  ⚡ Jobs           - Manage scanning tasks")
    click.echo()
    click.echo("                " + click.style("[5]", fg='cyan') + "  🌐 Web Paths      - View discovered web directories")
    click.echo("                " + click.style("[6]", fg='cyan') + "  📡 OSINT Data     - View gathered intelligence")
    click.echo()

    # Actions section
    click.echo(click.style("  ⚙️  ACTIONS", bold=True, fg='yellow'))
    click.echo("  ─" * 38)
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
            'j': 4, '4': 4,
            '5': 5,
            '6': 6,
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
            from menuscript.ui.interactive import view_jobs_menu
            view_jobs_menu()
        elif choice_num == 5:
            from menuscript.ui.interactive import view_web_paths
            view_web_paths(engagement_id)
        elif choice_num == 6:
            from menuscript.ui.interactive import view_osint
            view_osint(engagement_id)

    except (KeyboardInterrupt, EOFError):
        pass
