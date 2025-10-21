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


def render_recent_completions(width: int):
    """Render recently completed jobs."""
    jobs = list_jobs(limit=50)

    # Filter to done/failed jobs
    completed = [j for j in jobs if j.get('status') in ('done', 'failed')][:5]

    lines = []
    lines.append("")
    lines.append(click.style("RECENT COMPLETIONS", bold=True, fg='blue'))
    lines.append("-" * width)

    if not completed:
        lines.append("No completed jobs")
    else:
        for job in completed:
            jid = job.get('id', '?')
            tool = job.get('tool', 'unknown')[:10]
            target = job.get('target', '')[:30]
            status = job.get('status', 'unknown')

            # Color code status
            if status == 'done':
                status_str = click.style('✓ done', fg='green')
            elif status == 'failed':
                status_str = click.style('✗ fail', fg='red')
            else:
                status_str = status

            finished = job.get('finished_at', '')[:19] if job.get('finished_at') else 'N/A'

            job_line = f"  [{jid:>3}] {tool:<10} {target:<30} {status_str}"
            lines.append(job_line)

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


def render_live_log(job_id: Optional[int], width: int, height: int):
    """Render live log output from a running job."""
    if not job_id:
        return []

    job = get_job(job_id)
    if not job:
        return []

    lines = []
    lines.append("")
    lines.append(click.style(f"LIVE LOG - Job #{job_id} ({job.get('tool', 'unknown')})", bold=True, fg='magenta'))
    lines.append("-" * width)

    log_path = job.get('log')
    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            # Show last N lines (fit to screen)
            log_lines = content.split('\n')
            # Reserve space for header, stats, jobs, findings (approx 20-25 lines)
            available = max(5, height - 25)

            if len(log_lines) > available:
                log_lines = log_lines[-available:]

            for line in log_lines:
                # Truncate long lines
                if len(line) > width:
                    line = line[:width-3] + '...'
                lines.append(line)
        except Exception as e:
            lines.append(f"Error reading log: {e}")
    else:
        lines.append("No log available")

    return lines


def render_dashboard(workspace_id: int, workspace_name: str, follow_job_id: Optional[int] = None):
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

    # Recent completions
    output.extend(render_recent_completions(width))

    # Recent findings
    output.extend(render_recent_findings(workspace_id, width))

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
        output.append(f"Following Job #{follow_job_id} | Press Ctrl+C to exit | Refresh: 2s".center(width))
    else:
        output.append("Press Ctrl+C to exit | Refresh: 2s".center(width))

    # Print all lines
    for line in output:
        click.echo(line)


def run_dashboard(follow_job_id: Optional[int] = None, refresh_interval: int = 2):
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

    try:
        while True:
            render_dashboard(workspace_id, workspace_name, follow_job_id)
            time.sleep(refresh_interval)
    except KeyboardInterrupt:
        clear_screen()
        click.echo("\n" + click.style("Dashboard stopped.", fg='green'))
        click.echo()
