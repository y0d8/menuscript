#!/usr/bin/env python3
"""
menuscript.main - CLI entry point
"""
import click
import datetime
import os
import sys
from pathlib import Path

try:
    from menuscript.engine.background import enqueue_job, list_jobs, get_job, start_worker, worker_loop
    from menuscript.storage.engagements import EngagementManager
    from menuscript.ui.interactive import run_interactive_menu
    from menuscript.ui.dashboard import run_dashboard
except ImportError as e:
    click.echo(f"Import error: {e}", err=True)
    sys.exit(1)


@click.group()
@click.version_option(version='0.4.0')
def cli():
    """menuscript - Recon Suite for Penetration Testing"""
    pass


@cli.command()
def interactive():
    """Launch interactive tool selection menu."""
    run_interactive_menu()


@cli.command()
@click.option("--follow", "-f", type=int, default=None, help="Follow live output of job ID")
@click.option("--refresh", "-r", type=int, default=5, help="Refresh interval in seconds (default: 5)")
def dashboard(follow, refresh):
    """Launch live dashboard with real-time job status and findings."""
    run_dashboard(follow_job_id=follow, refresh_interval=refresh)


@cli.group()
def engagement():
    """Engagement management - organize your penetration testing engagements."""
    pass


@engagement.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Engagement description")
def engagement_create(name, description):
    """Create a new engagement."""
    em = EngagementManager()
    try:
        eng_id = em.create(name, description)
        click.echo(f"✓ Created engagement '{name}' (id={eng_id})")
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@engagement.command("list")
def engagement_list():
    """List all engagements."""
    em = EngagementManager()
    engagements = em.list()
    current = em.get_current()
    
    if not engagements:
        click.echo("No engagements found. Create one with: menuscript engagement create <name>")
        return
    
    click.echo("\n" + "=" * 80)
    click.echo("ENGAGEMENTS")
    click.echo("=" * 80)
    
    for eng in engagements:
        marker = "* " if current and eng['id'] == current['id'] else "  "
        stats = em.stats(eng['id'])
        click.echo(f"{marker}{eng['name']:<20} | Hosts: {stats['hosts']:>3} | Services: {stats['services']:>3} | Findings: {stats['findings']:>3}")
        if eng.get('description'):
            click.echo(f"  └─ {eng['description']}")
    
    click.echo("=" * 80)
    if current:
        click.echo(f"Current: {current['name']}")
    click.echo()


@engagement.command("use")
@click.argument("name")
def engagement_use(name):
    """Switch to an engagement."""
    em = EngagementManager()
    if em.set_current(name):
        click.echo(f"✓ Switched to workspace '{name}'")
    else:
        click.echo(f"✗ Workspace '{name}' not found", err=True)
        click.echo("Available engagements:")
        for eng in em.list():
            click.echo(f"  - {eng['name']}")


@engagement.command("current")
def engagement_current():
    """Show current engagement."""
    em = EngagementManager()
    current = em.get_current()
    
    if not current:
        click.echo("No engagement selected")
        return
    
    stats = em.stats(current['id'])
    
    click.echo("\n" + "=" * 60)
    click.echo(f"Current Engagement: {current['name']}")
    click.echo("=" * 60)
    click.echo(f"Description: {current.get('description', 'N/A')}")
    click.echo(f"Created: {current.get('created_at', 'N/A')}")
    click.echo()
    click.echo("Statistics:")
    click.echo(f"  Hosts:     {stats['hosts']}")
    click.echo(f"  Services:  {stats['services']}")
    click.echo(f"  Findings:  {stats['findings']}")
    click.echo("=" * 60 + "\n")


@engagement.command("delete")
@click.argument("name")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
def engagement_delete(name, force):
    """Delete an engagement and all its data."""
    em = EngagementManager()
    eng = em.get(name)
    
    if not eng:
        click.echo(f"✗ Workspace '{name}' not found", err=True)
        return
    
    if not force:
        stats = em.stats(eng['id'])
        click.echo(f"\nWarning: This will delete engagement '{name}' and:")
        click.echo(f"  - {stats['hosts']} hosts")
        click.echo(f"  - {stats['services']} services")
        click.echo(f"  - {stats['findings']} findings")
        
        if not click.confirm("\nAre you sure?"):
            click.echo("Cancelled")
            return
    
    if em.delete(name):
        click.echo(f"✓ Deleted workspace '{name}'")
    else:
        click.echo(f"✗ Error deleting workspace", err=True)


@cli.group()
def jobs():
    """Background job management."""
    pass


@jobs.command("enqueue")
@click.argument("tool")
@click.argument("target")
@click.option("--args", "-a", default="", help="Tool arguments (space-separated)")
@click.option("--label", "-l", default="", help="Job label")
def jobs_enqueue(tool, target, args, label):
    """Enqueue a background job."""
    args_list = args.split() if args else []
    
    try:
        job_id = enqueue_job(tool, target, args_list, label)
        click.echo(f"✓ Enqueued job {job_id}: {tool} {target}")
        click.echo(f"  Monitor: menuscript jobs get {job_id}")
        click.echo(f"  Tail log: menuscript jobs tail {job_id}")
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@jobs.command("list")
@click.option("--limit", "-n", default=20, help="Number of jobs to show")
@click.option("--status", "-s", default=None, help="Filter by status")
def jobs_list(limit, status):
    """List background jobs."""
    jobs_data = list_jobs(limit=limit)
    
    if status:
        jobs_data = [j for j in jobs_data if j.get('status') == status]
    
    if not jobs_data:
        click.echo("No jobs found")
        return
    
    click.echo("\n" + "=" * 100)
    click.echo(f"{'ID':<5} {'Tool':<12} {'Target':<25} {'Status':<10} {'Label':<20} {'Created':<20}")
    click.echo("=" * 100)
    
    for job in jobs_data:
        status_val = job.get('status', 'N/A')

        # Color code status
        if status_val == 'done':
            status_str = click.style(f"{status_val:<10}", fg='green')
        elif status_val == 'running':
            status_str = click.style(f"{status_val:<10}", fg='yellow')
        elif status_val in ('error', 'failed'):
            status_str = click.style(f"{status_val:<10}", fg='red')
        elif status_val == 'killed':
            status_str = click.style(f"{status_val:<10}", fg='magenta')
        else:
            status_str = f"{status_val:<10}"

        click.echo(
            f"{job['id']:<5} "
            f"{job.get('tool', 'N/A'):<12} "
            f"{job.get('target', 'N/A')[:24]:<25} "
            f"{status_str} "
            f"{job.get('label', '')[:19]:<20} "
            f"{job.get('created_at', 'N/A'):<20}"
        )
    
    click.echo("=" * 100 + "\n")


@jobs.command("get")
@click.argument("job_id", type=int)
def jobs_get(job_id):
    """Get job details."""
    job = get_job(job_id)
    
    if not job:
        click.echo(f"✗ Job {job_id} not found", err=True)
        return
    
    click.echo("\n" + "=" * 60)
    click.echo(f"Job {job_id}")
    click.echo("=" * 60)
    click.echo(f"Tool:       {job.get('tool', 'N/A')}")
    click.echo(f"Target:     {job.get('target', 'N/A')}")
    click.echo(f"Args:       {' '.join(job.get('args', []))}")
    click.echo(f"Label:      {job.get('label', 'N/A')}")
    click.echo(f"Status:     {job.get('status', 'N/A')}")
    click.echo(f"Created:    {job.get('created_at', 'N/A')}")
    click.echo(f"Started:    {job.get('started_at', 'N/A')}")
    click.echo(f"Finished:   {job.get('finished_at', 'N/A')}")
    click.echo(f"Log:        {job.get('log', 'N/A')}")
    
    if job.get('error'):
        click.echo(f"Error:      {job['error']}")
    
    click.echo("=" * 60 + "\n")


@jobs.command("show")
@click.argument("job_id", type=int)
def jobs_show(job_id):
    """Show job details and log output (alias for get + tail)."""
    import os

    job = get_job(job_id)

    if not job:
        click.echo(f"✗ Job {job_id} not found", err=True)
        return

    # Show job details
    click.echo("\n" + "=" * 70)
    click.echo(f"JOB #{job_id}")
    click.echo("=" * 70)
    click.echo(f"Tool:       {job.get('tool', 'N/A')}")
    click.echo(f"Target:     {job.get('target', 'N/A')}")
    click.echo(f"Args:       {' '.join(job.get('args', []))}")
    if job.get('label'):
        click.echo(f"Label:      {job['label']}")
    click.echo(f"Status:     {job.get('status', 'N/A')}")
    click.echo(f"Created:    {job.get('created_at', 'N/A')}")
    if job.get('started_at'):
        click.echo(f"Started:    {job['started_at']}")
    if job.get('finished_at'):
        click.echo(f"Finished:   {job['finished_at']}")

    if job.get('error'):
        click.echo(f"Error:      {job['error']}")

    click.echo()

    # Show log output
    log_path = job.get('log')
    if log_path and os.path.exists(log_path):
        click.echo(click.style("LOG OUTPUT:", bold=True, fg='cyan'))
        click.echo("-" * 70)

        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            # Show last 100 lines
            lines = content.split('\n')
            if len(lines) > 100:
                click.echo(f"... (showing last 100 of {len(lines)} lines)\n")
                lines = lines[-100:]

            for line in lines:
                click.echo(line)

        except Exception as e:
            click.echo(click.style(f"Error reading log: {e}", fg='red'))
    else:
        click.echo(click.style("No log file available", fg='yellow'))

    click.echo("\n" + "=" * 70 + "\n")


@jobs.command("tail")
@click.argument("job_id", type=int)
@click.option("--follow", "-f", is_flag=True, help="Follow log output")
def jobs_tail(job_id, follow):
    """Tail job log file."""
    import subprocess
    
    job = get_job(job_id)
    
    if not job:
        click.echo(f"✗ Job {job_id} not found", err=True)
        return
    
    log_path = job.get('log')
    
    if not log_path or not os.path.exists(log_path):
        click.echo(f"✗ Log file not found: {log_path}", err=True)
        return
    
    try:
        if follow:
            subprocess.run(["tail", "-f", log_path])
        else:
            subprocess.run(["tail", "-30", log_path])
    except KeyboardInterrupt:
        pass
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@jobs.command("kill")
@click.argument("job_id", type=int)
@click.option("--force", "-f", is_flag=True, help="Force kill (SIGKILL)")
def jobs_kill(job_id, force):
    """Kill a running job."""
    from menuscript.engine.background import kill_job

    job = get_job(job_id)

    if not job:
        click.echo(f"✗ Job {job_id} not found", err=True)
        return

    status = job.get('status')
    if status != 'running':
        click.echo(f"✗ Job {job_id} is not running (status: {status})", err=True)
        return

    if kill_job(job_id):
        click.echo(f"✓ Job {job_id} killed successfully", fg='green')
    else:
        click.echo(f"✗ Failed to kill job {job_id}", err=True)


@cli.group()
def worker():
    """Background worker management."""
    pass


@worker.command("start")
@click.option("--fg", is_flag=True, help="Run in foreground")
def worker_start(fg):
    """Start the background worker."""
    if fg:
        click.echo("Starting worker in foreground (Ctrl+C to stop)...")
        try:
            worker_loop()
        except KeyboardInterrupt:
            click.echo("\nWorker stopped")
    else:
        start_worker(detach=True)
        click.echo("✓ Background worker started")
        click.echo("  Logs: tail -f data/logs/worker.log")


@worker.command("status")
def worker_status():
    """Check worker status."""
    import subprocess
    
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        
        worker_procs = []
        for line in result.stdout.split('\n'):
            if 'menuscript' in line and 'worker' in line and 'grep' not in line:
                worker_procs.append(line)
        
        if worker_procs:
            click.echo("✓ Worker is running:")
            for proc in worker_procs:
                click.echo(f"  {proc}")
        else:
            click.echo("✗ Worker is not running")
            click.echo("  Start with: menuscript worker start")
    except Exception as e:
        click.echo(f"✗ Error checking status: {e}", err=True)


@cli.command("plugins")
def list_plugins():
    """List available plugins."""
    try:
        from menuscript.engine.loader import discover_plugins
        
        plugins = discover_plugins()
        
        if not plugins:
            click.echo("No plugins found")
            return
        
        click.echo("\n" + "=" * 80)
        click.echo("AVAILABLE PLUGINS")
        click.echo("=" * 80)
        
        for key, plugin in sorted(plugins.items()):
            name = getattr(plugin, 'name', 'Unknown')
            category = getattr(plugin, 'category', 'misc')
            click.echo(f"{key:<15} | {name:<30} | {category}")
        
        click.echo("=" * 80)
        click.echo(f"Total: {len(plugins)} plugins\n")
    except Exception as e:
        click.echo(f"✗ Error loading plugins: {e}", err=True)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()


# ==================== HOST COMMANDS ====================

@cli.group()
def hosts():
    """Host management commands."""
    pass


@hosts.command("list")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
@click.option("--all", "-a", is_flag=True, help="Show all hosts (including down hosts)")
@click.option("--status", "-s", default=None, help="Filter by status (up/down/unknown)")
def hosts_list(engagement, all, status):
    """List hosts in engagement (default: only live/up hosts)."""
    from menuscript.storage.hosts import HostManager

    em = EngagementManager()

    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected. Use: menuscript engagement use <name>", err=True)
            return

    hm = HostManager()
    all_hosts = hm.list_hosts(eng['id'])

    # Filter hosts
    if status:
        hosts = [h for h in all_hosts if h.get('status', 'unknown') == status]
    elif not all:
        # Default: only show 'up' hosts
        hosts = [h for h in all_hosts if h.get('status', 'unknown') == 'up']
    else:
        hosts = all_hosts

    if not hosts:
        filter_msg = f" with status='{status}'" if status else " (live only)" if not all else ""
        click.echo(f"No hosts found in workspace '{eng['name']}'{filter_msg}")
        return

    # Show filter info in header
    filter_info = ""
    if status:
        filter_info = f" (status={status})"
    elif not all:
        filter_info = " (live hosts only)"

    click.echo("\n" + "=" * 100)
    click.echo(f"HOSTS - Engagement: {eng['name']}{filter_info}")
    click.echo("=" * 100)
    click.echo(f"{'IP Address':<18} {'Hostname':<30} {'Status':<10} {'OS':<30}")
    click.echo("=" * 100)

    for host in hosts:
        click.echo(
            f"{host['ip_address']:<18} "
            f"{(host.get('hostname') or 'N/A')[:29]:<30} "
            f"{host.get('status', 'unknown'):<10} "
            f"{(host.get('os_name') or 'N/A')[:29]:<30}"
        )

    click.echo("=" * 100)
    click.echo(f"Total: {len(hosts)} hosts\n")


@hosts.command("show")
@click.argument("ip_address")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
def hosts_show(ip_address, workspace):
    """Show detailed host information."""
    from menuscript.storage.hosts import HostManager
    
    em = EngagementManager()
    
    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return
    
    hm = HostManager()
    host = hm.get_host_by_ip(eng['id'], ip_address)
    
    if not host:
        click.echo(f"✗ Host {ip_address} not found in workspace '{eng['name']}'", err=True)
        return
    
    services = hm.get_host_services(host['id'])
    
    click.echo("\n" + "=" * 80)
    click.echo(f"HOST: {host['ip_address']}")
    click.echo("=" * 80)
    click.echo(f"Hostname:     {host.get('hostname') or 'N/A'}")
    click.echo(f"Status:       {host.get('status', 'unknown')}")
    click.echo(f"OS:           {host.get('os_name') or 'N/A'}")
    click.echo(f"MAC:          {host.get('mac_address') or 'N/A'}")
    click.echo(f"First seen:   {host.get('created_at', 'N/A')}")
    click.echo(f"Last updated: {host.get('updated_at', 'N/A')}")
    
    click.echo("\n" + "-" * 80)
    click.echo(f"SERVICES ({len(services)})")
    click.echo("-" * 80)
    
    if services:
        click.echo(f"{'Port':<10} {'Protocol':<10} {'State':<10} {'Service':<20} {'Version':<30}")
        click.echo("-" * 80)
        for svc in services:
            click.echo(
                f"{svc['port']:<10} "
                f"{svc['protocol']:<10} "
                f"{svc['state']:<10} "
                f"{(svc.get('service_name') or 'unknown')[:19]:<20} "
                f"{(svc.get('service_version') or 'N/A')[:29]:<30}"
            )
    else:
        click.echo("No services found")
    
    click.echo("=" * 80 + "\n")


# ==================== SERVICE COMMANDS ====================

@cli.group()
def services():
    """Service management commands."""
    pass


@services.command("list")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
@click.option("--port", "-p", type=int, default=None, help="Filter by port")
def services_list(engagement, port):
    """List all services across all hosts."""
    from menuscript.storage.hosts import HostManager
    
    em = EngagementManager()
    
    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return
    
    hm = HostManager()
    
    # Get all hosts and their services
    hosts = hm.list_hosts(eng['id'])
    
    all_services = []
    for host in hosts:
        services = hm.get_host_services(host['id'])
        for svc in services:
            if port is None or svc['port'] == port:
                all_services.append({
                    'host_ip': host['ip_address'],
                    'host_name': host.get('hostname'),
                    **svc
                })
    
    if not all_services:
        click.echo(f"No services found in workspace '{eng['name']}'")
        return
    
    click.echo("\n" + "=" * 120)
    click.echo(f"SERVICES - Engagement: {eng['name']}")
    if port:
        click.echo(f"Filtered by port: {port}")
    click.echo("=" * 120)
    click.echo(f"{'Host':<18} {'Port':<8} {'Proto':<8} {'State':<10} {'Service':<20} {'Version':<40}")
    click.echo("=" * 120)
    
    for svc in sorted(all_services, key=lambda x: (x['host_ip'], x['port'])):
        click.echo(
            f"{svc['host_ip']:<18} "
            f"{svc['port']:<8} "
            f"{svc['protocol']:<8} "
            f"{svc['state']:<10} "
            f"{(svc.get('service_name') or 'unknown')[:19]:<20} "
            f"{(svc.get('service_version') or 'N/A')[:39]:<40}"
        )
    
    click.echo("=" * 120)
    click.echo(f"Total: {len(all_services)} services\n")


# ==================== FINDINGS COMMANDS ====================

@cli.group()
def findings():
    """Findings/vulnerabilities management commands."""
    pass


@findings.command("list")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
@click.option("--severity", "-s", default=None, help="Filter by severity (critical, high, medium, low, info)")
@click.option("--tool", "-t", default=None, help="Filter by tool")
@click.option("--host", "-h", default=None, help="Filter by host IP")
def findings_list(engagement, severity, tool, host):
    """List all findings in engagement."""
    from menuscript.storage.findings import FindingsManager

    em = EngagementManager()

    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    fm = FindingsManager()

    # Get host_id if filtering by host
    host_id = None
    if host:
        from menuscript.storage.hosts import HostManager
        hm = HostManager()
        host_obj = hm.get_host_by_ip(eng['id'], host)
        if not host_obj:
            click.echo(f"✗ Host {host} not found", err=True)
            return
        host_id = host_obj['id']

    findings = fm.list_findings(eng['id'], host_id=host_id, severity=severity, tool=tool)

    if not findings:
        click.echo(f"No findings found in workspace '{eng['name']}'")
        return

    # Get severity color mapping
    severity_colors = {
        'critical': 'red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'white'
    }

    click.echo("\n" + "=" * 140)
    click.echo(f"FINDINGS - Engagement: {eng['name']}")
    if severity:
        click.echo(f"Filtered by severity: {severity}")
    if tool:
        click.echo(f"Filtered by tool: {tool}")
    click.echo("=" * 140)
    click.echo(f"{'ID':<6} {'Severity':<10} {'Host':<18} {'Port':<6} {'Tool':<10} {'Title':<80}")
    click.echo("=" * 140)

    for finding in findings:
        sev_color = severity_colors.get(finding.get('severity', 'info'), 'white')
        click.echo(
            f"{finding['id']:<6} "
            f"{click.style(finding.get('severity', 'info').upper()[:9], fg=sev_color):<19} "
            f"{(finding.get('ip_address') or 'N/A')[:17]:<18} "
            f"{str(finding.get('port') or 'N/A')[:5]:<6} "
            f"{(finding.get('tool') or 'N/A')[:9]:<10} "
            f"{finding.get('title', '')[:79]:<80}"
        )

    click.echo("=" * 140)
    click.echo(f"Total: {len(findings)} findings\n")


@findings.command("show")
@click.argument("finding_id", type=int)
def findings_show(finding_id):
    """Show detailed finding information."""
    from menuscript.storage.findings import FindingsManager

    fm = FindingsManager()
    finding = fm.get_finding(finding_id)

    if not finding:
        click.echo(f"✗ Finding {finding_id} not found", err=True)
        return

    click.echo("\n" + "=" * 80)
    click.echo(f"FINDING #{finding['id']}")
    click.echo("=" * 80)
    click.echo(f"Severity:     {finding.get('severity', 'unknown').upper()}")
    click.echo(f"Type:         {finding.get('finding_type', 'N/A')}")
    click.echo(f"Tool:         {finding.get('tool', 'N/A')}")
    click.echo(f"Title:        {finding.get('title', 'N/A')}")
    click.echo(f"\nDescription:")
    click.echo(f"  {finding.get('description', 'N/A')}")

    if finding.get('path'):
        click.echo(f"\nPath:         {finding['path']}")

    if finding.get('port'):
        click.echo(f"Port:         {finding['port']}")

    if finding.get('refs'):
        click.echo(f"\nReference:    {finding['refs']}")

    click.echo(f"\nDiscovered:   {finding.get('created_at', 'N/A')}")
    click.echo("=" * 80 + "\n")


@findings.command("summary")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
def findings_summary(workspace):
    """Show findings summary by severity."""
    from menuscript.storage.findings import FindingsManager

    em = EngagementManager()

    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    fm = FindingsManager()
    summary = fm.get_findings_summary(eng['id'])

    total = sum(summary.values())

    click.echo("\n" + "=" * 60)
    click.echo(f"FINDINGS SUMMARY - Engagement: {eng['name']}")
    click.echo("=" * 60)
    click.echo(f"{'Severity':<15} {'Count':<10} {'Percentage':<15}")
    click.echo("=" * 60)

    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = summary.get(severity, 0)
        pct = (count / total * 100) if total > 0 else 0

        color = {
            'critical': 'red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'white'
        }.get(severity, 'white')

        click.echo(
            f"{click.style(severity.upper(), fg=color):<24} "
            f"{count:<10} "
            f"{pct:.1f}%"
        )

    click.echo("=" * 60)
    click.echo(f"{'TOTAL':<15} {total}")
    click.echo("=" * 60 + "\n")


# ==================== OSINT COMMANDS ====================

@cli.group()
def osint():
    """OSINT data management commands."""
    pass


@osint.command("list")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
@click.option("--type", "-t", default=None, help="Filter by data type (email, host, ip, url, asn)")
@click.option("--source", "-s", default=None, help="Filter by source tool")
def osint_list(engagement, type, source):
    """List all OSINT data in engagement."""
    from menuscript.storage.osint import OsintManager

    em = EngagementManager()

    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    om = OsintManager()
    osint_data = om.list_osint_data(eng['id'], data_type=type, source=source)

    if not osint_data:
        click.echo(f"No OSINT data found in workspace '{eng['name']}'")
        return

    click.echo("\n" + "=" * 120)
    click.echo(f"OSINT DATA - Engagement: {eng['name']}")
    if type:
        click.echo(f"Filtered by type: {type}")
    if source:
        click.echo(f"Filtered by source: {source}")
    click.echo("=" * 120)
    click.echo(f"{'ID':<6} {'Type':<12} {'Source':<15} {'Value':<70} {'Discovered':<20}")
    click.echo("=" * 120)

    for item in osint_data:
        click.echo(
            f"{item['id']:<6} "
            f"{(item.get('data_type') or 'N/A')[:11]:<12} "
            f"{(item.get('source') or 'N/A')[:14]:<15} "
            f"{item.get('value', '')[:69]:<70} "
            f"{item.get('created_at', 'N/A')[:19]:<20}"
        )

    click.echo("=" * 120)
    click.echo(f"Total: {len(osint_data)} entries\n")


@osint.command("summary")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
def osint_summary(workspace):
    """Show OSINT data summary by type."""
    from menuscript.storage.osint import OsintManager

    em = EngagementManager()

    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    om = OsintManager()
    summary = om.get_osint_summary(eng['id'])

    total = sum(summary.values())

    if total == 0:
        click.echo(f"No OSINT data found in workspace '{eng['name']}'")
        return

    click.echo("\n" + "=" * 60)
    click.echo(f"OSINT SUMMARY - Engagement: {eng['name']}")
    click.echo("=" * 60)
    click.echo(f"{'Type':<15} {'Count':<10} {'Percentage':<15}")
    click.echo("=" * 60)

    for data_type in sorted(summary.keys()):
        count = summary[data_type]
        pct = (count / total * 100) if total > 0 else 0

        click.echo(
            f"{data_type:<15} "
            f"{count:<10} "
            f"{pct:.1f}%"
        )

    click.echo("=" * 60)
    click.echo(f"{'TOTAL':<15} {total}")
    click.echo("=" * 60 + "\n")



# ==================== WEB PATHS COMMANDS ====================

@cli.group()
def paths():
    """Web paths/directories management commands."""
    pass


@paths.command("list")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
@click.option("--status", "-s", type=int, default=None, help="Filter by HTTP status code")
@click.option("--host", "-h", default=None, help="Filter by host IP or hostname")
def paths_list(engagement, status, host):
    """List discovered web paths."""
    from menuscript.storage.web_paths import WebPathsManager
    from menuscript.storage.hosts import HostManager

    em = EngagementManager()

    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    wpm = WebPathsManager()

    # Get host_id if filtering by host
    host_id = None
    if host:
        hm = HostManager()
        hosts = hm.list_hosts(eng['id'])
        for h in hosts:
            if h.get('hostname') == host or h.get('ip_address') == host:
                host_id = h['id']
                break
        if not host_id:
            click.echo(f"✗ Host {host} not found", err=True)
            return

    # List paths
    if host_id:
        paths = wpm.list_web_paths(host_id=host_id, status_code=status)
    else:
        paths = wpm.list_web_paths(engagement_id=eng['id'], status_code=status)

    if not paths:
        click.echo(f"No web paths found in workspace '{eng['name']}'")
        return

    click.echo("\n" + "=" * 140)
    click.echo(f"WEB PATHS - Engagement: {eng['name']}")
    if status:
        click.echo(f"Filtered by status: {status}")
    if host:
        click.echo(f"Filtered by host: {host}")
    click.echo("=" * 140)
    click.echo(f"{'ID':<6} {'Status':<8} {'Size':<10} {'Host':<25} {'URL':<80}")
    click.echo("=" * 140)

    for path in paths:
        status_code = path.get('status_code', 'N/A')
        # Color code status
        if status_code == 200:
            status_str = click.style(str(status_code), fg='green')
        elif 300 <= status_code < 400:
            status_str = click.style(str(status_code), fg='yellow')
        elif 400 <= status_code < 500:
            status_str = click.style(str(status_code), fg='red')
        else:
            status_str = str(status_code)

        host_info = path.get('hostname') or path.get('ip_address') or 'N/A'

        click.echo(
            f"{path['id']:<6} "
            f"{status_str:<17} "  # Extra space for ANSI codes
            f"{str(path.get('content_length') or 'N/A')[:9]:<10} "
            f"{host_info[:24]:<25} "
            f"{path.get('url', '')[:79]:<80}"
        )

    click.echo("=" * 140)
    click.echo(f"Total: {len(paths)} paths\n")


@paths.command("summary")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
def paths_summary(workspace):
    """Show web paths summary by status code."""
    from menuscript.storage.web_paths import WebPathsManager

    em = EngagementManager()

    if workspace:
        eng = em.get(workspace)
        if not eng:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    wpm = WebPathsManager()
    summary = wpm.get_paths_summary(eng['id'])

    total = sum(summary.values())

    if total == 0:
        click.echo(f"No web paths found in workspace '{eng['name']}'")
        return

    click.echo("\n" + "=" * 60)
    click.echo(f"WEB PATHS SUMMARY - Engagement: {eng['name']}")
    click.echo("=" * 60)
    click.echo(f"{'Status Code':<15} {'Count':<10} {'Percentage':<15}")
    click.echo("=" * 60)

    for status_code in sorted(summary.keys(), key=lambda x: int(x) if x.isdigit() else 999):
        count = summary[status_code]
        pct = (count / total * 100) if total > 0 else 0

        # Color code
        status_int = int(status_code) if status_code.isdigit() else 0
        if status_int == 200:
            status_display = click.style(status_code, fg='green')
        elif 300 <= status_int < 400:
            status_display = click.style(status_code, fg='yellow')
        elif 400 <= status_int < 500:
            status_display = click.style(status_code, fg='red')
        else:
            status_display = status_code

        click.echo(
            f"{status_display:<24} "  # Extra space for ANSI
            f"{count:<10} "
            f"{pct:.1f}%"
        )

    click.echo("=" * 60)
    click.echo(f"{'TOTAL':<15} {total}")
    click.echo("=" * 60 + "\n")


# ==================== CREDENTIALS COMMANDS ====================

@cli.group()
def creds():
    """Credentials management - similar to MSF's creds command."""
    pass


@creds.command("list")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
@click.option("--service", "-s", default=None, help="Filter by service (ssh, smb, mysql, etc.)")
@click.option("--status", "-t", default=None, help="Filter by status (valid, untested)")
@click.option("--host", "-h", default=None, help="Filter by host IP")
def creds_list(engagement, service, status, host):
    """List all discovered credentials (similar to MSF's creds command)."""
    from menuscript.storage.credentials import CredentialsManager
    from menuscript.storage.hosts import HostManager

    em = EngagementManager()

    if engagement:
        eng = em.get(engagement)
        if not eng:
            click.echo(f"✗ Workspace '{engagement}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    cm = CredentialsManager()

    # Get host_id if filtering by host
    host_id = None
    if host:
        hm = HostManager()
        host_obj = hm.get_host_by_ip(eng['id'], host)
        if not host_obj:
            click.echo(f"✗ Host {host} not found", err=True)
            return
        host_id = host_obj['id']

    creds = cm.list_credentials(eng['id'], host_id=host_id, service=service, status=status)

    if not creds:
        filter_msg = ""
        if service:
            filter_msg += f" (service={service})"
        if status:
            filter_msg += f" (status={status})"
        click.echo(f"No credentials found in workspace '{eng['name']}'{filter_msg}")
        return

    # Get stats
    stats = cm.get_stats(eng['id'])

    click.echo("\n" + "=" * 100)
    click.echo(f"CREDENTIALS - Engagement: {eng['name']}")
    if service or status or host:
        filters = []
        if service:
            filters.append(f"service={service}")
        if status:
            filters.append(f"status={status}")
        if host:
            filters.append(f"host={host}")
        click.echo(f"Filters: {', '.join(filters)}")
    click.echo("=" * 100)

    # Summary line
    click.echo(f"Total: {stats['total']}  |  " +
               click.style(f"Valid: {stats['valid']}", fg='green', bold=True) +
               f"  |  Usernames: {stats['users_only']}  |  Pairs: {stats['pairs']}")
    click.echo()

    # Separate valid and untested
    valid_creds = [c for c in creds if c.get('status') == 'valid']
    untested_creds = [c for c in creds if c.get('status') != 'valid']

    # Show valid credentials
    if valid_creds:
        click.echo(click.style("VALID CREDENTIALS (Confirmed Working)", bold=True, fg='green'))
        click.echo("─" * 100)
        click.echo(f"{'Username':<20} {'Password':<20} {'Service':<10} {'Host':<18} {'Port':<6} {'Tool':<15}")
        click.echo("─" * 100)

        for cred in valid_creds:
            username = cred.get('username', '')[:19]
            password = cred.get('password', '')[:19]
            service_name = cred.get('service', 'N/A')[:9]
            ip = cred.get('ip_address', 'N/A')[:17]
            port = str(cred.get('port', 'N/A'))[:5]
            tool_name = cred.get('tool', 'N/A')[:14]

            click.echo(
                click.style("✓", fg='green', bold=True) + " " +
                click.style(f"{username:<20} {password:<20}", fg='green', bold=True) +
                f"{service_name:<10} {ip:<18} {port:<6} {tool_name:<15}"
            )

        click.echo("─" * 100)
        click.echo()

    # Show discovered usernames
    if untested_creds:
        click.echo(click.style(f"DISCOVERED USERNAMES ({len(untested_creds)} untested)", bold=True, fg='cyan'))
        click.echo("─" * 80)

        # Group by service
        by_service = {}
        for cred in untested_creds:
            svc = cred.get('service', 'unknown')
            if svc not in by_service:
                by_service[svc] = []
            by_service[svc].append(cred.get('username', ''))

        for svc, usernames in sorted(by_service.items()):
            user_list = ', '.join(sorted(usernames))
            click.echo(f"{svc.upper():<8} ({len(usernames):2}): {user_list}")

        click.echo("─" * 80)

    click.echo(f"\nTotal displayed: {len(creds)} credentials\n")


@creds.command("stats")
@click.option("--engagement", "-w", default=None, help="Engagement name (default: current)")
def creds_stats(engagement):
    """Show credentials statistics."""
    from menuscript.storage.credentials import CredentialsManager

    em = EngagementManager()

    if engagement:
        eng = em.get(engagement)
        if not eng:
            click.echo(f"✗ Workspace '{engagement}' not found", err=True)
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo("✗ No engagement selected", err=True)
            return

    cm = CredentialsManager()
    stats = cm.get_stats(eng['id'])

    click.echo("\n" + "=" * 60)
    click.echo(f"CREDENTIALS STATISTICS - Engagement: {eng['name']}")
    click.echo("=" * 60)
    click.echo(f"Total Credentials:       {stats['total']}")
    click.echo(f"Valid (confirmed):       {click.style(str(stats['valid']), fg='green')}")
    click.echo(f"Username-only:           {stats['users_only']}")
    click.echo(f"Password-only:           {stats['passwords_only']}")
    click.echo(f"Username:Password pairs: {stats['pairs']}")
    click.echo("=" * 60 + "\n")


@cli.group()
def report():
    """Generate penetration test reports in various formats."""
    pass


@report.command("generate")
@click.option("--format", "-f", type=click.Choice(['markdown', 'html', 'json'], case_sensitive=False), default='html', help="Report format")
@click.option("--output", "-o", type=str, help="Output file path (default: reports/<engagement>_<timestamp>.<ext>)")
@click.option("--engagement", "-e", type=int, help="Engagement ID (default: current engagement)")
def report_generate(format, output, engagement):
    """Generate a penetration test report."""
    from menuscript.reporting.generator import ReportGenerator
    from menuscript.storage.engagements import EngagementManager
    import datetime

    # Get engagement
    em = EngagementManager()

    if engagement:
        eng = em.get_by_id(engagement)
        if not eng:
            click.echo(click.style(f"✗ Engagement {engagement} not found", fg='red'))
            return
    else:
        eng = em.get_current()
        if not eng:
            click.echo(click.style("✗ No current engagement. Use 'menuscript engagement list' to see available engagements.", fg='red'))
            return

    engagement_id = eng['id']
    engagement_name = eng['name']

    click.echo(f"Generating {format.upper()} report for engagement: {click.style(engagement_name, fg='cyan', bold=True)}")

    # Generate output filename if not specified
    if not output:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = engagement_name.replace(' ', '_').replace('/', '_')
        ext = format if format != 'markdown' else 'md'
        output = f"reports/{safe_name}_{timestamp}.{ext}"

    try:
        # Create report generator
        rg = ReportGenerator(engagement_id)

        # Generate report based on format
        if format == 'markdown':
            report_text = rg.generate_markdown(output)
        elif format == 'html':
            report_text = rg.generate_html(output)
        elif format == 'json':
            report_text = rg.generate_json(output)

        click.echo(click.style(f"✓ Report generated successfully!", fg='green'))
        click.echo(f"  File: {output}")
        click.echo(f"  Size: {len(report_text)} bytes")

        # Show summary
        data = rg.collect_data()
        click.echo(f"\nReport Summary:")
        click.echo(f"  Hosts: {len(data['hosts'])}")
        click.echo(f"  Findings: {len(data['findings'])}")
        click.echo(f"  Credentials: {len(data['credentials'])}")

    except Exception as e:
        click.echo(click.style(f"✗ Error generating report: {e}", fg='red'))
        import traceback
        traceback.print_exc()


@report.command("list")
def report_list():
    """List generated reports."""
    import os
    reports_dir = Path("reports")

    if not reports_dir.exists():
        click.echo("No reports directory found.")
        return

    reports = sorted(reports_dir.glob("*.*"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not reports:
        click.echo("No reports found.")
        return

    click.echo("\n" + "=" * 70)
    click.echo("GENERATED REPORTS")
    click.echo("=" * 70)

    for rpt in reports:
        size = rpt.stat().st_size
        mtime = datetime.datetime.fromtimestamp(rpt.stat().st_mtime)
        click.echo(f"{rpt.name}")
        click.echo(f"  Size: {size:,} bytes | Modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')}")

    click.echo("=" * 70 + "\n")


# ============================================================================
# Import Commands
# ============================================================================

@cli.group()
def import_data():
    """Import data from external sources."""
    pass


@import_data.command("msf")
@click.argument('xml_file', type=click.Path(exists=True))
@click.option('-v', '--verbose', is_flag=True, help='Show detailed import progress')
def import_msf(xml_file, verbose):
    """
    Import data from Metasploit Framework XML export.

    Export from MSF console:
        db_export -f xml /path/to/export.xml

    Example:
        menuscript import-data msf /path/to/msf_export.xml
    """
    from menuscript.importers.msf_importer import MSFImporter

    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("✗ No engagement selected! Use 'menuscript engagement use <name>'", fg='red'))
        return

    engagement_id = current_ws['id']
    engagement_name = current_ws['name']

    click.echo(click.style(f"\n🔄 Importing Metasploit data into engagement: {engagement_name}", fg='cyan', bold=True))
    click.echo()

    importer = MSFImporter(engagement_id)

    try:
        stats = importer.import_xml(xml_file, verbose=verbose)

        click.echo()
        click.echo(click.style("✓ Import completed successfully!", fg='green', bold=True))
        click.echo()
        click.echo("Import Summary:")
        click.echo(f"  • Hosts:           {stats['hosts']}")
        click.echo(f"  • Services:        {stats['services']}")
        click.echo(f"  • Credentials:     {stats['credentials']}")
        click.echo(f"  • Vulnerabilities: {stats['vulnerabilities']}")

        if stats['skipped'] > 0:
            click.echo(f"  • Skipped:         {stats['skipped']}")

        click.echo()
        click.echo(click.style("💡 TIP:", fg='yellow', bold=True) + " View imported data with:")
        click.echo("  • menuscript dashboard")
        click.echo("  • menuscript interactive")
        click.echo("  • menuscript report generate")
        click.echo()

    except Exception as e:
        click.echo(click.style(f"\n✗ Import failed: {e}", fg='red'))
        if verbose:
            import traceback
            traceback.print_exc()
        return
