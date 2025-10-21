#!/usr/bin/env python3
"""
menuscript.main - CLI entry point
"""
import click
import os
import sys
from pathlib import Path

try:
    from menuscript.engine.background import enqueue_job, list_jobs, get_job, start_worker, worker_loop
    from menuscript.storage.workspaces import WorkspaceManager
    from menuscript.ui.interactive import run_interactive_menu
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


@cli.group()
def workspace():
    """Workspace management (like msf workspaces)."""
    pass


@workspace.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Workspace description")
def workspace_create(name, description):
    """Create a new workspace."""
    wm = WorkspaceManager()
    try:
        ws_id = wm.create(name, description)
        click.echo(f"✓ Created workspace '{name}' (id={ws_id})")
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@workspace.command("list")
def workspace_list():
    """List all workspaces."""
    wm = WorkspaceManager()
    workspaces = wm.list()
    current = wm.get_current()
    
    if not workspaces:
        click.echo("No workspaces found. Create one with: menuscript workspace create <name>")
        return
    
    click.echo("\n" + "=" * 80)
    click.echo("WORKSPACES")
    click.echo("=" * 80)
    
    for ws in workspaces:
        marker = "* " if current and ws['id'] == current['id'] else "  "
        stats = wm.stats(ws['id'])
        click.echo(f"{marker}{ws['name']:<20} | Hosts: {stats['hosts']:>3} | Services: {stats['services']:>3} | Findings: {stats['findings']:>3}")
        if ws.get('description'):
            click.echo(f"  └─ {ws['description']}")
    
    click.echo("=" * 80)
    if current:
        click.echo(f"Current: {current['name']}")
    click.echo()


@workspace.command("use")
@click.argument("name")
def workspace_use(name):
    """Switch to a workspace."""
    wm = WorkspaceManager()
    if wm.set_current(name):
        click.echo(f"✓ Switched to workspace '{name}'")
    else:
        click.echo(f"✗ Workspace '{name}' not found", err=True)
        click.echo("Available workspaces:")
        for ws in wm.list():
            click.echo(f"  - {ws['name']}")


@workspace.command("current")
def workspace_current():
    """Show current workspace."""
    wm = WorkspaceManager()
    current = wm.get_current()
    
    if not current:
        click.echo("No workspace selected")
        return
    
    stats = wm.stats(current['id'])
    
    click.echo("\n" + "=" * 60)
    click.echo(f"Current Workspace: {current['name']}")
    click.echo("=" * 60)
    click.echo(f"Description: {current.get('description', 'N/A')}")
    click.echo(f"Created: {current.get('created_at', 'N/A')}")
    click.echo()
    click.echo("Statistics:")
    click.echo(f"  Hosts:     {stats['hosts']}")
    click.echo(f"  Services:  {stats['services']}")
    click.echo(f"  Findings:  {stats['findings']}")
    click.echo("=" * 60 + "\n")


@workspace.command("delete")
@click.argument("name")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
def workspace_delete(name, force):
    """Delete a workspace and all its data."""
    wm = WorkspaceManager()
    ws = wm.get(name)
    
    if not ws:
        click.echo(f"✗ Workspace '{name}' not found", err=True)
        return
    
    if not force:
        stats = wm.stats(ws['id'])
        click.echo(f"\nWarning: This will delete workspace '{name}' and:")
        click.echo(f"  - {stats['hosts']} hosts")
        click.echo(f"  - {stats['services']} services")
        click.echo(f"  - {stats['findings']} findings")
        
        if not click.confirm("\nAre you sure?"):
            click.echo("Cancelled")
            return
    
    if wm.delete(name):
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
        click.echo(
            f"{job['id']:<5} "
            f"{job.get('tool', 'N/A'):<12} "
            f"{job.get('target', 'N/A')[:24]:<25} "
            f"{job.get('status', 'N/A'):<10} "
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
def hosts_list(workspace):
    """List all hosts in workspace."""
    from menuscript.storage.hosts import HostManager
    
    wm = WorkspaceManager()
    
    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected. Use: menuscript workspace use <name>", err=True)
            return
    
    hm = HostManager()
    hosts = hm.list_hosts(ws['id'])
    
    if not hosts:
        click.echo(f"No hosts found in workspace '{ws['name']}'")
        return
    
    click.echo("\n" + "=" * 100)
    click.echo(f"HOSTS - Workspace: {ws['name']}")
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
def hosts_show(ip_address, workspace):
    """Show detailed host information."""
    from menuscript.storage.hosts import HostManager
    
    wm = WorkspaceManager()
    
    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return
    
    hm = HostManager()
    host = hm.get_host_by_ip(ws['id'], ip_address)
    
    if not host:
        click.echo(f"✗ Host {ip_address} not found in workspace '{ws['name']}'", err=True)
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
@click.option("--port", "-p", type=int, default=None, help="Filter by port")
def services_list(workspace, port):
    """List all services across all hosts."""
    from menuscript.storage.hosts import HostManager
    
    wm = WorkspaceManager()
    
    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return
    
    hm = HostManager()
    
    # Get all hosts and their services
    hosts = hm.list_hosts(ws['id'])
    
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
        click.echo(f"No services found in workspace '{ws['name']}'")
        return
    
    click.echo("\n" + "=" * 120)
    click.echo(f"SERVICES - Workspace: {ws['name']}")
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
@click.option("--severity", "-s", default=None, help="Filter by severity (critical, high, medium, low, info)")
@click.option("--tool", "-t", default=None, help="Filter by tool")
@click.option("--host", "-h", default=None, help="Filter by host IP")
def findings_list(workspace, severity, tool, host):
    """List all findings in workspace."""
    from menuscript.storage.findings import FindingsManager

    wm = WorkspaceManager()

    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return

    fm = FindingsManager()

    # Get host_id if filtering by host
    host_id = None
    if host:
        from menuscript.storage.hosts import HostManager
        hm = HostManager()
        host_obj = hm.get_host_by_ip(ws['id'], host)
        if not host_obj:
            click.echo(f"✗ Host {host} not found", err=True)
            return
        host_id = host_obj['id']

    findings = fm.list_findings(ws['id'], host_id=host_id, severity=severity, tool=tool)

    if not findings:
        click.echo(f"No findings found in workspace '{ws['name']}'")
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
    click.echo(f"FINDINGS - Workspace: {ws['name']}")
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
def findings_summary(workspace):
    """Show findings summary by severity."""
    from menuscript.storage.findings import FindingsManager

    wm = WorkspaceManager()

    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return

    fm = FindingsManager()
    summary = fm.get_findings_summary(ws['id'])

    total = sum(summary.values())

    click.echo("\n" + "=" * 60)
    click.echo(f"FINDINGS SUMMARY - Workspace: {ws['name']}")
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
@click.option("--type", "-t", default=None, help="Filter by data type (email, host, ip, url, asn)")
@click.option("--source", "-s", default=None, help="Filter by source tool")
def osint_list(workspace, type, source):
    """List all OSINT data in workspace."""
    from menuscript.storage.osint import OsintManager

    wm = WorkspaceManager()

    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return

    om = OsintManager()
    osint_data = om.list_osint_data(ws['id'], data_type=type, source=source)

    if not osint_data:
        click.echo(f"No OSINT data found in workspace '{ws['name']}'")
        return

    click.echo("\n" + "=" * 120)
    click.echo(f"OSINT DATA - Workspace: {ws['name']}")
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
def osint_summary(workspace):
    """Show OSINT data summary by type."""
    from menuscript.storage.osint import OsintManager

    wm = WorkspaceManager()

    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return

    om = OsintManager()
    summary = om.get_osint_summary(ws['id'])

    total = sum(summary.values())

    if total == 0:
        click.echo(f"No OSINT data found in workspace '{ws['name']}'")
        return

    click.echo("\n" + "=" * 60)
    click.echo(f"OSINT SUMMARY - Workspace: {ws['name']}")
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
@click.option("--status", "-s", type=int, default=None, help="Filter by HTTP status code")
@click.option("--host", "-h", default=None, help="Filter by host IP or hostname")
def paths_list(workspace, status, host):
    """List discovered web paths."""
    from menuscript.storage.web_paths import WebPathsManager
    from menuscript.storage.hosts import HostManager

    wm = WorkspaceManager()

    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return

    wpm = WebPathsManager()

    # Get host_id if filtering by host
    host_id = None
    if host:
        hm = HostManager()
        hosts = hm.list_hosts(ws['id'])
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
        paths = wpm.list_web_paths(workspace_id=ws['id'], status_code=status)

    if not paths:
        click.echo(f"No web paths found in workspace '{ws['name']}'")
        return

    click.echo("\n" + "=" * 140)
    click.echo(f"WEB PATHS - Workspace: {ws['name']}")
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
@click.option("--workspace", "-w", default=None, help="Workspace name (default: current)")
def paths_summary(workspace):
    """Show web paths summary by status code."""
    from menuscript.storage.web_paths import WebPathsManager

    wm = WorkspaceManager()

    if workspace:
        ws = wm.get(workspace)
        if not ws:
            click.echo(f"✗ Workspace '{workspace}' not found", err=True)
            return
    else:
        ws = wm.get_current()
        if not ws:
            click.echo("✗ No workspace selected", err=True)
            return

    wpm = WebPathsManager()
    summary = wpm.get_paths_summary(ws['id'])

    total = sum(summary.values())

    if total == 0:
        click.echo(f"No web paths found in workspace '{ws['name']}'")
        return

    click.echo("\n" + "=" * 60)
    click.echo(f"WEB PATHS SUMMARY - Workspace: {ws['name']}")
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
