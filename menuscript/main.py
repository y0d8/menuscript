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
except ImportError as e:
    click.echo(f"Import error: {e}", err=True)
    sys.exit(1)


@click.group()
@click.version_option(version='0.4.0')
def cli():
    """menuscript - Recon Suite for Penetration Testing"""
    pass


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
