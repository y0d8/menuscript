#!/usr/bin/env python3
"""
menuscript.ui.interactive - Interactive menu system for tool selection
"""
import click
import os
from typing import Dict, Any, Optional, List
from menuscript.engine.loader import discover_plugins
from menuscript.engine.background import enqueue_job, list_jobs, get_job
from menuscript.storage.workspaces import WorkspaceManager
from menuscript.storage.hosts import HostManager
from menuscript.storage.findings import FindingsManager
from menuscript.storage.osint import OsintManager
from menuscript.storage.web_paths import WebPathsManager


def show_main_menu() -> Optional[Dict[str, Any]]:
    """Show main menu and return action."""
    plugins = discover_plugins()

    if not plugins:
        click.echo("No plugins found!")
        return None

    # Group plugins by category
    by_category = {}
    for name, plugin in plugins.items():
        cat = getattr(plugin, 'category', 'other')
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append((name, plugin))

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("MENUSCRIPT - Interactive Menu")
    click.echo("=" * 70 + "\n")

    # Show current workspace with stats
    wm = WorkspaceManager()
    current_ws = wm.get_current()
    if current_ws:
        stats = wm.stats(current_ws['id'])
        click.echo(f"Workspace: {current_ws['name']}")
        click.echo(f"Data: {stats['hosts']} hosts | {stats['services']} services | {stats['findings']} findings\n")
    else:
        click.echo(click.style("⚠ No workspace selected! Use 'menuscript workspace use <name>'", fg='yellow'))
        click.echo()

    # Menu options
    click.echo(click.style("LAUNCH TOOLS", bold=True, fg='green'))
    click.echo("-" * 70)

    # Display tools by category
    tool_list = []
    idx = 1

    for category in sorted(by_category.keys()):
        click.echo(click.style(f"  {category.upper()}", fg='cyan'))

        for name, plugin in sorted(by_category[category], key=lambda x: x[0]):
            help_info = getattr(plugin, 'HELP', {})
            desc = help_info.get('description', 'No description')[:40]

            click.echo(f"    {idx:2}. {name}")
            tool_list.append(('launch_tool', name))
            idx += 1

    click.echo()

    # View options
    click.echo(click.style("VIEW DATA", bold=True, fg='blue'))
    click.echo("-" * 70)

    dashboard_option = idx
    click.echo(f"  {idx:2}. Live Dashboard")
    idx += 1

    job_option = idx
    click.echo(f"  {idx:2}. View Jobs")
    idx += 1

    results_option = idx
    click.echo(f"  {idx:2}. View Scan Results")
    idx += 1

    click.echo()
    click.echo(f"   0. Exit")
    click.echo()

    # Get user selection
    try:
        choice = click.prompt("Select an option", type=int, default=0)

        if choice == 0:
            return None

        if choice == dashboard_option:
            return {'action': 'view_dashboard'}

        if choice == job_option:
            return {'action': 'view_jobs'}

        if choice == results_option:
            return {'action': 'view_results'}

        if 1 <= choice <= len(tool_list):
            action_type, tool_name = tool_list[choice - 1]
            return {'action': action_type, 'tool': tool_name}
        else:
            click.echo(click.style("Invalid selection!", fg='red'))
            click.pause()
            return {'action': 'retry'}

    except (KeyboardInterrupt, click.Abort):
        click.echo("\nExiting...")
        return None


def show_tool_menu(tool_name: str) -> Optional[Dict[str, Any]]:
    """Show tool configuration menu and return job parameters."""
    plugins = discover_plugins()
    plugin = plugins.get(tool_name)

    if not plugin:
        click.echo(f"Plugin {tool_name} not found!")
        return None

    help_info = getattr(plugin, 'HELP', {})
    presets = help_info.get('presets', [])
    flags = help_info.get('flags', [])

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo(f"{help_info.get('name', tool_name)}")
    click.echo("=" * 70)
    click.echo(f"{help_info.get('description', '')}\n")

    # Show presets if available
    if presets:
        click.echo(click.style("PRESETS:", bold=True, fg='green'))
        for i, preset in enumerate(presets, 1):
            click.echo(f"  {i}. {preset['name']:<20} - {preset['desc']}")
            click.echo(f"     Args: {' '.join(preset['args'])}")
        click.echo()

    # Show common flags
    if flags:
        click.echo(click.style("COMMON FLAGS:", bold=True, fg='yellow'))
        for flag, desc in flags[:8]:  # Show first 8 flags
            click.echo(f"  {flag:<20} - {desc}")
        if len(flags) > 8:
            click.echo(f"  ... and {len(flags) - 8} more")
        click.echo()

    # Show examples
    examples = help_info.get('examples', [])
    if examples:
        click.echo(click.style("EXAMPLES:", bold=True, fg='blue'))
        for ex in examples[:3]:  # Show first 3 examples
            click.echo(f"  {ex}")
        click.echo()

    click.echo("-" * 70)

    # Get target
    target = click.prompt("\nTarget (IP, hostname, URL, or CIDR)", type=str)

    if not target or target.strip() == "":
        click.echo(click.style("Target required!", fg='red'))
        return None

    target = target.strip()

    # Get preset or custom args
    args = []
    selected_preset_name = None

    if presets:
        click.echo("\nSelect preset or enter custom args:")
        for i, preset in enumerate(presets, 1):
            click.echo(f"  {i}. {preset['name']}")
        click.echo(f"  {len(presets) + 1}. Custom args")

        try:
            choice = click.prompt("Choice", type=int, default=1)

            if 1 <= choice <= len(presets):
                selected_preset = presets[choice - 1]
                args = selected_preset['args']
                selected_preset_name = selected_preset['name']
                click.echo(f"Using preset: {selected_preset['name']}")
            else:
                # Custom args
                custom = click.prompt("Enter custom arguments (space-separated)", default="", type=str)
                if custom:
                    args = custom.split()
        except (KeyboardInterrupt, click.Abort):
            return None
    else:
        # No presets, just ask for custom args
        custom = click.prompt("Enter arguments (space-separated, or press Enter for defaults)", default="", type=str)
        if custom:
            args = custom.split()

    # Special handling for MSF login modules - prompt for credentials
    if tool_name == 'msf_auxiliary' and args:
        module_path = args[0] if args else ""
        is_login_module = any(x in module_path.lower() for x in ['_login', 'brute'])

        if is_login_module:
            click.echo()
            click.echo(click.style("=== Credential Configuration ===", bold=True, fg='yellow'))
            click.echo("Configure authentication options for this login module:\n")

            # Ask about credential options
            cred_mode = click.prompt(
                "Credential mode",
                type=click.Choice(['single', 'wordlist', 'userpass_file', 'skip'], case_sensitive=False),
                default='skip',
                show_choices=True
            )

            if cred_mode == 'single':
                # Single username/password
                username = click.prompt("USERNAME", default="", type=str)
                if username:
                    args.append(f"USERNAME={username}")

                password = click.prompt("PASSWORD", default="", type=str)
                if password:
                    args.append(f"PASSWORD={password}")

            elif cred_mode == 'wordlist':
                # Separate user and password files
                user_file = click.prompt("USER_FILE (path to username list)", default="", type=str)
                if user_file:
                    args.append(f"USER_FILE={user_file}")

                pass_file = click.prompt("PASS_FILE (path to password list)", default="", type=str)
                if pass_file:
                    args.append(f"PASS_FILE={pass_file}")

            elif cred_mode == 'userpass_file':
                # Combined username:password file
                userpass_file = click.prompt("USERPASS_FILE (path to user:pass list)", default="", type=str)
                if userpass_file:
                    args.append(f"USERPASS_FILE={userpass_file}")

            # Additional options
            if cred_mode != 'skip':
                click.echo()
                if click.confirm("Try username as password (USER_AS_PASS)?", default=False):
                    args.append("USER_AS_PASS=true")

                if click.confirm("Try blank passwords?", default=False):
                    args.append("BLANK_PASSWORDS=true")

                if click.confirm("Stop on first success?", default=True):
                    args.append("STOP_ON_SUCCESS=true")

                # Ask about threads
                threads = click.prompt("Number of threads (THREADS)", default=1, type=int)
                if threads > 1:
                    args.append(f"THREADS={threads}")

    # Optional label
    label = click.prompt("Job label (optional)", default="", type=str)

    return {
        'tool': tool_name,
        'target': target,
        'args': args,
        'label': label
    }


def launch_job(job_params: Dict[str, Any]) -> bool:
    """Launch a job with the given parameters."""
    try:
        job_id = enqueue_job(
            tool=job_params['tool'],
            target=job_params['target'],
            args=job_params.get('args', []),
            label=job_params.get('label', '')
        )

        click.echo()
        click.echo(click.style("✓ Job enqueued successfully!", fg='green', bold=True))
        click.echo(f"Job ID: {job_id}")
        click.echo(f"Tool: {job_params['tool']}")
        click.echo(f"Target: {job_params['target']}")
        if job_params.get('args'):
            click.echo(f"Args: {' '.join(job_params['args'])}")

        click.echo("\nTip: Check job status with: menuscript jobs list")
        click.echo("      View job output with: menuscript jobs show <id>")

        return True

    except Exception as e:
        click.echo(click.style(f"✗ Error enqueueing job: {e}", fg='red'))
        return False


def view_jobs_menu():
    """Show jobs list and allow viewing details."""
    while True:
        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo("JOB QUEUE")
        click.echo("=" * 70 + "\n")

        jobs = list_jobs(limit=20)

        if not jobs:
            click.echo("No jobs found.")
            click.echo()
            click.pause("Press any key to return to main menu...")
            return

        # Display jobs table
        click.echo(f"{'ID':<5} {'Status':<10} {'Tool':<12} {'Target':<25} {'Created':<20}")
        click.echo("-" * 70)

        for job in jobs:
            jid = job.get('id', '?')
            status = job.get('status', 'unknown')
            tool = job.get('tool', 'unknown')
            target = job.get('target', '')[:25]
            created = job.get('created_at', '')[:19]

            # Color code status
            if status == 'done':
                status_str = click.style(status, fg='green')
            elif status == 'running':
                status_str = click.style(status, fg='yellow')
            elif status == 'failed':
                status_str = click.style(status, fg='red')
            else:
                status_str = status

            click.echo(f"{jid:<5} {status_str:<10} {tool:<12} {target:<25} {created:<20}")

        click.echo()
        click.echo("Enter job ID to view details, or 0 to return")

        try:
            choice = click.prompt("Job ID", type=int, default=0)

            if choice == 0:
                return

            # Show job details
            view_job_detail(choice)

        except (KeyboardInterrupt, click.Abort):
            return


def view_job_detail(job_id: int):
    """Show detailed information about a specific job."""
    job = get_job(job_id)

    if not job:
        click.echo(click.style(f"Job {job_id} not found!", fg='red'))
        click.pause()
        return

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo(f"JOB #{job_id} DETAILS")
    click.echo("=" * 70 + "\n")

    # Job info
    click.echo(f"Tool:    {job.get('tool', 'unknown')}")
    click.echo(f"Target:  {job.get('target', 'N/A')}")
    click.echo(f"Status:  {job.get('status', 'unknown')}")
    click.echo(f"Created: {job.get('created_at', 'N/A')}")

    if job.get('args'):
        click.echo(f"Args:    {' '.join(job['args'])}")

    if job.get('label'):
        click.echo(f"Label:   {job['label']}")

    if job.get('pid'):
        click.echo(f"PID:     {job['pid']}")

    click.echo()

    # Show log file if exists
    log_path = job.get('log')
    if log_path and os.path.exists(log_path):
        click.echo(click.style("LOG OUTPUT:", bold=True, fg='cyan'))
        click.echo("-" * 70)

        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            # Show last 50 lines
            lines = content.split('\n')
            if len(lines) > 50:
                click.echo(f"... (showing last 50 of {len(lines)} lines)\n")
                lines = lines[-50:]

            for line in lines:
                click.echo(line)

        except Exception as e:
            click.echo(click.style(f"Error reading log: {e}", fg='red'))
    else:
        click.echo(click.style("No log file available", fg='yellow'))

    click.echo()
    click.pause("Press any key to return...")


def view_results_menu():
    """Show scan results menu."""
    wm = WorkspaceManager()
    current_ws = wm.get_current()

    if not current_ws:
        click.echo(click.style("No workspace selected!", fg='red'))
        click.pause()
        return

    workspace_id = current_ws['id']

    while True:
        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo(f"SCAN RESULTS - Workspace: {current_ws['name']}")
        click.echo("=" * 70 + "\n")

        stats = wm.stats(workspace_id)

        click.echo("  1. Hosts        ({:3} total)".format(stats['hosts']))
        click.echo("  2. Services     ({:3} total)".format(stats['services']))
        click.echo("  3. Findings     ({:3} total)".format(stats['findings']))

        # Get OSINT and paths counts
        try:
            om = OsintManager()
            osint_count = len(om.list_osint_data(workspace_id))
        except:
            osint_count = 0

        try:
            wpm = WebPathsManager()
            # Count all paths across all hosts
            paths_count = 0
            hm = HostManager()
            for host in hm.list_hosts(workspace_id):
                paths_count += len(wpm.list_paths(host['id']))
        except:
            paths_count = 0

        click.echo("  4. OSINT Data   ({:3} total)".format(osint_count))
        click.echo("  5. Web Paths    ({:3} total)".format(paths_count))
        click.echo()
        click.echo("  0. Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select data type", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                view_hosts(workspace_id)
            elif choice == 2:
                view_services(workspace_id)
            elif choice == 3:
                view_findings(workspace_id)
            elif choice == 4:
                view_osint(workspace_id)
            elif choice == 5:
                view_web_paths(workspace_id)
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def view_hosts(workspace_id: int):
    """Display hosts in workspace."""
    hm = HostManager()
    all_hosts = hm.list_hosts(workspace_id)

    # Filter to only show 'up' hosts
    hosts = [h for h in all_hosts if h.get('status') == 'up']

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("HOSTS (live only)")
    click.echo("=" * 70 + "\n")

    if not hosts:
        click.echo("No live hosts found.")
    else:
        click.echo(f"{'ID':<5} {'IP Address':<18} {'Hostname':<25} {'Status':<10}")
        click.echo("-" * 70)

        for host in hosts:
            hid = host.get('id', '?')
            ip = host.get('ip_address', 'N/A')
            hostname = (host.get('hostname') or '')[:25] or '-'
            status = host.get('status', 'unknown')

            # Get service count
            services = hm.get_host_services(hid)
            svc_count = len(services)

            click.echo(f"{hid:<5} {ip:<18} {hostname:<25} {status:<10} ({svc_count} services)")

    click.echo(f"\nTotal: {len(hosts)} live host{'s' if len(hosts) != 1 else ''}")
    click.echo()
    click.pause("Press any key to return...")


def view_services(workspace_id: int):
    """Display services in workspace."""
    hm = HostManager()

    # Get all hosts and their services
    hosts = hm.list_hosts(workspace_id)
    all_services = []

    for host in hosts:
        services = hm.get_host_services(host['id'])
        for svc in services:
            all_services.append({
                'host_ip': host['ip_address'],
                **svc
            })

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("SERVICES")
    click.echo("=" * 70 + "\n")

    if not all_services:
        click.echo("No services found.")
    else:
        click.echo(f"{'Host IP':<18} {'Port':<7} {'Protocol':<10} {'Service':<15} {'Version':<25}")
        click.echo("-" * 70)

        for svc in all_services[:50]:  # Limit to 50
            host_ip = svc.get('host_ip', 'N/A')
            port = svc.get('port', '?')
            protocol = svc.get('protocol', 'tcp')
            service = (svc.get('service_name') or 'unknown')[:15]
            version = (svc.get('service_version') or '')[:25] or '-'

            click.echo(f"{host_ip:<18} {port:<7} {protocol:<10} {service:<15} {version:<25}")

        if len(all_services) > 50:
            click.echo(f"\n... and {len(all_services) - 50} more")

    click.echo()
    click.pause("Press any key to return...")


def view_findings(workspace_id: int):
    """Display findings in workspace."""
    fm = FindingsManager()
    findings = fm.list_findings(workspace_id)

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("FINDINGS")
    click.echo("=" * 70 + "\n")

    if not findings:
        click.echo("No findings found.")
    else:
        # Show summary
        by_severity = {}
        for f in findings:
            sev = f.get('severity', 'info')
            by_severity[sev] = by_severity.get(sev, 0) + 1

        click.echo("Summary by severity:")
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in by_severity:
                count = by_severity[sev]
                color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue',
                    'info': 'white'
                }.get(sev, 'white')

                click.echo(f"  {sev.capitalize():<10}: {click.style(str(count), fg=color)}")

        click.echo()
        click.echo(f"{'ID':<5} {'Severity':<10} {'Type':<20} {'Title':<40}")
        click.echo("-" * 70)

        for finding in findings[:30]:  # Limit to 30
            fid = finding.get('id', '?')
            sev = finding.get('severity', 'info')
            ftype = (finding.get('finding_type') or 'unknown')[:20]
            title = (finding.get('title') or 'No title')[:40]

            # Color code severity
            color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'blue',
                'info': 'white'
            }.get(sev, 'white')

            sev_colored = click.style(sev, fg=color)

            click.echo(f"{fid:<5} {sev_colored:<10} {ftype:<20} {title:<40}")

        if len(findings) > 30:
            click.echo(f"\n... and {len(findings) - 30} more")

    click.echo()
    click.pause("Press any key to return...")


def view_osint(workspace_id: int):
    """Display OSINT data in workspace."""
    om = OsintManager()
    data = om.list_osint_data(workspace_id)

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("OSINT DATA")
    click.echo("=" * 70 + "\n")

    if not data:
        click.echo("No OSINT data found.")
    else:
        # Group by type
        by_type = {}
        for item in data:
            dtype = item.get('data_type', 'unknown')
            if dtype not in by_type:
                by_type[dtype] = []
            by_type[dtype].append(item)

        for dtype in sorted(by_type.keys()):
            items = by_type[dtype]
            click.echo(click.style(f"{dtype.upper()} ({len(items)})", bold=True, fg='cyan'))
            click.echo("-" * 70)

            for item in items[:20]:  # Limit to 20 per type
                value = item.get('value', 'N/A')
                source = item.get('source', 'unknown')
                click.echo(f"  {value:<50} (from {source})")

            if len(items) > 20:
                click.echo(f"  ... and {len(items) - 20} more")

            click.echo()

    click.pause("Press any key to return...")


def view_web_paths(workspace_id: int):
    """Display web paths in workspace."""
    hm = HostManager()
    wpm = WebPathsManager()

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("WEB PATHS")
    click.echo("=" * 70 + "\n")

    hosts = hm.list_hosts(workspace_id)
    total_paths = 0

    for host in hosts:
        paths = wpm.list_web_paths(host['id'])

        if paths:
            click.echo(click.style(f"Host: {host.get('ip_address', 'N/A')}", bold=True, fg='cyan'))
            click.echo("-" * 70)

            for path in paths[:15]:  # Limit per host
                path_str = path.get('path', '/')
                status = path.get('status_code', '?')
                size = path.get('content_length', '?')

                # Color code status
                if str(status).startswith('2'):
                    status_colored = click.style(str(status), fg='green')
                elif str(status).startswith('3'):
                    status_colored = click.style(str(status), fg='yellow')
                elif str(status).startswith('4'):
                    status_colored = click.style(str(status), fg='red')
                else:
                    status_colored = str(status)

                click.echo(f"  {status_colored:<10} {path_str:<45} ({size} bytes)")

            if len(paths) > 15:
                click.echo(f"  ... and {len(paths) - 15} more")

            total_paths += len(paths)
            click.echo()

    if total_paths == 0:
        click.echo("No web paths found.")

    click.pause("Press any key to return...")


def run_interactive_menu():
    """Main interactive menu loop."""
    while True:
        # Show main menu
        result = show_main_menu()

        if not result:
            click.echo("\nGoodbye!")
            break

        action = result.get('action')

        if action == 'retry':
            continue

        elif action == 'view_dashboard':
            from menuscript.ui.dashboard import run_dashboard
            run_dashboard()

        elif action == 'view_jobs':
            view_jobs_menu()

        elif action == 'view_results':
            view_results_menu()

        elif action == 'launch_tool':
            tool_name = result.get('tool')

            # Show tool configuration menu
            job_params = show_tool_menu(tool_name)

            if not job_params:
                continue

            # Confirm before launching
            click.echo("\n" + "=" * 70)
            click.echo("CONFIRM JOB")
            click.echo("=" * 70)
            click.echo(f"Tool:   {job_params['tool']}")
            click.echo(f"Target: {job_params['target']}")
            if job_params.get('args'):
                click.echo(f"Args:   {' '.join(job_params['args'])}")
            if job_params.get('label'):
                click.echo(f"Label:  {job_params['label']}")
            click.echo()

            if click.confirm("Launch this job?", default=True):
                launch_job(job_params)
                click.echo()
                click.pause("Press any key to continue...")
