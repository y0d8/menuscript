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
from menuscript.ui.terminal import setup_terminal


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

    # Header with box drawing
    click.echo("\n┌" + "─" * 76 + "┐")
    click.echo("│" + click.style(" MENUSCRIPT - INTERACTIVE MENU ".center(76), bold=True, fg='cyan') + "│")
    click.echo("└" + "─" * 76 + "┘")

    # Show current workspace with stats
    wm = WorkspaceManager()
    current_ws = wm.get_current()
    if current_ws:
        stats = wm.stats(current_ws['id'])
        click.echo(f"\n  📂 Workspace: " + click.style(current_ws['name'], fg='green', bold=True))
        click.echo(f"  📊 Data: {stats['hosts']} hosts | {stats['services']} services | {stats['findings']} findings")
    else:
        click.echo("\n  " + click.style("⚠️  No workspace selected! ", fg='yellow', bold=True) +
                   "Use 'menuscript workspace use <name>'")

    click.echo()
    click.echo(click.style("  💡 TIP: ", fg='yellow', bold=True) +
               "Use letter shortcuts (d/j/r/w) or enter the tool number")
    click.echo()
    click.echo("  " + "━" * 76)
    click.echo()

    # Menu options - Tools section
    click.echo(click.style("  🔧 SCANNING TOOLS", bold=True, fg='green'))
    click.echo("  ─" * 38)

    # Display tools by category
    tool_list = []
    idx = 1

    # Category icons
    category_icons = {
        'network': '🌐',
        'web': '🔍',
        'msf': '💥',
        'other': '🛠️'
    }

    for category in sorted(by_category.keys()):
        icon = category_icons.get(category, '🛠️')
        click.echo(f"\n    {icon} " + click.style(category.upper(), fg='cyan', bold=True))

        for name, plugin in sorted(by_category[category], key=lambda x: x[0]):
            help_info = getattr(plugin, 'HELP', {})
            desc = help_info.get('description', 'No description')

            # Create better, concise descriptions
            desc_map = {
                'msf_auxiliary': 'Metasploit auxiliary modules (login, scanners, enumeration)',
                'enum4linux': 'SMB/CIFS enumeration (shares, users, groups)',
                'nmap': 'Network scanner with presets (discovery, port scans)',
                'theharvester': 'OSINT gathering (emails, domains, subdomains)',
                'gobuster': 'Web directory and DNS brute-forcing',
                'nikto': 'Web server vulnerability scanner',
                'sqlmap': 'Automated SQL injection testing and exploitation'
            }

            # Use custom description if available, otherwise use original (limited)
            display_desc = desc_map.get(name, desc[:52])

            # Format tool entry with description
            tool_entry = f"      [{idx:2}] {name:<15} - {display_desc}"
            click.echo(tool_entry)

            tool_list.append(('launch_tool', name))
            idx += 1

    click.echo()
    click.echo("  " + "━" * 76)
    click.echo()

    # View options with shortcuts
    click.echo(click.style("  📊 DATA & MONITORING", bold=True, fg='blue'))
    click.echo("  ─" * 38)

    dashboard_option = idx
    click.echo(f"      " + click.style("[d]", fg='cyan', bold=True) + " or " +
               click.style(f"[{idx}]", fg='cyan') + f"  📈 Live Dashboard    - Real-time monitoring view")
    idx += 1

    job_option = idx
    click.echo(f"      " + click.style("[j]", fg='cyan', bold=True) + " or " +
               click.style(f"[{idx}]", fg='cyan') + f"  ⚡ View Jobs         - Manage running scans")
    idx += 1

    results_option = idx
    click.echo(f"      " + click.style("[r]", fg='cyan', bold=True) + " or " +
               click.style(f"[{idx}]", fg='cyan') + f"  📋 View Results      - Browse scan findings")
    idx += 1

    click.echo()
    click.echo("  " + "━" * 76)
    click.echo()
    click.echo(click.style("  🗂️  WORKSPACE MANAGEMENT", bold=True, fg='magenta'))
    click.echo("  ─" * 38)

    workspace_option = idx
    click.echo(f"      " + click.style("[w]", fg='cyan', bold=True) + " or " +
               click.style(f"[{idx}]", fg='cyan') + f"  📂 Manage Workspaces - Switch, create, or delete workspaces")
    idx += 1

    click.echo()
    click.echo("  " + "━" * 76)
    click.echo()
    click.echo(click.style("  ⚙️  ACTIONS", bold=True, fg='yellow'))
    click.echo("  ─" * 38)
    click.echo(f"      " + click.style("[q]", fg='red', bold=True) + " or " +
               click.style("[0]", fg='red') + "  ← Exit")

    click.echo()
    click.echo("  " + "─" * 76)
    click.echo(click.style("  Enter your choice: ", bold=True), nl=False)

    # Get user selection
    try:
        choice_input = input().strip().lower()

        # Handle letter shortcuts
        if choice_input == 'd':
            return {'action': 'view_dashboard'}
        elif choice_input == 'j':
            return {'action': 'view_jobs'}
        elif choice_input == 'r':
            return {'action': 'view_results'}
        elif choice_input == 'w':
            return {'action': 'manage_workspaces'}
        elif choice_input in ('q', '0', ''):
            return None

        # Handle numeric input
        try:
            choice = int(choice_input)
        except ValueError:
            click.echo(click.style("\n  ✗ Invalid input! Please enter a number or letter shortcut.", fg='red'))
            click.pause()
            return {'action': 'retry'}

        if choice == 0:
            return None

        if choice == dashboard_option:
            return {'action': 'view_dashboard'}

        if choice == job_option:
            return {'action': 'view_jobs'}

        if choice == results_option:
            return {'action': 'view_results'}

        if choice == workspace_option:
            return {'action': 'manage_workspaces'}

        if 1 <= choice <= len(tool_list):
            action_type, tool_name = tool_list[choice - 1]
            return {'action': action_type, 'tool': tool_name}
        else:
            click.echo(click.style(f"\n  ✗ Invalid selection! Please choose 1-{len(tool_list) + 4} or use shortcuts.", fg='red'))
            click.pause()
            return {'action': 'retry'}

    except (KeyboardInterrupt, EOFError):
        click.echo("\n\n  " + click.style("👋 Goodbye!", fg='green'))
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
            elif status in ('failed', 'error'):
                status_str = click.style(status, fg='red')
            elif status == 'killed':
                status_str = click.style(status, fg='magenta')
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

    # Show kill option for running jobs
    if job.get('status') == 'running':
        try:
            if click.confirm(click.style("\nKill this job?", fg='red'), default=False):
                from menuscript.engine.background import kill_job
                if kill_job(job_id):
                    click.echo(click.style("✓ Job killed successfully", fg='green'))
                else:
                    click.echo(click.style("✗ Failed to kill job", fg='red'))
                click.pause("\nPress any key to continue...")
                return  # Return to refresh job list
        except (KeyboardInterrupt, click.Abort):
            pass

    click.pause("\nPress any key to return...")


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


def manage_workspaces_menu():
    """Interactive workspace management menu."""
    wm = WorkspaceManager()

    while True:
        click.clear()

        # Header
        click.echo("\n┌" + "─" * 76 + "┐")
        click.echo("│" + click.style(" WORKSPACE MANAGEMENT ".center(76), bold=True, fg='magenta') + "│")
        click.echo("└" + "─" * 76 + "┘")

        # List all workspaces
        workspaces = wm.list()
        current_ws = wm.get_current()
        current_id = current_ws['id'] if current_ws else None

        click.echo()
        click.echo(click.style("  📂 AVAILABLE WORKSPACES", bold=True, fg='cyan'))
        click.echo("  ─" * 38)

        if not workspaces:
            click.echo("  No workspaces found. Create one to get started!")
        else:
            for ws in workspaces:
                ws_id = ws['id']
                ws_name = ws['name']
                stats = wm.stats(ws_id)

                # Mark current workspace
                if ws_id == current_id:
                    marker = click.style("★", fg='yellow', bold=True)
                    name_style = click.style(ws_name, fg='green', bold=True)
                else:
                    marker = " "
                    name_style = ws_name

                click.echo(f"    {marker} [{ws_id:2}] {name_style:<20} " +
                          f"({stats['hosts']} hosts, {stats['services']} services, {stats['findings']} findings)")

        click.echo()
        click.echo(click.style("  ⚙️  ACTIONS", bold=True, fg='yellow'))
        click.echo("  ─" * 38)
        click.echo("    " + click.style("[s]", fg='cyan', bold=True) + " Switch to Workspace  - Enter workspace name to switch")
        click.echo("    " + click.style("[c]", fg='cyan', bold=True) + " Create Workspace     - Create a new workspace")
        click.echo("    " + click.style("[d]", fg='cyan', bold=True) + " Delete Workspace     - Delete a workspace")
        click.echo("    " + click.style("[b]", fg='red', bold=True) + " Back to Main Menu")

        click.echo()
        click.echo("  " + "─" * 76)
        click.echo(click.style("  Enter your choice: ", bold=True), nl=False)

        try:
            choice = input().strip().lower()

            if choice == 'b' or choice == '':
                return

            elif choice == 's':
                # Switch workspace
                ws_name = click.prompt("\n  Enter workspace name", type=str)
                if wm.set_current(ws_name.strip()):
                    click.echo(click.style(f"\n  ✓ Switched to workspace '{ws_name}'", fg='green'))
                else:
                    click.echo(click.style("\n  ✗ Workspace not found!", fg='red'))
                click.pause()

            elif choice == 'c':
                # Create workspace
                ws_name = click.prompt("\n  Enter new workspace name", type=str)
                if ws_name.strip():
                    ws_id = wm.create(ws_name.strip(), "")
                    wm.set_current(ws_name.strip())
                    click.echo(click.style(f"\n  ✓ Created workspace '{ws_name}' and set as current", fg='green'))
                else:
                    click.echo(click.style("\n  ✗ Workspace name cannot be empty!", fg='red'))
                click.pause()

            elif choice == 'd':
                # Delete workspace
                ws_name = click.prompt("\n  Enter workspace name to delete", type=str)
                ws = wm.get(ws_name.strip())

                if ws:
                    if ws['id'] == current_id:
                        click.echo(click.style("\n  ✗ Cannot delete the current workspace! Switch to another first.", fg='red'))
                    elif click.confirm(f"\n  Are you sure you want to delete '{ws['name']}'? This will delete all data!", default=False):
                        wm.delete(ws_name.strip())
                        click.echo(click.style(f"\n  ✓ Deleted workspace '{ws['name']}'", fg='green'))
                    else:
                        click.echo("\n  Cancelled.")
                else:
                    click.echo(click.style("\n  ✗ Workspace not found!", fg='red'))
                click.pause()

            else:
                click.echo(click.style("\n  ✗ Invalid choice! Use s/c/d/b", fg='red'))
                click.pause()

        except (KeyboardInterrupt, EOFError):
            return


def view_hosts(workspace_id: int):
    """Display hosts with search, filtering, and tagging capabilities."""
    hm = HostManager()

    # Active filters
    filters = {
        'search': None,
        'os_name': None,
        'status': 'up',  # Default to only show live hosts
        'tags': None
    }

    # Selected hosts for bulk operations
    selected_hosts = set()

    while True:
        click.clear()
        click.echo("\n" + "=" * 90)
        click.echo("HOSTS MANAGEMENT")
        click.echo("=" * 90 + "\n")

        # Show active filters
        active_filters = []
        if filters['search']:
            active_filters.append(f"search: {filters['search']}")
        if filters['os_name']:
            active_filters.append(f"OS: {filters['os_name']}")
        if filters['status']:
            active_filters.append(f"status: {filters['status']}")
        if filters['tags']:
            active_filters.append(f"tag: {filters['tags']}")

        if active_filters:
            click.echo(click.style("Active Filters: ", bold=True) + ", ".join(active_filters))
            click.echo()

        # Get hosts with filters
        hosts = hm.search_hosts(
            workspace_id,
            search=filters['search'],
            os_name=filters['os_name'],
            status=filters['status'],
            tags=filters['tags']
        )

        if not hosts:
            click.echo("No hosts found with current filters.")
        else:
            click.echo(f"{'[ ]':<4} {'ID':<5} {'IP Address':<18} {'Hostname':<20} {'OS':<18} {'Tags':<15}")
            click.echo("-" * 90)

            for host in hosts[:30]:  # Limit to 30
                hid = host.get('id', '?')
                selected = '[X]' if hid in selected_hosts else '[ ]'
                ip = host.get('ip_address', 'N/A')[:17]
                hostname = (host.get('hostname') or '-')[:19]
                os = (host.get('os_name') or '-')[:17]
                tags = (host.get('tags') or '')[:14]

                click.echo(f"{selected:<4} {hid:<5} {ip:<18} {hostname:<20} {os:<18} {tags:<15}")

            if len(hosts) > 30:
                click.echo(f"\n... and {len(hosts) - 30} more (use filters to narrow results)")

            click.echo(f"\nTotal: {len(hosts)} host(s) | Selected: {len(selected_hosts)}")

        # Menu options
        click.echo("\n" + "-" * 90)
        click.echo("Filters:")
        click.echo("  [1] Search (IP/Hostname)  [2] Filter by OS  [3] Filter by Status  [4] Filter by Tag")
        click.echo("\nSelection:")
        click.echo("  [5] Select Host(s)  [6] Deselect All")
        click.echo("\nActions:")
        click.echo("  [7] Tag Selected Hosts  [8] Remove Tag from Selected  [9] View Host Details")
        click.echo("\n  [0] Back to Results Menu")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filters['search'] = _hosts_filter_search()
            elif choice == 2:
                filters['os_name'] = _hosts_filter_os()
            elif choice == 3:
                filters['status'] = _hosts_filter_status()
            elif choice == 4:
                filters['tags'] = _hosts_filter_by_tag(workspace_id, hm)
            elif choice == 5:
                _hosts_select(hosts, selected_hosts)
            elif choice == 6:
                selected_hosts.clear()
                click.echo(click.style("✓ All selections cleared", fg='green'))
                click.pause()
            elif choice == 7:
                if selected_hosts:
                    _hosts_bulk_tag(selected_hosts, hm)
                else:
                    click.echo(click.style("No hosts selected", fg='yellow'))
                    click.pause()
            elif choice == 8:
                if selected_hosts:
                    _hosts_bulk_remove_tag(selected_hosts, hm, workspace_id)
                else:
                    click.echo(click.style("No hosts selected", fg='yellow'))
                    click.pause()
            elif choice == 9:
                if hosts:
                    _hosts_view_details(hosts, hm)

        except (KeyboardInterrupt, click.Abort):
            return


def _hosts_filter_search():
    """Prompt for search term."""
    try:
        search = click.prompt("Search term (IP/Hostname, or press Enter to clear)", default="", show_default=False)
        return search if search else None
    except (KeyboardInterrupt, click.Abort):
        return None


def _hosts_filter_os():
    """Prompt for OS filter."""
    try:
        os_name = click.prompt("OS name (or press Enter to clear)", default="", show_default=False)
        return os_name if os_name else None
    except (KeyboardInterrupt, click.Abort):
        return None


def _hosts_filter_status():
    """Prompt for status filter."""
    click.echo("\nSelect status:")
    click.echo("  [1] Up (live)")
    click.echo("  [2] Down")
    click.echo("  [3] All")
    click.echo("  [0] Clear filter")

    try:
        choice = click.prompt("Status", type=int, default=1)
        if choice == 1:
            return 'up'
        elif choice == 2:
            return 'down'
        elif choice == 3:
            return None
        return 'up'  # default
    except (KeyboardInterrupt, click.Abort):
        return 'up'


def _hosts_filter_by_tag(workspace_id: int, hm: 'HostManager'):
    """Prompt for tag filter."""
    tags = hm.get_all_tags(workspace_id)

    if not tags:
        click.echo(click.style("No tags available", fg='yellow'))
        click.pause()
        return None

    click.echo("\nSelect tag:")
    for idx, tag in enumerate(tags, 1):
        click.echo(f"  [{idx}] {tag}")
    click.echo("  [0] Clear filter")

    try:
        choice = click.prompt("Tag", type=int, default=0)
        if choice > 0 and choice <= len(tags):
            return tags[choice - 1]
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _hosts_select(hosts: list, selected_hosts: set):
    """Select hosts by ID."""
    try:
        host_ids = click.prompt("Enter host ID(s) to toggle selection (comma-separated)", default="", show_default=False)
        if not host_ids:
            return

        ids = [int(x.strip()) for x in host_ids.split(',') if x.strip().isdigit()]

        for hid in ids:
            if hid in selected_hosts:
                selected_hosts.remove(hid)
            else:
                # Verify host exists in current list
                if any(h.get('id') == hid for h in hosts):
                    selected_hosts.add(hid)

        click.echo(click.style(f"✓ Selection updated ({len(selected_hosts)} selected)", fg='green'))
        click.pause()
    except (ValueError, KeyboardInterrupt, click.Abort):
        pass


def _hosts_bulk_tag(selected_hosts: set, hm: 'HostManager'):
    """Add tag to selected hosts."""
    try:
        tag = click.prompt("Tag to add", type=str)
        if not tag:
            return

        success_count = 0
        for hid in selected_hosts:
            if hm.add_tag(hid, tag):
                success_count += 1

        click.echo(click.style(f"✓ Tagged {success_count} host(s) with '{tag}'", fg='green'))
        click.pause()
    except (KeyboardInterrupt, click.Abort):
        pass


def _hosts_bulk_remove_tag(selected_hosts: set, hm: 'HostManager', workspace_id: int):
    """Remove tag from selected hosts."""
    tags = hm.get_all_tags(workspace_id)

    if not tags:
        click.echo(click.style("No tags available", fg='yellow'))
        click.pause()
        return

    click.echo("\nSelect tag to remove:")
    for idx, tag in enumerate(tags, 1):
        click.echo(f"  [{idx}] {tag}")

    try:
        choice = click.prompt("Tag", type=int, default=0)
        if choice > 0 and choice <= len(tags):
            tag = tags[choice - 1]

            success_count = 0
            for hid in selected_hosts:
                if hm.remove_tag(hid, tag):
                    success_count += 1

            click.echo(click.style(f"✓ Removed tag '{tag}' from {success_count} host(s)", fg='green'))
            click.pause()
    except (KeyboardInterrupt, click.Abort, ValueError):
        pass


def _hosts_view_details(hosts: list, hm: 'HostManager'):
    """View detailed information about a specific host."""
    try:
        host_id = click.prompt("Enter host ID to view details", type=int)

        host = next((h for h in hosts if h.get('id') == host_id), None)
        if not host:
            click.echo(click.style("Host not found", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo(f"HOST DETAILS - {host.get('ip_address', 'N/A')}")
        click.echo("=" * 70 + "\n")

        click.echo(f"ID:           {host.get('id')}")
        click.echo(f"IP Address:   {host.get('ip_address', 'N/A')}")
        click.echo(f"Hostname:     {host.get('hostname') or 'N/A'}")
        click.echo(f"OS:           {host.get('os_name') or 'N/A'}")
        click.echo(f"MAC Address:  {host.get('mac_address') or 'N/A'}")
        click.echo(f"Status:       {host.get('status', 'unknown')}")
        click.echo(f"Tags:         {host.get('tags') or 'None'}")

        # Show services
        services = hm.get_host_services(host_id)
        click.echo(f"\nServices: {len(services)}")
        if services:
            click.echo(f"\n{'Port':<7} {'Protocol':<10} {'Service':<15}")
            click.echo("-" * 40)
            for svc in services[:10]:  # Show first 10
                port = svc.get('port', '?')
                protocol = svc.get('protocol', 'tcp')
                service = (svc.get('service_name') or 'unknown')[:15]
                click.echo(f"{port:<7} {protocol:<10} {service:<15}")

            if len(services) > 10:
                click.echo(f"... and {len(services) - 10} more")

        click.echo()
        click.pause("Press any key to return...")
    except (KeyboardInterrupt, click.Abort, ValueError):
        pass


def view_services(workspace_id: int):
    """Display services - choose between grouped by host or all services view."""
    while True:
        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo("SERVICES VIEW")
        click.echo("=" * 70 + "\n")
        click.echo("  [1] View by Host (hierarchical)")
        click.echo("  [2] View All Services (with filters)")
        click.echo("  [0] Back to Results Menu")
        click.echo()

        try:
            choice = click.prompt("Select view", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                view_services_by_host(workspace_id)
            elif choice == 2:
                view_all_services_filtered(workspace_id)

        except (KeyboardInterrupt, click.Abort):
            return


def view_services_by_host(workspace_id: int):
    """Display services grouped by host."""
    hm = HostManager()
    import re

    while True:
        # Get all hosts with services
        hosts = hm.list_hosts(workspace_id)
        hosts_with_services = []

        for host in hosts:
            services = hm.get_host_services(host['id'])
            if services:  # Only show hosts with services
                hosts_with_services.append({
                    'host': host,
                    'service_count': len(services)
                })

        # Sort by service count (most services first)
        hosts_with_services.sort(key=lambda x: x['service_count'], reverse=True)

        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo("SERVICES BY HOST")
        click.echo("=" * 70 + "\n")

        if not hosts_with_services:
            click.echo("No services found.")
            click.echo()
            click.pause("Press any key to return...")
            return

        # Show host selection menu
        click.echo(f"{'#':<3} {'Host IP':<18} {'Hostname':<25} {'Services':<10}")
        click.echo("-" * 70)

        for idx, item in enumerate(hosts_with_services, 1):
            host = item['host']
            ip = host.get('ip_address', 'N/A')
            hostname = (host.get('hostname') or '')[:25] or '-'
            svc_count = item['service_count']

            click.echo(f"{idx:<3} {ip:<18} {hostname:<25} {svc_count} service(s)")

        click.echo("\n  0. Back to Services View")

        try:
            choice = click.prompt("\nSelect host to view services", type=int, default=0)

            if choice == 0:
                return

            if 1 <= choice <= len(hosts_with_services):
                selected = hosts_with_services[choice - 1]
                view_host_services(selected['host'], hm)
            else:
                click.echo(click.style("Invalid selection", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def view_all_services_filtered(workspace_id: int):
    """Display all services with filtering and sorting options."""
    hm = HostManager()
    import re

    # Active filters
    filters = {
        'service_name': None,
        'port_min': None,
        'port_max': None,
        'protocol': None,
        'sort_by': 'port'
    }

    while True:
        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo("ALL SERVICES")
        click.echo("=" * 80 + "\n")

        # Show active filters
        active_filters = []
        if filters['service_name']:
            active_filters.append(f"service: {filters['service_name']}")
        if filters['port_min'] is not None or filters['port_max'] is not None:
            if filters['port_min'] and filters['port_max']:
                active_filters.append(f"ports: {filters['port_min']}-{filters['port_max']}")
            elif filters['port_min']:
                active_filters.append(f"ports: >={filters['port_min']}")
            elif filters['port_max']:
                active_filters.append(f"ports: <={filters['port_max']}")
        if filters['protocol']:
            active_filters.append(f"protocol: {filters['protocol']}")

        if active_filters:
            click.echo(click.style("Active Filters: ", bold=True) + ", ".join(active_filters))
        click.echo(click.style(f"Sort by: {filters['sort_by']}", bold=True))
        click.echo()

        # Get services with filters
        services = hm.get_all_services(
            workspace_id,
            service_name=filters['service_name'],
            port_min=filters['port_min'],
            port_max=filters['port_max'],
            protocol=filters['protocol'],
            sort_by=filters['sort_by']
        )

        if not services:
            click.echo("No services found with current filters.")
        else:
            click.echo(f"{'Port':<7} {'Proto':<7} {'Service':<15} {'Host':<18} {'Version':<30}")
            click.echo("-" * 80)

            for svc in services[:50]:  # Limit to 50
                port = svc.get('port', '?')
                protocol = (svc.get('protocol') or 'tcp')[:6]
                service = (svc.get('service_name') or 'unknown')[:14]
                host_ip = (svc.get('ip_address') or 'N/A')[:17]

                # Clean version string
                raw_version = svc.get('service_version') or ''
                if raw_version:
                    version = re.sub(r'^(syn-ack|reset|tcp-response)\s+ttl\s+\d+\s*', '', raw_version)
                    version = version[:29] or '-'
                else:
                    version = '-'

                click.echo(f"{port:<7} {protocol:<7} {service:<15} {host_ip:<18} {version:<30}")

            if len(services) > 50:
                click.echo(f"\n... and {len(services) - 50} more (use filters to narrow results)")
            else:
                click.echo(f"\nTotal: {len(services)} service(s)")

        # Menu options
        click.echo("\n" + "-" * 80)
        click.echo("Options:")
        click.echo("  [1] Filter by Service Name")
        click.echo("  [2] Filter by Port Range")
        click.echo("  [3] Filter by Protocol")
        click.echo("  [4] Sort by (port/service/protocol)")
        click.echo("  [5] Clear All Filters")
        click.echo("  [0] Back to Services View")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filters['service_name'] = _filter_service_name()
            elif choice == 2:
                port_range = _filter_port_range()
                if port_range:
                    filters['port_min'], filters['port_max'] = port_range
            elif choice == 3:
                filters['protocol'] = _filter_protocol()
            elif choice == 4:
                filters['sort_by'] = _select_sort_order()
            elif choice == 5:
                filters = {k: None if k != 'sort_by' else 'port' for k, v in filters.items()}
                click.echo(click.style("✓ All filters cleared", fg='green'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def _filter_service_name():
    """Prompt for service name filter."""
    try:
        name = click.prompt("Service name (or press Enter to clear)", default="", show_default=False)
        return name if name else None
    except (KeyboardInterrupt, click.Abort):
        return None


def _filter_port_range():
    """Prompt for port range filter."""
    try:
        port_min = click.prompt("Minimum port (or press Enter to skip)", type=int, default="", show_default=False)
    except click.Abort:
        port_min = None
    except:
        port_min = None

    try:
        port_max = click.prompt("Maximum port (or press Enter to skip)", type=int, default="", show_default=False)
    except click.Abort:
        port_max = None
    except:
        port_max = None

    if port_min is not None or port_max is not None:
        return (port_min, port_max)
    return None


def _filter_protocol():
    """Prompt for protocol filter."""
    click.echo("\nSelect protocol:")
    click.echo("  [1] TCP")
    click.echo("  [2] UDP")
    click.echo("  [0] Clear filter")

    try:
        choice = click.prompt("Protocol", type=int, default=0)
        if choice == 1:
            return 'tcp'
        elif choice == 2:
            return 'udp'
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _select_sort_order():
    """Prompt for sort order."""
    click.echo("\nSort by:")
    click.echo("  [1] Port")
    click.echo("  [2] Service Name")
    click.echo("  [3] Protocol")

    try:
        choice = click.prompt("Sort", type=int, default=1)
        if choice == 2:
            return 'service'
        elif choice == 3:
            return 'protocol'
        return 'port'
    except (KeyboardInterrupt, click.Abort):
        return 'port'


def view_host_services(host: dict, hm: HostManager):
    """Display services for a specific host."""
    import re

    services = hm.get_host_services(host['id'])

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo(f"SERVICES - {host.get('ip_address', 'N/A')}")
    if host.get('hostname'):
        click.echo(f"Hostname: {host['hostname']}")
    click.echo("=" * 70 + "\n")

    if not services:
        click.echo("No services found.")
    else:
        click.echo(f"{'Port':<7} {'Protocol':<10} {'Service':<15} {'Version'}")
        click.echo("-" * 70)

        for svc in services:
            port = svc.get('port', '?')
            protocol = svc.get('protocol', 'tcp')
            service = (svc.get('service_name') or 'unknown')[:15]

            # Clean version string - remove nmap metadata like "syn-ack ttl 64"
            raw_version = svc.get('service_version') or ''
            if raw_version:
                # Strip nmap response prefixes (syn-ack, reset, etc.) and ttl info
                version = re.sub(r'^(syn-ack|reset|tcp-response)\s+ttl\s+\d+\s*', '', raw_version)
                version = version[:60] or '-'
            else:
                version = '-'

            click.echo(f"{port:<7} {protocol:<10} {service:<15} {version}")

        click.echo(f"\nTotal: {len(services)} service(s)")

    click.echo()
    click.pause("Press any key to continue...")


def view_findings(workspace_id: int):
    """Display findings in workspace with filtering options."""
    fm = FindingsManager()

    # Active filters
    filters = {
        'severity': None,
        'finding_type': None,
        'tool': None,
        'search': None,
        'ip_address': None
    }

    while True:
        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo("FINDINGS")
        click.echo("=" * 80 + "\n")

        # Show active filters
        active_filters = [f"{k}: {v}" for k, v in filters.items() if v]
        if active_filters:
            click.echo(click.style("Active Filters: ", bold=True) + ", ".join(active_filters))
            click.echo()

        # Get findings with filters
        findings = fm.list_findings(
            workspace_id,
            severity=filters['severity'],
            finding_type=filters['finding_type'],
            tool=filters['tool'],
            search=filters['search'],
            ip_address=filters['ip_address']
        )

        if not findings:
            click.echo("No findings found with current filters.")
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
            click.echo(f"{'ID':<5} {'Severity':<10} {'Type':<20} {'Host':<15} {'Title':<35}")
            click.echo("-" * 90)

            for finding in findings[:30]:  # Limit to 30
                fid = finding.get('id', '?')
                sev = finding.get('severity', 'info')
                ftype = (finding.get('finding_type') or 'unknown')[:19]
                host = (finding.get('ip_address') or 'N/A')[:14]
                title = (finding.get('title') or 'No title')[:34]

                # Color code severity
                color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue',
                    'info': 'white'
                }.get(sev, 'white')

                sev_colored = click.style(sev, fg=color)

                click.echo(f"{fid:<5} {sev_colored:<10} {ftype:<20} {host:<15} {title:<35}")

            if len(findings) > 30:
                click.echo(f"\n... and {len(findings) - 30} more (use filters to narrow results)")

        # Menu options
        click.echo("\n" + "-" * 80)
        click.echo("Options:")
        click.echo("  [1] Filter by Severity")
        click.echo("  [2] Filter by Type")
        click.echo("  [3] Filter by Tool")
        click.echo("  [4] Search (title/description)")
        click.echo("  [5] Filter by IP Address")
        click.echo("  [6] Clear All Filters")
        click.echo("  [0] Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filters['severity'] = _filter_by_severity()
            elif choice == 2:
                filters['finding_type'] = _filter_by_type(workspace_id, fm)
            elif choice == 3:
                filters['tool'] = _filter_by_tool(workspace_id, fm)
            elif choice == 4:
                filters['search'] = _filter_by_search()
            elif choice == 5:
                filters['ip_address'] = _filter_by_ip()
            elif choice == 6:
                filters = {k: None for k in filters}
                click.echo(click.style("✓ All filters cleared", fg='green'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def _filter_by_severity():
    """Prompt for severity filter."""
    click.echo("\nSelect severity:")
    click.echo("  [1] Critical")
    click.echo("  [2] High")
    click.echo("  [3] Medium")
    click.echo("  [4] Low")
    click.echo("  [5] Info")
    click.echo("  [0] Clear filter")

    try:
        choice = click.prompt("Severity", type=int, default=0)
        severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}
        return severity_map.get(choice)
    except (KeyboardInterrupt, click.Abort):
        return None


def _filter_by_type(workspace_id: int, fm: 'FindingsManager'):
    """Prompt for finding type filter."""
    types = fm.get_unique_types(workspace_id)

    if not types:
        click.echo(click.style("No finding types available", fg='yellow'))
        click.pause()
        return None

    click.echo("\nSelect finding type:")
    for idx, ftype in enumerate(types, 1):
        click.echo(f"  [{idx}] {ftype}")
    click.echo("  [0] Clear filter")

    try:
        choice = click.prompt("Type", type=int, default=0)
        if choice > 0 and choice <= len(types):
            return types[choice - 1]
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _filter_by_tool(workspace_id: int, fm: 'FindingsManager'):
    """Prompt for tool filter."""
    tools = fm.get_unique_tools(workspace_id)

    if not tools:
        click.echo(click.style("No tools available", fg='yellow'))
        click.pause()
        return None

    click.echo("\nSelect tool:")
    for idx, tool in enumerate(tools, 1):
        click.echo(f"  [{idx}] {tool}")
    click.echo("  [0] Clear filter")

    try:
        choice = click.prompt("Tool", type=int, default=0)
        if choice > 0 and choice <= len(tools):
            return tools[choice - 1]
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _filter_by_search():
    """Prompt for search term."""
    try:
        search = click.prompt("Search term (or press Enter to clear)", default="", show_default=False)
        return search if search else None
    except (KeyboardInterrupt, click.Abort):
        return None


def _filter_by_ip():
    """Prompt for IP address filter."""
    try:
        ip = click.prompt("IP address (or press Enter to clear)", default="", show_default=False)
        return ip if ip else None
    except (KeyboardInterrupt, click.Abort):
        return None


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
    # Set up terminal for proper line editing (backspace, arrows, history)
    setup_terminal()

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

        elif action == 'manage_workspaces':
            manage_workspaces_menu()

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
