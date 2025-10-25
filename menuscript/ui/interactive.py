#!/usr/bin/env python3
"""
menuscript.ui.interactive - Interactive menu system for tool selection
"""
import click
import os
import textwrap
from typing import Dict, Any, Optional, List
from rich.console import Console
from rich.table import Table
from menuscript.engine.loader import discover_plugins
from menuscript.engine.background import enqueue_job, list_jobs, get_job
from menuscript.storage.engagements import EngagementManager
from menuscript.storage.hosts import HostManager
from menuscript.storage.findings import FindingsManager
from menuscript.storage.osint import OsintManager
from menuscript.storage.web_paths import WebPathsManager
from menuscript.ui.terminal import setup_terminal


def get_terminal_width() -> int:
    """Get terminal width with fallback."""
    try:
        width, _ = os.get_terminal_size()
        return width
    except:
        # Fallback to environment variable or default
        try:
            return int(os.environ.get('COLUMNS', 80))
        except:
            return 80


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

    # Get terminal width
    import os
    try:
        width = os.get_terminal_size().columns
    except:
        width = 80

    # Header with box drawing and color
    click.echo("\n┌" + "─" * (width - 2) + "┐")
    click.echo("│" + click.style(" MENUSCRIPT - INTERACTIVE MENU ".center(width - 2), bold=True, fg='cyan') + "│")
    click.echo("└" + "─" * (width - 2) + "┘")

    # ASCII Art Header
    click.echo()
    click.echo(click.style("""
   ███████╗ ██████╗ ██╗   ██╗██╗         ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ███████╗
   ██╔════╝██╔═══██╗██║   ██║██║         ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔════╝
   ███████╗██║   ██║██║   ██║██║         ███████║███████║██║     █████╔╝ █████╗  ██████╔╝███████╗
   ╚════██║██║   ██║██║   ██║██║         ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗╚════██║
   ███████║╚██████╔╝╚██████╔╝███████╗    ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║███████║
   ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝
    """, fg='cyan', bold=True))

    # Credit line
    click.echo("  " + click.style("Created by CyberSoul SecurITy", fg='bright_black', italic=True))
    click.echo()

    # Description
    click.echo("  Menuscript ties your favorite hacking tools together so you can spend less time switching windows")
    click.echo("  and more time breaking things (ethically of course). Kick off scans using the latest tools like")
    click.echo("  Nmap, Metasploit, Gobuster, theHavester, and many more. Menuscript is your one stop shop to")
    click.echo("  manage engagements, review findings, and generate reports — all in one place.")

    click.echo()
    click.echo("  " + click.style("TIP:", bold=True) + " Use letter shortcuts (d/j/h/s/f/c/r/e/v) or enter the number")
    click.echo()
    click.echo("  " + "─" * (width - 4))
    click.echo()

    # Store engagement info for footer
    em = EngagementManager()
    current_ws = em.get_current()

    # Menu options - Tools section
    click.echo(click.style("  SCANNING TOOLS", bold=True))
    click.echo()

    # Display tools by category
    tool_list = []
    idx = 1

    for category in sorted(by_category.keys()):
        click.echo("    " + click.style(category.upper(), bold=True))

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
    click.echo("  " + "─" * (width - 4))
    click.echo()

    # Data & Management options with shortcuts
    click.echo(click.style("  COMMAND & CONTROL HUB", bold=True))
    click.echo()

    dashboard_option = idx
    click.echo(f"      " + click.style("[d]", bold=True) + " or " +
               f"[{idx}]" + "   Live Dashboard          - Real-time monitoring view")
    idx += 1

    job_option = idx
    click.echo(f"      " + click.style("[j]", bold=True) + " or " +
               f"[{idx}]" + "  Job Management          - Manage running scans")
    idx += 1

    hosts_option = idx
    click.echo(f"      " + click.style("[h]", bold=True) + " or " +
               f"[{idx}]" + "  Host Management         - View and manage hosts")
    idx += 1

    services_option = idx
    click.echo(f"      " + click.style("[s]", bold=True) + " or " +
               f"[{idx}]" + "  Service Management      - View and manage services")
    idx += 1

    findings_option = idx
    click.echo(f"      " + click.style("[f]", bold=True) + " or " +
               f"[{idx}]" + "  Findings Management     - View, add, edit, delete findings")
    idx += 1

    credentials_option = idx
    click.echo(f"      " + click.style("[c]", bold=True) + " or " +
               f"[{idx}]" + "  Credential Management   - View, test, manage credentials")
    idx += 1

    reports_option = idx
    click.echo(f"      " + click.style("[r]", bold=True) + " or " +
               f"[{idx}]" + "  Reports Management      - Generate, view, import data")
    idx += 1

    engagement_option = idx
    click.echo(f"      " + click.style("[e]", bold=True) + " or " +
               f"[{idx}]" + "  Engagement Management   - Switch, create, delete engagements")
    idx += 1

    additional_option = idx
    click.echo(f"      " + click.style("[v]", bold=True) + " or " +
               f"[{idx}]" + "  View Additional Data    - OSINT, Web Paths")
    idx += 1

    click.echo()
    click.echo(f"      " + click.style("[q]", bold=True) + " or " +
               "[0]" + "   Exit")

    click.echo()
    click.echo("  " + "─" * (width - 4))

    # Workspace status footer
    if current_ws:
        stats = em.stats(current_ws['id'])
        engagement_info = f"Engagement: {click.style(current_ws['name'], bold=True)} | {stats['hosts']} hosts | {stats['services']} services | {stats['findings']} findings"
        click.echo(f"  {engagement_info}")
    else:
        click.echo("  " + click.style("WARNING: No engagement selected!", bold=True) + " Use 'menuscript engagement use <name>'")

    click.echo("  " + "─" * (width - 4))
    click.echo(click.style("  Enter your choice: ", bold=True), nl=False)

    # Get user selection
    try:
        choice_input = input().strip().lower()

        # Handle letter shortcuts
        if choice_input == 'd':
            return {'action': 'view_dashboard'}
        elif choice_input == 'j':
            return {'action': 'view_jobs'}
        elif choice_input == 'h':
            return {'action': 'manage_hosts'}
        elif choice_input == 's':
            return {'action': 'manage_services'}
        elif choice_input == 'f':
            return {'action': 'manage_findings'}
        elif choice_input == 'c':
            return {'action': 'manage_credentials'}
        elif choice_input == 'r':
            return {'action': 'manage_reports'}
        elif choice_input == 'e':
            return {'action': 'manage_engagements'}
        elif choice_input == 'v':
            return {'action': 'view_additional_data'}
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

        if choice == hosts_option:
            return {'action': 'manage_hosts'}

        if choice == services_option:
            return {'action': 'manage_services'}

        if choice == findings_option:
            return {'action': 'manage_findings'}

        if choice == credentials_option:
            return {'action': 'manage_credentials'}

        if choice == reports_option:
            return {'action': 'manage_reports'}

        if choice == engagement_option:
            return {'action': 'manage_engagements'}

        if choice == additional_option:
            return {'action': 'view_additional_data'}

        if 1 <= choice <= len(tool_list):
            action_type, tool_name = tool_list[choice - 1]
            return {'action': action_type, 'tool': tool_name}
        else:
            click.echo(click.style(f"\n  ✗ Invalid selection! Please choose 1-{len(tool_list) + 9} or use shortcuts.", fg='red'))
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

    # Get terminal width for responsive banner
    width = get_terminal_width()

    # Tool category icons
    category_icons = {
        'network': '🌐',
        'web': '🔍',
        'osint': '🔎',
        'metasploit': '⚡',
        'windows': '🪟',
        'other': '🔧'
    }

    # Build centered banner with box drawing
    click.clear()
    tool_title = help_info.get('name', tool_name)
    description = help_info.get('description', '')
    category = getattr(plugin, 'category', 'other')
    icon = category_icons.get(category, '🔧')

    # Header with horizontal line styling (similar to presets)
    click.echo("\n" + click.style("─" * width, fg='cyan', bold=True))
    # Tool title with icon centered
    title_with_icon = f"{icon}  {tool_title}"
    padding = (width - len(title_with_icon)) // 2
    title_line = " " * padding + title_with_icon
    click.echo(click.style(title_line, fg='cyan', bold=True))
    click.echo(click.style("─" * width, fg='cyan', bold=True))
    click.echo()

    # Wrap description to match terminal width, preserving paragraph structure
    # Display in a bordered box for better visibility (centered, 75% of terminal width)
    if description:
        box_width = int(width * 0.75)  # Box is 75% of terminal width
        left_margin = (width - box_width) // 2
        
        # Split by double newlines to preserve paragraphs
        paragraphs = description.split('\n\n')
        formatted_lines = []
        
        for para in paragraphs:
            # Check if this paragraph contains bullet points
            if '\n-' in para or para.strip().startswith('-'):
                # This is a bulleted list - process each line separately
                lines = para.split('\n')
                for line in lines:
                    if line.strip():
                        # Wrap long bullet lines
                        wrapped = textwrap.fill(line, width=box_width - 4)
                        for wrapped_line in wrapped.split('\n'):
                            formatted_lines.append(wrapped_line)
                formatted_lines.append('')  # Add blank line after bullet section
            else:
                # Regular paragraph - wrap it and split into individual lines
                wrapped_para = textwrap.fill(para, width=box_width - 4)  # Leave room for box borders
                for line in wrapped_para.split('\n'):
                    formatted_lines.append(line)
                formatted_lines.append('')  # Add blank line after paragraph
        
        # Remove trailing blank line
        if formatted_lines and formatted_lines[-1] == '':
            formatted_lines.pop()
        
        # Draw the box around the description (centered)
        margin = " " * left_margin
        click.echo(margin + click.style("┌" + "─" * (box_width - 2) + "┐", fg='blue'))
        for line in formatted_lines:
            if line:
                # Calculate actual display length (accounting for emojis which take 2 display columns)
                # Count emojis in the line
                import unicodedata
                display_len = 0
                for char in line:
                    # Emojis and some special chars have East Asian Width 'W' (wide) or 'F' (fullwidth)
                    if unicodedata.east_asian_width(char) in ('W', 'F'):
                        display_len += 2
                    else:
                        display_len += 1
                
                # Pad line to exact width and add borders
                padding_needed = box_width - 4 - display_len
                if padding_needed < 0:
                    padding_needed = 0
                padded_line = line + " " * padding_needed
                click.echo(margin + click.style("│ ", fg='blue') + padded_line + click.style(" │", fg='blue'))
            else:
                # Empty line
                click.echo(margin + click.style("│" + " " * (box_width - 2) + "│", fg='blue'))
        click.echo(margin + click.style("└" + "─" * (box_width - 2) + "┘", fg='blue'))
    click.echo()

    # Get target FIRST (more logical workflow) - Make it prominent
    click.echo(click.style("━" * width, fg='yellow', bold=True))
    click.echo(click.style("🎯 TARGET SELECTION", fg='yellow', bold=True))
    click.echo(click.style("━" * width, fg='yellow', bold=True))
    click.echo()
    
    # Offer to use hosts from current engagement
    from menuscript.storage.engagements import EngagementManager
    from menuscript.storage.hosts import HostManager
    
    em = EngagementManager()
    current_eng = em.get_current()
    
    target = None
    if current_eng:
        hm = HostManager()
        all_hosts = hm.list_hosts(current_eng['id'])
        if all_hosts:
            # Count active hosts (status = 'up')
            active_hosts = [h for h in all_hosts if h.get('status') == 'up']
            
            click.echo(f"Found {len(all_hosts)} total host(s), {len(active_hosts)} active.")
            click.echo()
            click.echo("  1. Use all hosts from engagement")
            click.echo("  2. Use only active hosts (status: up)")
            click.echo("  3. Enter custom target")
            click.echo()
            
            choice = click.prompt(click.style("Select option", fg='yellow', bold=True), type=int, default=3)
            
            if choice == 1:
                # Get IPs from all hosts
                ips = [h['ip_address'] for h in all_hosts if h.get('ip_address')]
                if ips:
                    target = ' '.join(ips)
                    click.echo(click.style(f"✓ Using all {len(ips)} host(s): {target[:80]}{'...' if len(target) > 80 else ''}", fg='green'))
                    click.echo()
                else:
                    click.echo(click.style("No IP addresses found in hosts!", fg='red'))
                    return None
            elif choice == 2:
                # Get IPs from active hosts only
                ips = [h['ip_address'] for h in active_hosts if h.get('ip_address')]
                if ips:
                    target = ' '.join(ips)
                    click.echo(click.style(f"✓ Using {len(ips)} active host(s): {target[:80]}{'...' if len(target) > 80 else ''}", fg='green'))
                    click.echo()
                else:
                    click.echo(click.style("No active hosts found!", fg='yellow'))
                    return None
    
    # If no target set yet, prompt for it
    if not target:
        target = click.prompt(click.style("Enter target (IP, hostname, URL, or CIDR)", fg='yellow', bold=True) + " [or 'back' to return]", type=str)
        
        if not target or target.strip() == "":
            click.echo(click.style("Target required!", fg='red'))
            return None

        target = target.strip()

        # Check if user wants to go back
        if target.lower() in ['back', 'b', 'exit', 'q']:
            return {'action': 'back'}

    # Now show presets and let user choose
    args = []
    selected_preset_name = None

    if presets:
        click.echo()
        click.echo(click.style("━" * width, fg='green', bold=True))
        click.echo(click.style("📋 AVAILABLE PRESETS", bold=True, fg='green'))
        click.echo(click.style("━" * width, fg='green', bold=True))
        click.echo()

        # Check if tool has categorized presets
        preset_categories = help_info.get('preset_categories', {})

        if preset_categories:
            # Display presets grouped by category
            preset_num = 1
            for category_name, category_presets in preset_categories.items():
                # Format category name (e.g., "basic_detection" -> "Basic Detection")
                display_name = category_name.replace('_', ' ').title()
                click.echo(click.style(f"  {display_name}:", bold=True))
                for preset in category_presets:
                    click.echo(f"    {preset_num}. {preset['name']:<20} - {preset['desc']}")
                    preset_num += 1
                click.echo()
        else:
            # Fall back to simple list for tools without categories
            for i, preset in enumerate(presets, 1):
                click.echo(f"  {i}. {preset['name']:<20} - {preset['desc']}")
            click.echo()

        click.echo(f"  {len(presets) + 1}. Custom args")
        click.echo(f"  0. Back")
        click.echo()

        try:
            choice = click.prompt(click.style("Select preset", fg='green', bold=True), type=int, default=1)

            if choice == 0:
                return {'action': 'back'}
            elif 1 <= choice <= len(presets):
                selected_preset = presets[choice - 1]
                args = selected_preset['args']
                selected_preset_name = selected_preset['name']
                click.echo(click.style(f"\n✓ Using preset: {selected_preset['name']}", fg='green'))
            else:
                # Custom args
                custom = click.prompt("\nEnter custom arguments (space-separated)", default="", type=str)
                if custom:
                    args = custom.split()
        except (KeyboardInterrupt, click.Abort):
            return None
    else:
        # No presets, just ask for custom args
        click.echo()
        click.echo(click.style("─" * width, fg='yellow'))
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

            # Check if we have discovered credentials in the database
            from menuscript.storage.credentials import CredentialsManager
            from menuscript.storage.engagements import EngagementManager

            em = EngagementManager()
            current_eng = em.get_current()
            db_users_available = False
            db_user_count = 0

            if current_eng:
                cm = CredentialsManager()
                # Get all credentials
                all_creds = cm.list_credentials(current_eng['id'])

                # Separate username-only and valid pairs
                db_users = [c for c in all_creds if c.get('username') and not c.get('password')]
                db_valid_pairs = [c for c in all_creds if c.get('username') and c.get('password')]

                db_user_count = len(db_users)
                db_pair_count = len(db_valid_pairs)
                db_users_available = db_user_count > 0 or db_pair_count > 0

                if db_users_available:
                    click.echo(click.style("💡 Credentials in database:", fg='cyan', bold=True))
                    if db_user_count > 0:
                        click.echo(click.style(f"   • {db_user_count} discovered usernames (for brute force)", fg='cyan'))
                    if db_pair_count > 0:
                        click.echo(click.style(f"   • {db_pair_count} valid username:password pairs", fg='green', bold=True))
                    click.echo()

            # Ask about credential options with clear descriptions
            if db_users_available:
                click.echo(click.style("Choose how to configure credentials:", bold=True))
                click.echo()
                if db_pair_count > 0:
                    click.echo("  " + click.style("[use_db_pairs]", fg='green', bold=True) + f"  - Test {db_pair_count} valid username:password pairs from database")
                if db_user_count > 0:
                    click.echo("  " + click.style("[use_db_user_as_pass]", fg='yellow', bold=True) + f"  - Test {db_user_count} usernames AS passwords (user:user)")
                    click.echo("  " + click.style("[use_db_users]", fg='cyan', bold=True) + f"  - Brute force with {db_user_count} usernames from database + password wordlist")
                click.echo("  [single]        - Test a single username/password")
                click.echo("  [wordlist]      - Use custom username and password files")
                click.echo("  [userpass_file] - Use custom username:password file")
                click.echo("  [skip]          - Skip credential configuration")
                click.echo()

                # Build choices list
                choices = []
                if db_pair_count > 0:
                    choices.append('use_db_pairs')
                if db_user_count > 0:
                    choices.append('use_db_user_as_pass')
                    choices.append('use_db_users')
                choices.extend(['single', 'wordlist', 'userpass_file', 'skip'])

                # Smart default: pairs > user_as_pass > users_with_wordlist
                if db_pair_count > 0:
                    default_choice = 'use_db_pairs'
                elif db_user_count > 0:
                    default_choice = 'use_db_user_as_pass'  # Try username as password first (fast!)
                else:
                    default_choice = 'skip'
            else:
                choices = ['single', 'wordlist', 'userpass_file', 'skip']
                default_choice = 'skip'

            cred_mode = click.prompt(
                "Credential mode",
                type=click.Choice(choices, case_sensitive=False),
                default=default_choice,
                show_choices=False
            )

            if cred_mode == 'use_db_pairs':
                # Use valid username:password pairs from database
                import tempfile
                import os

                click.echo(click.style(f"✓ Using {db_pair_count} valid username:password pairs from database", fg='green'))
                click.echo()

                # Filter options
                click.echo("Filter credentials by:")
                filter_service = click.prompt("  Service (ssh, smb, mysql, etc.) or leave blank for all", default="", type=str)
                filter_host = click.prompt("  Host IP or leave blank for all", default="", type=str)

                # Get filtered credentials
                filtered_pairs = db_valid_pairs
                if filter_service or filter_host:
                    filtered_pairs = []
                    for c in db_valid_pairs:
                        if filter_service and c.get('service') != filter_service:
                            continue
                        if filter_host and c.get('ip_address') != filter_host:
                            continue
                        filtered_pairs.append(c)

                if not filtered_pairs:
                    click.echo(click.style("✗ No credentials match the filters", fg='red'))
                    cred_mode = 'skip'
                else:
                    click.echo(click.style(f"✓ {len(filtered_pairs)} credential pairs selected", fg='green'))

                    # Create temp file with username:password pairs
                    temp_fd, temp_path = tempfile.mkstemp(prefix='menuscript_creds_', suffix='.txt', text=True)
                    try:
                        with os.fdopen(temp_fd, 'w') as f:
                            for cred in filtered_pairs:
                                username = cred.get('username')
                                password = cred.get('password')
                                if username and password:
                                    # MSF userpass format: username password (space-separated)
                                    f.write(f"{username} {password}\n")

                        click.echo(f"Created temporary credential file: {temp_path}")
                        click.echo(f"  Contains {len(filtered_pairs)} username:password pairs")
                        args.append(f"USERPASS_FILE={temp_path}")

                    except Exception as e:
                        click.echo(click.style(f"✗ Error creating credential file: {e}", fg='red'))
                        try:
                            os.unlink(temp_path)
                        except:
                            pass
                        cred_mode = 'skip'

            elif cred_mode == 'use_db_user_as_pass':
                # Use usernames AS passwords (username:username pairs)
                import tempfile
                import os

                click.echo(click.style(f"✓ Testing {db_user_count} usernames AS passwords (user:user)", fg='green'))
                click.echo()

                # Filter options
                click.echo("Filter credentials by:")
                filter_service = click.prompt("  Service (ssh, smb, mysql, etc.) or leave blank for all", default="", type=str)
                filter_host = click.prompt("  Host IP or leave blank for all", default="", type=str)

                # Get filtered credentials
                filtered_users = db_users
                if filter_service or filter_host:
                    filtered_users = []
                    for c in db_users:
                        if filter_service and c.get('service') != filter_service:
                            continue
                        if filter_host and c.get('ip_address') != filter_host:
                            continue
                        filtered_users.append(c)

                if not filtered_users:
                    click.echo(click.style("✗ No usernames match the filters", fg='red'))
                    cred_mode = 'skip'
                else:
                    click.echo(click.style(f"✓ {len(filtered_users)} usernames selected", fg='green'))

                    # Create temp file with username:username pairs
                    temp_fd, temp_path = tempfile.mkstemp(prefix='menuscript_user_as_pass_', suffix='.txt', text=True)
                    try:
                        with os.fdopen(temp_fd, 'w') as f:
                            for cred in filtered_users:
                                username = cred.get('username')
                                if username:
                                    # MSF userpass format: username password (space-separated)
                                    # Using username AS password: msfadmin msfadmin
                                    f.write(f"{username} {username}\n")

                        click.echo(f"Created temporary credential file: {temp_path}")
                        click.echo(f"  Contains {len(filtered_users)} username:username pairs")
                        click.echo()
                        click.echo(click.style("Examples:", fg='cyan'))

                        # Show first 5 examples
                        shown = 0
                        for cred in filtered_users[:5]:
                            username = cred.get('username')
                            if username:
                                click.echo(f"  • {username}:{username}")
                                shown += 1

                        if len(filtered_users) > 5:
                            click.echo(f"  ... and {len(filtered_users) - 5} more")

                        args.append(f"USERPASS_FILE={temp_path}")

                    except Exception as e:
                        click.echo(click.style(f"✗ Error creating credential file: {e}", fg='red'))
                        try:
                            os.unlink(temp_path)
                        except:
                            pass
                        cred_mode = 'skip'

            elif cred_mode == 'use_db_users':
                # Use discovered usernames from database for brute force
                import tempfile
                import os

                click.echo(click.style(f"✓ Using {db_user_count} discovered usernames from database", fg='green'))
                click.echo()

                # Filter options
                click.echo("Filter usernames by:")
                filter_service = click.prompt("  Service (ssh, smb, mysql, etc.) or leave blank for all", default="", type=str)
                filter_host = click.prompt("  Host IP or leave blank for all", default="", type=str)

                # Get filtered credentials
                if filter_service or filter_host:
                    filtered_creds = []
                    for c in db_users:
                        if filter_service and c.get('service') != filter_service:
                            continue
                        if filter_host and c.get('ip_address') != filter_host:
                            continue
                        filtered_creds.append(c)
                    db_users = filtered_creds

                if not db_users:
                    click.echo(click.style("✗ No usernames match the filters", fg='red'))
                    cred_mode = 'skip'
                else:
                    click.echo(click.style(f"✓ {len(db_users)} usernames selected", fg='green'))

                    # Create temp file with usernames
                    temp_fd, temp_path = tempfile.mkstemp(prefix='menuscript_users_', suffix='.txt', text=True)
                    try:
                        with os.fdopen(temp_fd, 'w') as f:
                            for cred in db_users:
                                username = cred.get('username')
                                if username:
                                    f.write(username + '\n')

                        click.echo(f"Created temporary user file: {temp_path}")
                        click.echo(f"  Contains {len(db_users)} usernames")
                        args.append(f"USER_FILE={temp_path}")

                        # Ask for password file
                        click.echo()
                        click.echo("Now specify the password wordlist to test:")

                        # Common password file locations
                        default_pass_file = "/usr/share/wordlists/rockyou.txt"
                        if not os.path.exists(default_pass_file):
                            # Try alternative locations
                            alt_locations = [
                                "/usr/share/wordlists/metasploit/unix_passwords.txt",
                                "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt",
                                "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
                            ]
                            for alt in alt_locations:
                                if os.path.exists(alt):
                                    default_pass_file = alt
                                    break

                        pass_file = click.prompt("PASS_FILE (path to password list)", default=default_pass_file, type=str, show_default=True)

                        # Ensure we got a valid password file (not the username file)
                        if not pass_file or pass_file.strip() == "":
                            click.echo(click.style("⚠️  No password file specified", fg='red'))
                            pass_file = default_pass_file

                        # Make sure it's not the same as the username file
                        if pass_file == temp_path:
                            click.echo(click.style("⚠️  Password file cannot be the same as username file!", fg='red'))
                            pass_file = default_pass_file

                        if pass_file and os.path.exists(pass_file):
                            args.append(f"PASS_FILE={pass_file}")
                            click.echo(click.style(f"✓ Using password file: {pass_file}", fg='green'))
                        elif pass_file:
                            click.echo(click.style(f"⚠️  Warning: Password file not found: {pass_file}", fg='yellow'))
                            if click.confirm("Continue anyway?", default=False):
                                args.append(f"PASS_FILE={pass_file}")
                            else:
                                click.echo(click.style("Cancelled", fg='red'))
                                cred_mode = 'skip'

                    except Exception as e:
                        click.echo(click.style(f"✗ Error creating user file: {e}", fg='red'))
                        try:
                            os.unlink(temp_path)
                        except:
                            pass
                        cred_mode = 'skip'

            elif cred_mode == 'single':
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
        click.echo("\n" + "=" * 110)
        click.echo("JOB QUEUE")
        click.echo("=" * 110 + "\n")

        jobs = list_jobs(limit=20)

        if not jobs:
            click.echo("No jobs found.")
            click.echo()
            click.pause("Press any key to return to main menu...")
            return

        # Display jobs count
        click.echo(f"  {click.style('Total Jobs:', bold=True)} {len(jobs)}")
        click.echo()
        
        # Table header with borders
        click.echo("  ┌──────┬──────────┬──────────────┬────────────────────────────────────────┬────────────────────┬──────────────────────┐")
        header = f"  │  ID  │ Status   │ Tool         │ Target                                 │ Label              │ Created              │"
        click.echo(click.style(header, bold=True))
        click.echo("  ├──────┼──────────┼──────────────┼────────────────────────────────────────┼────────────────────┼──────────────────────┤")

        for job in jobs:
            jid = str(job.get('id', '?'))
            status = job.get('status', 'unknown')
            tool = job.get('tool', 'unknown')
            target = job.get('target', '')
            label = job.get('label', '') or '-'
            created = job.get('created_at', '')[:19] if job.get('created_at') else '-'

            # Truncate target if too long
            if len(target) > 38:
                target = target[:35] + '...'
            
            # Truncate label if too long
            if len(label) > 18:
                label = label[:15] + '...'
            
            # Truncate tool if too long
            if len(tool) > 12:
                tool = tool[:12]

            # Color code status with status marker
            if status == 'done':
                status_marker = click.style('✓', fg='green')
                status_display = f"{status_marker} {status:<7}"
            elif status == 'running':
                status_marker = click.style('▶', fg='yellow')
                status_display = f"{status_marker} {status:<7}"
            elif status in ('failed', 'error'):
                status_marker = click.style('✗', fg='red')
                status_display = f"{status_marker} {status:<7}"
            elif status == 'killed':
                status_marker = click.style('●', fg='magenta')
                status_display = f"{status_marker} {status:<7}"
            elif status == 'queued':
                status_marker = click.style('◷', fg='cyan')
                status_display = f"{status_marker} {status:<7}"
            else:
                status_display = f"  {status:<7}"

            row = f"  │ {jid:>4} │ {status_display} │ {tool:<12} │ {target:<38} │ {label:<18} │ {created:<20} │"
            click.echo(row)

        # Bottom border
        click.echo("  └──────┴──────────┴──────────────┴────────────────────────────────────────┴────────────────────┴──────────────────────┘")
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
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']

    while True:
        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo(f"SCAN RESULTS - Engagement: {current_ws['name']}")
        click.echo("=" * 70 + "\n")

        stats = em.stats(engagement_id)

        click.echo("  1. Hosts        ({:3} total)".format(stats['hosts']))
        click.echo("  2. Services     ({:3} total)".format(stats['services']))
        click.echo("  3. Findings     ({:3} total)".format(stats['findings']))

        # Get credentials count
        try:
            from menuscript.storage.credentials import CredentialsManager
            cm = CredentialsManager()
            creds_stats = cm.get_stats(engagement_id)
            creds_count = creds_stats['total']
        except:
            creds_count = 0

        # Get OSINT and paths counts
        try:
            om = OsintManager()
            osint_count = len(om.list_osint_data(engagement_id))
        except:
            osint_count = 0

        try:
            wpm = WebPathsManager()
            # Count all paths across all hosts
            paths_count = 0
            hm = HostManager()
            for host in hm.list_hosts(engagement_id):
                paths_count += len(wpm.list_paths(host['id']))
        except:
            paths_count = 0

        click.echo("  4. Credentials  ({:3} total)".format(creds_count))
        click.echo("  5. OSINT Data   ({:3} total)".format(osint_count))
        click.echo("  6. Web Paths    ({:3} total)".format(paths_count))
        click.echo()
        click.echo("  0. Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select data type", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                view_hosts(engagement_id)
            elif choice == 2:
                view_services(engagement_id)
            elif choice == 3:
                view_findings(engagement_id)
            elif choice == 4:
                view_credentials(engagement_id)
            elif choice == 5:
                view_osint(engagement_id)
            elif choice == 6:
                view_web_paths(engagement_id)
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def manage_engagements_menu():
    """Interactive engagement management menu."""
    em = EngagementManager()

    while True:
        click.clear()

        # Header
        click.echo("\n┌" + "─" * 76 + "┐")
        click.echo("│" + click.style(" ENGAGEMENT MANAGEMENT ".center(76), bold=True, fg='magenta') + "│")
        click.echo("└" + "─" * 76 + "┘")

        # List all engagements
        engagements = em.list()
        current_ws = em.get_current()
        current_id = current_ws['id'] if current_ws else None

        click.echo()
        click.echo(click.style("  📂 AVAILABLE ENGAGEMENTS", bold=True, fg='cyan'))
        click.echo("  ─" * 38)

        if not engagements:
            click.echo("  No engagements found. Create one to get started!")
        else:
            for ws in engagements:
                ws_id = ws['id']
                ws_name = ws['name']
                stats = em.stats(ws_id)

                # Mark current engagement
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
        click.echo("    " + click.style("[s]", fg='cyan', bold=True) + " Switch to Engagement  - Enter engagement name to switch")
        click.echo("    " + click.style("[c]", fg='cyan', bold=True) + " Create Engagement     - Create a new engagement")
        click.echo("    " + click.style("[d]", fg='cyan', bold=True) + " Delete Engagement     - Delete a engagement")
        click.echo("    " + click.style("[b]", fg='red', bold=True) + " Back to Main Menu")

        click.echo()
        click.echo("  " + "─" * 76)
        click.echo(click.style("  Enter your choice: ", bold=True), nl=False)

        try:
            choice = input().strip().lower()

            if choice == 'b' or choice == '':
                return

            elif choice == 's':
                # Switch engagement
                ws_name = click.prompt("\n  Enter engagement name", type=str)
                if em.set_current(ws_name.strip()):
                    click.echo(click.style(f"\n  ✓ Switched to engagement '{ws_name}'", fg='green'))
                else:
                    click.echo(click.style("\n  ✗ Engagement not found!", fg='red'))
                click.pause()

            elif choice == 'c':
                # Create engagement
                ws_name = click.prompt("\n  Enter new engagement name", type=str)
                if ws_name.strip():
                    ws_id = em.create(ws_name.strip(), "")
                    em.set_current(ws_name.strip())
                    click.echo(click.style(f"\n  ✓ Created engagement '{ws_name}' and set as current", fg='green'))
                else:
                    click.echo(click.style("\n  ✗ Engagement name cannot be empty!", fg='red'))
                click.pause()

            elif choice == 'd':
                # Delete engagement
                ws_name = click.prompt("\n  Enter engagement name to delete", type=str)
                ws = em.get(ws_name.strip())

                if ws:
                    if ws['id'] == current_id:
                        click.echo(click.style("\n  ✗ Cannot delete the current engagement! Switch to another first.", fg='red'))
                    elif click.confirm(f"\n  Are you sure you want to delete '{ws['name']}'? This will delete all data!", default=False):
                        em.delete(ws_name.strip())
                        click.echo(click.style(f"\n  ✓ Deleted engagement '{ws['name']}'", fg='green'))
                    else:
                        click.echo("\n  Cancelled.")
                else:
                    click.echo(click.style("\n  ✗ Engagement not found!", fg='red'))
                click.pause()

            else:
                click.echo(click.style("\n  ✗ Invalid choice! Use s/c/d/b", fg='red'))
                click.pause()

        except (KeyboardInterrupt, EOFError):
            return


def manage_hosts_menu():
    """Host management menu wrapper."""
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']
    view_hosts(engagement_id)


def manage_services_menu():
    """Service management menu wrapper."""
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']
    view_services(engagement_id)


def manage_findings_menu():
    """Findings management menu wrapper."""
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']
    view_findings(engagement_id)


def manage_credentials_menu():
    """Credential management menu wrapper."""
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']

    # Show credentials management with option to test
    while True:
        view_credentials(engagement_id)
        # Check if user wants to test credentials
        break


def view_additional_data_menu():
    """Additional data viewing menu for OSINT and Web Paths."""
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']

    while True:
        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo("ADDITIONAL DATA")
        click.echo("=" * 70 + "\n")

        click.echo("  1. OSINT Data       - View and manage OSINT reconnaissance data")
        click.echo("  2. Web Paths        - View and manage discovered web paths")
        click.echo()
        click.echo("  0. Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select data type", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                view_osint(engagement_id)
            elif choice == 2:
                view_web_paths(engagement_id)
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def view_hosts(engagement_id: int):
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
        width = 100
        
        click.echo()
        click.echo("  " + "═" * (width - 4))
        click.echo(click.style("  HOST MANAGEMENT", bold=True))
        click.echo("  " + "═" * (width - 4))
        click.echo()

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
            click.echo("  " + click.style("Active Filters: ", bold=True) + ", ".join(active_filters))
            click.echo()

        # Get hosts with filters
        hosts = hm.search_hosts(
            engagement_id,
            search=filters['search'],
            os_name=filters['os_name'],
            status=filters['status'],
            tags=filters['tags']
        )

        if not hosts:
            click.echo("  " + click.style("No hosts found with current filters.", fg='yellow'))
        else:
            # Summary stats
            total = len(hosts)
            active = len([h for h in hosts if h.get('status') == 'up'])
            click.echo(f"  {click.style('Total:', bold=True)} {total} hosts  |  {click.style('Active:', bold=True, fg='green')} {active}")
            click.echo()
            
            # Table header with better spacing
            click.echo("  ┌───┬─────┬─────────────────┬──────────────────────────┬──────────────────────────────┬──────────┐")
            header = f"  │[ ]│ ID  │ IP Address      │ Hostname                 │ Operating System             │ Services │"
            click.echo(click.style(header, bold=True))
            click.echo("  ├───┼─────┼─────────────────┼──────────────────────────┼──────────────────────────────┼──────────┤")

            for host in hosts[:25]:  # Limit to 25 for better viewing
                hid = host.get('id', '?')
                selected = 'X' if hid in selected_hosts else ' '
                ip = (host.get('ip_address', 'N/A') or 'N/A')
                hostname = (host.get('hostname') or '-')
                os_info = (host.get('os_name') or '-')
                
                # Truncate long strings
                if len(ip) > 15:
                    ip = ip[:15]
                if len(hostname) > 24:
                    hostname = hostname[:21] + '...'
                if len(os_info) > 28:
                    os_info = os_info[:25] + '...'
                
                # Get service count
                services = hm.get_host_services(hid)
                svc_count = f"{len(services)}" if services else "0"
                
                # Color code by status
                status = host.get('status', 'unknown')
                if status == 'up':
                    status_marker = click.style('●', fg='green')
                elif status == 'down':
                    status_marker = click.style('●', fg='red')
                else:
                    status_marker = click.style('●', fg='yellow')

                row = f"  │ {selected:^1} │ {str(hid):<4}│ {status_marker} {ip:<14}│ {hostname:<24} │ {os_info:<28} │ {svc_count:^8} │"
                click.echo(row)

            # Bottom border
            click.echo("  └───┴─────┴─────────────────┴──────────────────────────┴──────────────────────────────┴──────────┘")

            if len(hosts) > 25:
                click.echo(f"\n  ... and {len(hosts) - 25} more (use filters to narrow results)")

            if selected_hosts:
                click.echo(f"\n  {click.style(f'Selected: {len(selected_hosts)} host(s)', fg='cyan', bold=True)}")

        # Menu options
        click.echo()
        click.echo("  " + "─" * (width - 4))
        click.echo(click.style("  FILTERS & SEARCH", bold=True))
        click.echo("  " + "─" * (width - 4))
        click.echo()
        click.echo("      " + click.style("[1]", bold=True) + " Search by IP/Hostname")
        click.echo("      " + click.style("[2]", bold=True) + " Filter by Operating System")
        click.echo("      " + click.style("[3]", bold=True) + " Filter by Status (up/down)")
        click.echo("      " + click.style("[4]", bold=True) + " Filter by Tag")
        click.echo("      " + click.style("[5]", bold=True) + " Clear All Filters")
        click.echo()
        click.echo("  " + "─" * (width - 4))
        click.echo(click.style("  ACTIONS", bold=True))
        click.echo("  " + "─" * (width - 4))
        click.echo()
        click.echo("      " + click.style("[6]", bold=True) + " View Host Details")
        click.echo("      " + click.style("[7]", bold=True) + " Select/Deselect Hosts")
        click.echo("      " + click.style("[8]", bold=True) + " Tag Selected Hosts")
        click.echo("      " + click.style("[9]", bold=True) + " Delete Selected Hosts")
        click.echo()
        click.echo("  " + "─" * (width - 4))
        click.echo()
        click.echo("      " + click.style("[0]", bold=True) + " Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("  Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filters['search'] = _hosts_filter_search()
            elif choice == 2:
                filters['os_name'] = _hosts_filter_os()
            elif choice == 3:
                filters['status'] = _hosts_filter_status()
            elif choice == 4:
                filters['tags'] = _hosts_filter_by_tag(engagement_id, hm)
            elif choice == 5:
                # Clear all filters
                filters = {k: None if k != 'status' else 'up' for k in filters}
                click.echo(click.style("  ✓ All filters cleared", fg='green'))
                click.pause()
            elif choice == 6:
                _view_host_details(engagement_id, hm)
            elif choice == 7:
                _hosts_select(hosts, selected_hosts)
            elif choice == 8:
                if selected_hosts:
                    _hosts_tag_selected(engagement_id, hm, selected_hosts)
                else:
                    click.echo(click.style("  ✗ No hosts selected", fg='red'))
                    click.pause()
            elif choice == 9:
                if selected_hosts:
                    _hosts_delete_selected(engagement_id, hm, selected_hosts)
                    selected_hosts.clear()
                else:
                    click.echo(click.style("  ✗ No hosts selected", fg='red'))
                    click.pause()
            else:
                click.echo(click.style("  ✗ Invalid selection!", fg='red'))
                click.pause()

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


def _hosts_filter_by_tag(engagement_id: int, hm: 'HostManager'):
    """Prompt for tag filter."""
    tags = hm.get_all_tags(engagement_id)

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


def _hosts_bulk_remove_tag(selected_hosts: set, hm: 'HostManager', engagement_id: int):
    """Remove tag from selected hosts."""
    tags = hm.get_all_tags(engagement_id)

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




def _view_host_details(engagement_id: int, hm: 'HostManager'):
    """View detailed information about a specific host by ID."""
    try:
        host_id = click.prompt("\n  Enter host ID to view details", type=int)
        host = hm.get_host(host_id)
        
        if not host:
            click.echo(click.style("  ✗ Host not found", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo()
        click.echo("  " + "═" * 76)
        click.echo(click.style(f"  HOST DETAILS - {host.get('ip_address', 'N/A')}", bold=True))
        click.echo("  " + "═" * 76)
        click.echo()

        click.echo(f"  {click.style('ID:', bold=True):<20} {host.get('id')}")
        click.echo(f"  {click.style('IP Address:', bold=True):<20} {host.get('ip_address', 'N/A')}")
        click.echo(f"  {click.style('Hostname:', bold=True):<20} {host.get('hostname') or 'N/A'}")
        click.echo(f"  {click.style('Operating System:', bold=True):<20} {host.get('os_name') or 'N/A'}")
        click.echo(f"  {click.style('MAC Address:', bold=True):<20} {host.get('mac_address') or 'N/A'}")
        
        status = host.get('status', 'unknown')
        status_color = 'green' if status == 'up' else 'red' if status == 'down' else 'yellow'
        click.echo(f"  {click.style('Status:', bold=True):<20} {click.style(status, fg=status_color)}")
        click.echo(f"  {click.style('Tags:', bold=True):<20} {host.get('tags') or 'None'}")

        # Show services
        services = hm.get_host_services(host_id)
        click.echo()
        click.echo(f"  {click.style(f'Services: {len(services)}', bold=True)}")
        
        if services:
            click.echo()
            click.echo(f"  {'Port':<8} {'Protocol':<10} {'Service':<20} {'Version':<30}")
            click.echo("  " + "─" * 76)
            for svc in services[:15]:  # Show first 15
                port = svc.get('port', '?')
                protocol = svc.get('protocol', 'tcp')
                service = (svc.get('service_name') or 'unknown')[:20]
                version = (svc.get('version') or '')[:30]
                click.echo(f"  {port:<8} {protocol:<10} {service:<20} {version:<30}")

            if len(services) > 15:
                click.echo(f"\n  ... and {len(services) - 15} more services")

        click.echo()
        click.pause("  Press any key to return...")
    except (KeyboardInterrupt, click.Abort, ValueError):
        pass


def _hosts_tag_selected(engagement_id: int, hm: 'HostManager', selected_hosts: set):
    """Add tags to selected hosts."""
    try:
        tag = click.prompt("\n  Enter tag to add", type=str).strip()
        if not tag:
            return
        
        for host_id in selected_hosts:
            host = hm.get_host(host_id)
            if host:
                existing_tags = host.get('tags', '')
                tags_list = [t.strip() for t in existing_tags.split(',') if t.strip()] if existing_tags else []
                if tag not in tags_list:
                    tags_list.append(tag)
                    hm.update_host(host_id, {'tags': ','.join(tags_list)})
        
        click.echo(click.style(f"  ✓ Tagged {len(selected_hosts)} host(s) with '{tag}'", fg='green'))
        click.pause()
    except (KeyboardInterrupt, click.Abort):
        pass


def _hosts_delete_selected(engagement_id: int, hm: 'HostManager', selected_hosts: set):
    """Delete selected hosts."""
    if not click.confirm(f"\n  ⚠️  Delete {len(selected_hosts)} host(s)? This cannot be undone!", default=False):
        return
    
    deleted = 0
    for host_id in list(selected_hosts):
        try:
            hm.delete_host(host_id)
            deleted += 1
        except Exception as e:
            click.echo(click.style(f"  ✗ Failed to delete host {host_id}: {e}", fg='red'))
    
    click.echo(click.style(f"  ✓ Deleted {deleted} host(s)", fg='green'))
    click.pause()


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


def _add_new_host(engagement_id: int, hm: 'HostManager'):
    """Add a new host manually."""
    click.clear()
    click.echo("\n" + "=" * 80)
    click.echo("ADD NEW HOST")
    click.echo("=" * 80 + "\n")

    try:
        # IP Address (required)
        ip_address = click.prompt("IP Address", type=str)
        if not ip_address.strip():
            click.echo(click.style("\n✗ IP Address is required!", fg='red'))
            click.pause()
            return

        # Hostname (optional)
        hostname = click.prompt("Hostname (press Enter to skip)", type=str, default="")

        # OS Name (optional)
        os_name = click.prompt("OS Name (press Enter to skip)", type=str, default="")

        # MAC Address (optional)
        mac_address = click.prompt("MAC Address (press Enter to skip)", type=str, default="")

        # Status
        click.echo("\nStatus:")
        click.echo("  [1] Up")
        click.echo("  [2] Down")
        click.echo("  [3] Unknown")
        status_choice = click.prompt("Select status", type=int, default=1)
        status_map = {1: 'up', 2: 'down', 3: 'unknown'}
        status = status_map.get(status_choice, 'up')

        # Tags (optional)
        tags = click.prompt("Tags (comma-separated, press Enter to skip)", type=str, default="")

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("SUMMARY:", bold=True))
        click.echo(f"IP Address: {ip_address}")
        click.echo(f"Hostname: {hostname or 'N/A'}")
        click.echo(f"OS: {os_name or 'N/A'}")
        click.echo(f"MAC Address: {mac_address or 'N/A'}")
        click.echo(f"Status: {status}")
        click.echo(f"Tags: {tags or 'None'}")
        click.echo("-" * 80)

        if not click.confirm("\nAdd this host?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Add to database
        host_data = {
            'ip': ip_address,
            'hostname': hostname or None,
            'os': os_name or None,
            'mac': mac_address or None,
            'status': status,
            'tags': tags or None
        }

        host_id = hm.add_or_update_host(engagement_id, host_data)
        click.echo(click.style(f"\n✓ Host added successfully! (ID: {host_id})", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        click.echo(click.style("\nCancelled.", fg='yellow'))
        click.pause()


def _edit_host(engagement_id: int, hm: 'HostManager'):
    """Edit an existing host."""
    try:
        host_id = click.prompt("\nEnter Host ID to edit", type=int)
        host = hm.get_host(host_id)

        if not host or host.get('engagement_id') != engagement_id:
            click.echo(click.style("\n✗ Host not found or not in current engagement!", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo(f"EDIT HOST #{host_id}")
        click.echo("=" * 80 + "\n")
        click.echo("Press Enter to keep current value\n")

        # Hostname
        current_hostname = host.get('hostname', '')
        hostname = click.prompt(f"Hostname [{current_hostname}]", type=str, default=current_hostname or "")

        # OS Name
        current_os = host.get('os_name', '')
        os_name = click.prompt(f"OS Name [{current_os}]", type=str, default=current_os or "")

        # MAC Address
        current_mac = host.get('mac_address', '')
        mac_address = click.prompt(f"MAC Address [{current_mac}]", type=str, default=current_mac or "")

        # Status
        current_status = host.get('status', 'up')
        click.echo(f"\nCurrent Status: {current_status}")
        click.echo("  [1] Up")
        click.echo("  [2] Down")
        click.echo("  [3] Unknown")
        click.echo("  [0] Keep current")
        status_choice = click.prompt("Select status", type=int, default=0)
        status_map = {1: 'up', 2: 'down', 3: 'unknown'}
        status = status_map.get(status_choice, current_status)

        # Tags
        current_tags = host.get('tags', '')
        tags = click.prompt(f"Tags [{current_tags}]", type=str, default=current_tags or "")

        # Build update dict
        updates = {}
        if hostname != host.get('hostname'):
            updates['hostname'] = hostname or None
        if os_name != host.get('os_name'):
            updates['os_name'] = os_name or None
        if mac_address != host.get('mac_address'):
            updates['mac_address'] = mac_address or None
        if status != host.get('status'):
            updates['status'] = status
        if tags != host.get('tags'):
            updates['tags'] = tags or None

        if not updates:
            click.echo(click.style("\nNo changes made.", fg='yellow'))
            click.pause()
            return

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("CHANGES:", bold=True))
        for key, value in updates.items():
            click.echo(f"  {key}: {value}")
        click.echo("-" * 80)

        if not click.confirm("\nSave changes?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Update database
        hm.update_host(host_id, **updates)
        click.echo(click.style("\n✓ Host updated successfully!", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Host ID!", fg='red'))
        click.pause()


def _delete_hosts(selected_host_ids: set, hm: 'HostManager'):
    """Delete selected hosts."""
    if not selected_host_ids:
        return

    try:
        # Show hosts to be deleted
        click.echo("\n" + "-" * 80)
        click.echo(click.style(f"HOSTS TO DELETE ({len(selected_host_ids)}):", bold=True))
        for host_id in list(selected_host_ids)[:10]:
            host = hm.get_host(host_id)
            if host:
                click.echo(f"  ID {host_id}: {host.get('ip_address')} - {host.get('hostname', 'N/A')}")

        if len(selected_host_ids) > 10:
            click.echo(f"  ... and {len(selected_host_ids) - 10} more")

        click.echo("-" * 80)

        if not click.confirm(click.style(f"\nAre you sure you want to delete {len(selected_host_ids)} host(s)?", fg='red'), default=False):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Delete from database
        deleted_count = 0
        for host_id in selected_host_ids:
            if hm.delete_host(host_id):
                deleted_count += 1

        click.echo(click.style(f"\n✓ Deleted {deleted_count} host(s) successfully!", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return


def view_services(engagement_id: int):
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
                view_services_by_host(engagement_id)
            elif choice == 2:
                view_all_services_filtered(engagement_id)

        except (KeyboardInterrupt, click.Abort):
            return


def view_services_by_host(engagement_id: int):
    """Display services grouped by host."""
    hm = HostManager()
    import re

    while True:
        # Get all hosts with services
        hosts = hm.list_hosts(engagement_id)
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


def view_all_services_filtered(engagement_id: int):
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
            engagement_id,
            service_name=filters['service_name'],
            port_min=filters['port_min'],
            port_max=filters['port_max'],
            protocol=filters['protocol'],
            sort_by=filters['sort_by']
        )

        if not services:
            click.echo("No services found with current filters.")
        else:
            # Table header
            click.echo("  ┌" + "─" * 8 + "┬" + "─" * 9 + "┬" + "─" * 18 + "┬" + "─" * 18 + "┬" + "─" * 35 + "┐")
            header = f"  │ {'Port':<6} │ {'Proto':<7} │ {'Service':<16} │ {'Host':<16} │ {'Version':<33} │"
            click.echo(click.style(header, bold=True))
            click.echo("  ├" + "─" * 8 + "┼" + "─" * 9 + "┼" + "─" * 18 + "┼" + "─" * 18 + "┼" + "─" * 35 + "┤")

            for svc in services[:50]:  # Limit to 50
                port = svc.get('port', '?')
                protocol = (svc.get('protocol') or 'tcp')[:7]
                service = (svc.get('service_name') or 'unknown')[:16]
                host_ip = (svc.get('ip_address') or 'N/A')[:16]

                # Clean version string
                raw_version = svc.get('service_version') or ''
                if raw_version:
                    version = re.sub(r'^(syn-ack|reset|tcp-response)\s+ttl\s+\d+\s*', '', raw_version)
                    version = version[:33] or '-'
                else:
                    version = '-'

                row = f"  │ {port:<6} │ {protocol:<7} │ {service:<16} │ {host_ip:<16} │ {version:<33} │"
                click.echo(row)

            # Bottom border
            click.echo("  └" + "─" * 8 + "┴" + "─" * 9 + "┴" + "─" * 18 + "┴" + "─" * 18 + "┴" + "─" * 35 + "┘")

            if len(services) > 50:
                click.echo(f"\n  ... and {len(services) - 50} more (use filters to narrow results)")
            else:
                click.echo(f"\n  Total: {len(services)} service(s)")

        # Menu options
        click.echo("\n" + "-" * 80)
        click.echo("Filters:")
        click.echo("  [1] Filter by Service Name")
        click.echo("  [2] Filter by Port Range")
        click.echo("  [3] Filter by Protocol")
        click.echo("  [4] Sort by (port/service/protocol)")
        click.echo("  [5] Clear All Filters")
        click.echo("\nManagement:")
        click.echo("  [6] Add New Service")
        click.echo("  [7] Edit Service")
        click.echo("  [8] Delete Service")
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
            elif choice == 6:
                _add_new_service(engagement_id, hm)
            elif choice == 7:
                _edit_service(engagement_id, hm)
            elif choice == 8:
                _delete_service(engagement_id, hm)

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


def _add_new_service(engagement_id: int, hm: 'HostManager'):
    """Add a new service manually."""
    click.clear()
    click.echo("\n" + "=" * 80)
    click.echo("ADD NEW SERVICE")
    click.echo("=" * 80 + "\n")

    try:
        # Host selection
        hosts = hm.list_hosts(engagement_id)

        if not hosts:
            click.echo(click.style("✗ No hosts found. Please add hosts first!", fg='red'))
            click.pause()
            return

        click.echo("Select host:")
        for idx, host in enumerate(hosts[:20], 1):
            click.echo(f"  [{idx}] {host.get('ip_address')} - {host.get('hostname', 'N/A')}")

        host_choice = click.prompt("Select host", type=int)
        if not (1 <= host_choice <= len(hosts)):
            click.echo(click.style("✗ Invalid host selection!", fg='red'))
            click.pause()
            return

        host_id = hosts[host_choice - 1]['id']

        # Port (required)
        port = click.prompt("\nPort", type=int)

        # Service name
        service_name = click.prompt("Service name (e.g., ssh, http, mysql)", type=str, default="")

        # Protocol
        click.echo("\nProtocol:")
        click.echo("  [1] TCP")
        click.echo("  [2] UDP")
        proto_choice = click.prompt("Select protocol", type=int, default=1)
        protocol = 'tcp' if proto_choice == 1 else 'udp'

        # State
        click.echo("\nState:")
        click.echo("  [1] Open")
        click.echo("  [2] Closed")
        click.echo("  [3] Filtered")
        state_choice = click.prompt("Select state", type=int, default=1)
        state_map = {1: 'open', 2: 'closed', 3: 'filtered'}
        state = state_map.get(state_choice, 'open')

        # Version (optional)
        version = click.prompt("\nService version (press Enter to skip)", type=str, default="")

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("SUMMARY:", bold=True))
        click.echo(f"Host: {hosts[host_choice - 1].get('ip_address')}")
        click.echo(f"Port: {port}")
        click.echo(f"Protocol: {protocol}")
        click.echo(f"Service: {service_name or 'unknown'}")
        click.echo(f"State: {state}")
        click.echo(f"Version: {version or 'N/A'}")
        click.echo("-" * 80)

        if not click.confirm("\nAdd this service?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Add to database
        service_data = {
            'port': port,
            'protocol': protocol,
            'service': service_name or 'unknown',
            'state': state,
            'version': version or None
        }

        service_id = hm.add_service(host_id, service_data)
        click.echo(click.style(f"\n✓ Service added successfully! (ID: {service_id})", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        click.echo(click.style("\nCancelled.", fg='yellow'))
        click.pause()
    except ValueError as e:
        click.echo(click.style(f"\n✗ Invalid input: {e}", fg='red'))
        click.pause()


def _edit_service(engagement_id: int, hm: 'HostManager'):
    """Edit an existing service."""
    try:
        service_id = click.prompt("\nEnter Service ID to edit", type=int)

        # Get service - need to search through all services
        all_services = hm.get_all_services(engagement_id)
        service = next((s for s in all_services if s.get('id') == service_id), None)

        if not service:
            click.echo(click.style("\n✗ Service not found!", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo(f"EDIT SERVICE #{service_id}")
        click.echo("=" * 80 + "\n")
        click.echo("Press Enter to keep current value\n")

        # Service name
        current_service = service.get('service_name', '')
        service_name = click.prompt(f"Service name [{current_service}]", type=str, default=current_service or "")

        # State
        current_state = service.get('state', 'open')
        click.echo(f"\nCurrent State: {current_state}")
        click.echo("  [1] Open")
        click.echo("  [2] Closed")
        click.echo("  [3] Filtered")
        click.echo("  [0] Keep current")
        state_choice = click.prompt("Select state", type=int, default=0)
        state_map = {1: 'open', 2: 'closed', 3: 'filtered'}
        state = state_map.get(state_choice, current_state)

        # Version
        current_version = service.get('service_version', '')
        version = click.prompt(f"\nVersion [{current_version}]", type=str, default=current_version or "")

        # Build update dict
        updates = {}
        if service_name != service.get('service_name'):
            updates['service_name'] = service_name or None
        if state != service.get('state'):
            updates['state'] = state
        if version != service.get('service_version'):
            updates['service_version'] = version or None

        if not updates:
            click.echo(click.style("\nNo changes made.", fg='yellow'))
            click.pause()
            return

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("CHANGES:", bold=True))
        for key, value in updates.items():
            click.echo(f"  {key}: {value}")
        click.echo("-" * 80)

        if not click.confirm("\nSave changes?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Update database
        hm.update_service(service_id, **updates)
        click.echo(click.style("\n✓ Service updated successfully!", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Service ID!", fg='red'))
        click.pause()


def _delete_service(engagement_id: int, hm: 'HostManager'):
    """Delete a service."""
    try:
        service_id = click.prompt("\nEnter Service ID to delete", type=int)

        # Get service
        all_services = hm.get_all_services(engagement_id)
        service = next((s for s in all_services if s.get('id') == service_id), None)

        if not service:
            click.echo(click.style("\n✗ Service not found!", fg='red'))
            click.pause()
            return

        # Show service details
        click.echo("\n" + "-" * 80)
        click.echo(click.style("SERVICE TO DELETE:", bold=True))
        click.echo(f"ID: {service.get('id')}")
        click.echo(f"Host: {service.get('ip_address')}")
        click.echo(f"Port: {service.get('port')}")
        click.echo(f"Protocol: {service.get('protocol')}")
        click.echo(f"Service: {service.get('service_name')}")
        click.echo("-" * 80)

        if not click.confirm(click.style("\nAre you sure you want to delete this service?", fg='red'), default=False):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Delete from database
        if hm.delete_service(service_id):
            click.echo(click.style("\n✓ Service deleted successfully!", fg='green'))
        else:
            click.echo(click.style("\n✗ Failed to delete service!", fg='red'))

        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Service ID!", fg='red'))
        click.pause()


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


def view_findings(engagement_id: int):
    """Display findings in engagement with filtering options."""
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
            engagement_id,
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

            # Table header
            click.echo("  ┌" + "─" * 6 + "┬" + "─" * 12 + "┬" + "─" * 22 + "┬" + "─" * 17 + "┬" + "─" * 40 + "┐")
            header = f"  │ {'ID':<4} │ {'Severity':<10} │ {'Type':<20} │ {'Host':<15} │ {'Title':<38} │"
            click.echo(click.style(header, bold=True))
            click.echo("  ├" + "─" * 6 + "┼" + "─" * 12 + "┼" + "─" * 22 + "┼" + "─" * 17 + "┼" + "─" * 40 + "┤")

            for finding in findings[:30]:  # Limit to 30
                fid = finding.get('id', '?')
                sev = finding.get('severity', 'info')
                ftype = (finding.get('finding_type') or 'unknown')[:20]
                host = (finding.get('ip_address') or 'N/A')[:15]
                title = (finding.get('title') or 'No title')[:38]

                # Color code severity
                color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue',
                    'info': 'white'
                }.get(sev, 'white')

                sev_colored = click.style(f"{sev:<10}", fg=color)

                row = f"  │ {fid:<4} │ {sev_colored} │ {ftype:<20} │ {host:<15} │ {title:<38} │"
                click.echo(row)

            # Bottom border
            click.echo("  └" + "─" * 6 + "┴" + "─" * 12 + "┴" + "─" * 22 + "┴" + "─" * 17 + "┴" + "─" * 40 + "┘")

            if len(findings) > 30:
                click.echo(f"\n  ... and {len(findings) - 30} more (use filters to narrow results)")

        # Menu options
        click.echo("\n" + "-" * 80)
        click.echo("Filter Options:")
        click.echo("  [1] Filter by Severity")
        click.echo("  [2] Filter by Type")
        click.echo("  [3] Filter by Tool")
        click.echo("  [4] Search (title/description)")
        click.echo("  [5] Filter by IP Address")
        click.echo("  [6] Clear All Filters")
        click.echo()
        click.echo("Management Options:")
        click.echo("  [7] View Finding Details")
        click.echo("  [8] Add New Finding")
        click.echo("  [9] Edit Finding")
        click.echo("  [10] Delete Finding")
        click.echo()
        click.echo("  [0] Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filters['severity'] = _filter_by_severity()
            elif choice == 2:
                filters['finding_type'] = _filter_by_type(engagement_id, fm)
            elif choice == 3:
                filters['tool'] = _filter_by_tool(engagement_id, fm)
            elif choice == 4:
                filters['search'] = _filter_by_search()
            elif choice == 5:
                filters['ip_address'] = _filter_by_ip()
            elif choice == 6:
                filters = {k: None for k in filters}
                click.echo(click.style("✓ All filters cleared", fg='green'))
                click.pause()
            elif choice == 7:
                _view_finding_details(engagement_id, fm)
            elif choice == 8:
                _add_new_finding(engagement_id, fm)
            elif choice == 9:
                _edit_finding(engagement_id, fm)
            elif choice == 10:
                _delete_finding(engagement_id, fm)
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
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


def _filter_by_type(engagement_id: int, fm: 'FindingsManager'):
    """Prompt for finding type filter."""
    types = fm.get_unique_types(engagement_id)

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


def _filter_by_tool(engagement_id: int, fm: 'FindingsManager'):
    """Prompt for tool filter."""
    tools = fm.get_unique_tools(engagement_id)

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


def _view_finding_details(engagement_id: int, fm: 'FindingsManager'):
    """View detailed information about a specific finding."""
    try:
        finding_id = click.prompt("\nEnter Finding ID to view", type=int)
        finding = fm.get_finding(finding_id)

        if not finding or finding.get('engagement_id') != engagement_id:
            click.echo(click.style("\n✗ Finding not found or not in current engagement!", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo("FINDING DETAILS")
        click.echo("=" * 80 + "\n")

        # Display all fields
        click.echo(click.style(f"ID: ", bold=True) + str(finding.get('id')))

        severity = finding.get('severity', 'info')
        sev_color = {'critical': 'red', 'high': 'red', 'medium': 'yellow', 'low': 'blue', 'info': 'white'}.get(severity, 'white')
        click.echo(click.style(f"Severity: ", bold=True) + click.style(severity.upper(), fg=sev_color))

        click.echo(click.style(f"Title: ", bold=True) + (finding.get('title') or 'N/A'))
        click.echo(click.style(f"Type: ", bold=True) + (finding.get('finding_type') or 'N/A'))
        click.echo(click.style(f"Tool: ", bold=True) + (finding.get('tool') or 'N/A'))
        click.echo(click.style(f"Host: ", bold=True) + (finding.get('ip_address') or 'N/A'))

        if finding.get('hostname'):
            click.echo(click.style(f"Hostname: ", bold=True) + finding['hostname'])
        if finding.get('port'):
            click.echo(click.style(f"Port: ", bold=True) + str(finding['port']))
        if finding.get('path'):
            click.echo(click.style(f"Path: ", bold=True) + finding['path'])
        if finding.get('refs'):
            click.echo(click.style(f"References: ", bold=True) + finding['refs'])

        click.echo(click.style(f"\nDescription:", bold=True))
        click.echo(finding.get('description') or 'No description provided.')

        click.echo(click.style(f"\nCreated: ", bold=True) + (finding.get('created_at') or 'N/A'))

        click.pause("\n\nPress any key to continue...")

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Finding ID!", fg='red'))
        click.pause()


def _add_new_finding(engagement_id: int, fm: 'FindingsManager'):
    """Add a new finding manually."""
    from menuscript.storage.hosts import HostManager

    click.clear()
    click.echo("\n" + "=" * 80)
    click.echo("ADD NEW FINDING")
    click.echo("=" * 80 + "\n")

    try:
        # Title (required)
        title = click.prompt("Title", type=str)
        if not title.strip():
            click.echo(click.style("\n✗ Title is required!", fg='red'))
            click.pause()
            return

        # Severity
        click.echo("\nSeverity:")
        click.echo("  [1] Critical")
        click.echo("  [2] High")
        click.echo("  [3] Medium")
        click.echo("  [4] Low")
        click.echo("  [5] Info")
        sev_choice = click.prompt("Select severity", type=int, default=5)
        severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}
        severity = severity_map.get(sev_choice, 'info')

        # Finding type
        finding_type = click.prompt("\nFinding Type (e.g., web_vulnerability, misconfiguration)", type=str, default="")

        # Description
        description = click.prompt("\nDescription (press Enter to skip)", type=str, default="")

        # Host selection
        hm = HostManager()
        hosts = hm.list_hosts(engagement_id)

        host_id = None
        if hosts:
            click.echo("\nSelect host (or press Enter to skip):")
            click.echo("  [0] No host")
            for idx, host in enumerate(hosts[:20], 1):
                click.echo(f"  [{idx}] {host.get('ip_address')} - {host.get('hostname', 'N/A')}")

            host_choice = click.prompt("Select host", type=int, default=0)
            if 1 <= host_choice <= len(hosts):
                host_id = hosts[host_choice - 1]['id']

        # Port
        port_str = click.prompt("\nPort (press Enter to skip)", type=str, default="")
        port = int(port_str) if port_str.isdigit() else None

        # Path
        path = click.prompt("\nPath/URL (press Enter to skip)", type=str, default="")

        # References
        refs = click.prompt("\nReferences/CVE (press Enter to skip)", type=str, default="")

        # Tool
        tool = click.prompt("\nTool (press Enter to skip)", type=str, default="manual")

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("SUMMARY:", bold=True))
        click.echo(f"Title: {title}")
        click.echo(f"Severity: {severity}")
        click.echo(f"Type: {finding_type or 'N/A'}")
        click.echo(f"Description: {description[:50] + '...' if len(description) > 50 else description}")
        click.echo(f"Host: {host_id or 'N/A'}")
        click.echo(f"Port: {port or 'N/A'}")
        click.echo(f"Path: {path or 'N/A'}")
        click.echo(f"References: {refs or 'N/A'}")
        click.echo(f"Tool: {tool or 'manual'}")
        click.echo("-" * 80)

        if not click.confirm("\nAdd this finding?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Add to database
        finding_id = fm.add_finding(
            engagement_id=engagement_id,
            title=title,
            finding_type=finding_type or None,
            severity=severity,
            description=description or None,
            host_id=host_id,
            tool=tool or 'manual',
            refs=refs or None,
            port=port,
            path=path or None
        )

        click.echo(click.style(f"\n✓ Finding added successfully! (ID: {finding_id})", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        click.echo(click.style("\nCancelled.", fg='yellow'))
        click.pause()


def _edit_finding(engagement_id: int, fm: 'FindingsManager'):
    """Edit an existing finding."""
    try:
        finding_id = click.prompt("\nEnter Finding ID to edit", type=int)
        finding = fm.get_finding(finding_id)

        if not finding or finding.get('engagement_id') != engagement_id:
            click.echo(click.style("\n✗ Finding not found or not in current engagement!", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo(f"EDIT FINDING #{finding_id}")
        click.echo("=" * 80 + "\n")
        click.echo("Press Enter to keep current value\n")

        # Title
        current_title = finding.get('title', '')
        title = click.prompt(f"Title [{current_title}]", type=str, default=current_title)

        # Severity
        current_severity = finding.get('severity', 'info')
        click.echo(f"\nCurrent Severity: {current_severity}")
        click.echo("  [1] Critical")
        click.echo("  [2] High")
        click.echo("  [3] Medium")
        click.echo("  [4] Low")
        click.echo("  [5] Info")
        click.echo("  [0] Keep current")
        sev_choice = click.prompt("Select severity", type=int, default=0)
        severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}
        severity = severity_map.get(sev_choice, current_severity)

        # Finding type
        current_type = finding.get('finding_type', '')
        finding_type = click.prompt(f"\nFinding Type [{current_type}]", type=str, default=current_type)

        # Description
        current_desc = finding.get('description', '')
        description = click.prompt(f"\nDescription [{current_desc[:30]}...]", type=str, default=current_desc)

        # Build update dict
        updates = {}
        if title != finding.get('title'):
            updates['title'] = title
        if severity != finding.get('severity'):
            updates['severity'] = severity
        if finding_type != finding.get('finding_type'):
            updates['finding_type'] = finding_type
        if description != finding.get('description'):
            updates['description'] = description

        if not updates:
            click.echo(click.style("\nNo changes made.", fg='yellow'))
            click.pause()
            return

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("CHANGES:", bold=True))
        for key, value in updates.items():
            click.echo(f"  {key}: {value}")
        click.echo("-" * 80)

        if not click.confirm("\nSave changes?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Update database
        if fm.update_finding(finding_id, **updates):
            click.echo(click.style("\n✓ Finding updated successfully!", fg='green'))
        else:
            click.echo(click.style("\n✗ Failed to update finding!", fg='red'))

        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Finding ID!", fg='red'))
        click.pause()


def _delete_finding(engagement_id: int, fm: 'FindingsManager'):
    """Delete a finding."""
    try:
        finding_id = click.prompt("\nEnter Finding ID to delete", type=int)
        finding = fm.get_finding(finding_id)

        if not finding or finding.get('engagement_id') != engagement_id:
            click.echo(click.style("\n✗ Finding not found or not in current engagement!", fg='red'))
            click.pause()
            return

        # Show finding details
        click.echo("\n" + "-" * 80)
        click.echo(click.style("FINDING TO DELETE:", bold=True))
        click.echo(f"ID: {finding.get('id')}")
        click.echo(f"Title: {finding.get('title')}")
        click.echo(f"Severity: {finding.get('severity')}")
        click.echo(f"Type: {finding.get('finding_type', 'N/A')}")
        click.echo("-" * 80)

        if not click.confirm(click.style("\nAre you sure you want to delete this finding?", fg='red'), default=False):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Delete from database
        if fm.delete_finding(finding_id):
            click.echo(click.style("\n✓ Finding deleted successfully!", fg='green'))
        else:
            click.echo(click.style("\n✗ Failed to delete finding!", fg='red'))

        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Finding ID!", fg='red'))
        click.pause()


def view_credentials(engagement_id: int):
    """Display and manage credentials in engagement."""
    from menuscript.storage.credentials import CredentialsManager

    cm = CredentialsManager()

    # Active filters
    filters = {
        'service': None,
        'status': None,
        'host_id': None
    }

    while True:
        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo("CREDENTIALS")
        click.echo("=" * 80 + "\n")

        # Show active filters
        active_filters = [f"{k}: {v}" for k, v in filters.items() if v]
        if active_filters:
            click.echo(click.style("Active Filters: ", bold=True) + ", ".join(active_filters))
            click.echo()

        # Get credentials with filters
        credentials = cm.list_credentials(
            engagement_id,
            host_id=filters['host_id'],
            service=filters['service'],
            status=filters['status']
        )

        if not credentials:
            click.echo("No credentials found with current filters.")
        else:
            # Show summary
            stats = cm.get_stats(engagement_id)
            click.echo("Summary:")
            click.echo(f"  Total:         {stats['total']}")
            click.echo(f"  Valid:         " + click.style(str(stats['valid']), fg='green'))
            click.echo(f"  Username only: {stats['users_only']}")
            click.echo(f"  Password only: {stats['passwords_only']}")
            click.echo(f"  Full pairs:    {stats['pairs']}")
            click.echo()

            # Table header
            click.echo("  ┌" + "─" * 6 + "┬" + "─" * 17 + "┬" + "─" * 12 + "┬" + "─" * 22 + "┬" + "─" * 22 + "┬" + "─" * 10 + "┐")
            header = f"  │ {'ID':<4} │ {'Host':<15} │ {'Service':<10} │ {'Username':<20} │ {'Password':<20} │ {'Status':<8} │"
            click.echo(click.style(header, bold=True))
            click.echo("  ├" + "─" * 6 + "┼" + "─" * 17 + "┼" + "─" * 12 + "┼" + "─" * 22 + "┼" + "─" * 22 + "┼" + "─" * 10 + "┤")

            for cred in credentials[:30]:  # Limit to 30
                cid = cred.get('id', '?')
                host = (cred.get('ip_address') or 'N/A')[:15]
                service = (cred.get('service') or 'N/A')[:10]
                username = (cred.get('username') or '-')[:20]
                password = (cred.get('password') or '-')[:20]
                status = cred.get('status', 'unknown')[:8]

                # Color code status
                status_color = {
                    'valid': 'green',
                    'invalid': 'red',
                    'untested': 'yellow',
                    'discovered': 'cyan'
                }.get(status, 'white')

                status_colored = click.style(f"{status:<8}", fg=status_color)

                row = f"  │ {cid:<4} │ {host:<15} │ {service:<10} │ {username:<20} │ {password:<20} │ {status_colored} │"
                click.echo(row)

            # Bottom border
            click.echo("  └" + "─" * 6 + "┴" + "─" * 17 + "┴" + "─" * 12 + "┴" + "─" * 22 + "┴" + "─" * 22 + "┴" + "─" * 10 + "┘")

            if len(credentials) > 30:
                click.echo(f"\n  ... and {len(credentials) - 30} more (use filters to narrow results)")

        # Menu options
        click.echo("\n" + "-" * 80)
        click.echo("Filter Options:")
        click.echo("  [1] Filter by Service")
        click.echo("  [2] Filter by Status")
        click.echo("  [3] Filter by Host")
        click.echo("  [4] Clear All Filters")
        click.echo()
        click.echo("Management Options:")
        click.echo("  [5] View Credential Details")
        click.echo("  [6] Add New Credential")
        click.echo("  [7] Edit Credential")
        click.echo("  [8] Delete Credential")
        click.echo("  [9] Test Credentials")
        click.echo()
        click.echo("  [0] Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filters['service'] = _filter_credential_by_service(engagement_id, cm)
            elif choice == 2:
                filters['status'] = _filter_credential_by_status()
            elif choice == 3:
                filters['host_id'] = _filter_credential_by_host(engagement_id)
            elif choice == 4:
                filters = {k: None for k in filters}
                click.echo(click.style("✓ All filters cleared", fg='green'))
                click.pause()
            elif choice == 5:
                _view_credential_details(engagement_id, cm)
            elif choice == 6:
                _add_new_credential(engagement_id, cm)
            elif choice == 7:
                _edit_credential(engagement_id, cm)
            elif choice == 8:
                _delete_credential(engagement_id, cm)
            elif choice == 9:
                test_credentials_menu()
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def _filter_credential_by_service(engagement_id: int, cm: 'CredentialsManager'):
    """Prompt for service filter."""
    credentials = cm.list_credentials(engagement_id)
    services = sorted(set([c.get('service') for c in credentials if c.get('service')]))

    if not services:
        click.echo(click.style("\nNo services found in credentials.", fg='yellow'))
        click.pause()
        return None

    click.echo("\nAvailable services:")
    click.echo("  [0] Clear filter")
    for idx, svc in enumerate(services, 1):
        click.echo(f"  [{idx}] {svc}")

    try:
        choice = click.prompt("Select service", type=int, default=0)
        if 1 <= choice <= len(services):
            return services[choice - 1]
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _filter_credential_by_status():
    """Prompt for status filter."""
    click.echo("\nSelect status:")
    click.echo("  [1] Valid")
    click.echo("  [2] Invalid")
    click.echo("  [3] Untested")
    click.echo("  [4] Discovered")
    click.echo("  [0] Clear filter")

    try:
        choice = click.prompt("Status", type=int, default=0)
        status_map = {1: 'valid', 2: 'invalid', 3: 'untested', 4: 'discovered'}
        return status_map.get(choice)
    except (KeyboardInterrupt, click.Abort):
        return None


def _filter_credential_by_host(engagement_id: int):
    """Prompt for host filter."""
    from menuscript.storage.hosts import HostManager
    hm = HostManager()
    hosts = hm.list_hosts(engagement_id)

    if not hosts:
        click.echo(click.style("\nNo hosts found.", fg='yellow'))
        click.pause()
        return None

    click.echo("\nSelect host:")
    click.echo("  [0] Clear filter")
    for idx, host in enumerate(hosts[:20], 1):
        click.echo(f"  [{idx}] {host.get('ip_address')} - {host.get('hostname', 'N/A')}")

    try:
        choice = click.prompt("Host", type=int, default=0)
        if 1 <= choice <= len(hosts):
            return hosts[choice - 1]['id']
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _view_credential_details(engagement_id: int, cm: 'CredentialsManager'):
    """View detailed information about a specific credential."""
    try:
        cred_id = click.prompt("\nEnter Credential ID to view", type=int)
        credentials = cm.list_credentials(engagement_id)
        credential = next((c for c in credentials if c.get('id') == cred_id), None)

        if not credential:
            click.echo(click.style("\n✗ Credential not found!", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo("CREDENTIAL DETAILS")
        click.echo("=" * 80 + "\n")

        # Display all fields
        click.echo(click.style(f"ID: ", bold=True) + str(credential.get('id')))
        click.echo(click.style(f"Host: ", bold=True) + (credential.get('ip_address') or 'N/A'))

        if credential.get('hostname'):
            click.echo(click.style(f"Hostname: ", bold=True) + credential['hostname'])

        click.echo(click.style(f"Service: ", bold=True) + (credential.get('service') or 'N/A'))
        click.echo(click.style(f"Port: ", bold=True) + str(credential.get('port') or 'N/A'))
        click.echo(click.style(f"Protocol: ", bold=True) + (credential.get('protocol') or 'tcp'))
        click.echo(click.style(f"Username: ", bold=True) + (credential.get('username') or 'N/A'))
        click.echo(click.style(f"Password: ", bold=True) + (credential.get('password') or 'N/A'))

        status = credential.get('status', 'unknown')
        status_color = {'valid': 'green', 'invalid': 'red', 'untested': 'yellow'}.get(status, 'white')
        click.echo(click.style(f"Status: ", bold=True) + click.style(status, fg=status_color))

        click.echo(click.style(f"Type: ", bold=True) + (credential.get('credential_type') or 'user'))
        click.echo(click.style(f"Tool: ", bold=True) + (credential.get('tool') or 'N/A'))
        click.echo(click.style(f"Created: ", bold=True) + (credential.get('created_at') or 'N/A'))

        click.pause("\n\nPress any key to continue...")

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Credential ID!", fg='red'))
        click.pause()


def _add_new_credential(engagement_id: int, cm: 'CredentialsManager'):
    """Add a new credential manually."""
    from menuscript.storage.hosts import HostManager

    click.clear()
    click.echo("\n" + "=" * 80)
    click.echo("ADD NEW CREDENTIAL")
    click.echo("=" * 80 + "\n")

    try:
        # Host selection
        hm = HostManager()
        hosts = hm.list_hosts(engagement_id)

        if not hosts:
            click.echo(click.style("✗ No hosts found. Please add hosts first!", fg='red'))
            click.pause()
            return

        click.echo("Select host:")
        for idx, host in enumerate(hosts[:20], 1):
            click.echo(f"  [{idx}] {host.get('ip_address')} - {host.get('hostname', 'N/A')}")

        host_choice = click.prompt("Select host", type=int)
        if not (1 <= host_choice <= len(hosts)):
            click.echo(click.style("✗ Invalid host selection!", fg='red'))
            click.pause()
            return

        host_id = hosts[host_choice - 1]['id']

        # Service
        service = click.prompt("\nService (e.g., ssh, smb, mysql)", type=str)

        # Port
        port = click.prompt("Port", type=int)

        # Username
        username = click.prompt("Username", type=str, default="")

        # Password
        password = click.prompt("Password", type=str, default="")

        if not username and not password:
            click.echo(click.style("\n✗ Must provide at least username or password!", fg='red'))
            click.pause()
            return

        # Protocol
        protocol = click.prompt("Protocol (tcp/udp)", type=str, default="tcp")

        # Status
        click.echo("\nStatus:")
        click.echo("  [1] Untested")
        click.echo("  [2] Valid")
        click.echo("  [3] Invalid")
        status_choice = click.prompt("Select status", type=int, default=1)
        status_map = {1: 'untested', 2: 'valid', 3: 'invalid'}
        status = status_map.get(status_choice, 'untested')

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("SUMMARY:", bold=True))
        click.echo(f"Host: {hosts[host_choice - 1].get('ip_address')}")
        click.echo(f"Service: {service}")
        click.echo(f"Port: {port}")
        click.echo(f"Username: {username or 'N/A'}")
        click.echo(f"Password: {password or 'N/A'}")
        click.echo(f"Protocol: {protocol}")
        click.echo(f"Status: {status}")
        click.echo("-" * 80)

        if not click.confirm("\nAdd this credential?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Add to database
        cred_id = cm.add_credential(
            engagement_id=engagement_id,
            host_id=host_id,
            username=username or None,
            password=password or None,
            service=service,
            port=port,
            protocol=protocol,
            status=status,
            tool='manual'
        )

        click.echo(click.style(f"\n✓ Credential added successfully! (ID: {cred_id})", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        click.echo(click.style("\nCancelled.", fg='yellow'))
        click.pause()


def _edit_credential(engagement_id: int, cm: 'CredentialsManager'):
    """Edit an existing credential."""
    try:
        cred_id = click.prompt("\nEnter Credential ID to edit", type=int)
        credentials = cm.list_credentials(engagement_id)
        credential = next((c for c in credentials if c.get('id') == cred_id), None)

        if not credential:
            click.echo(click.style("\n✗ Credential not found!", fg='red'))
            click.pause()
            return

        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo(f"EDIT CREDENTIAL #{cred_id}")
        click.echo("=" * 80 + "\n")
        click.echo("Press Enter to keep current value\n")

        # Username
        current_username = credential.get('username', '')
        username = click.prompt(f"Username [{current_username}]", type=str, default=current_username or "")

        # Password
        current_password = credential.get('password', '')
        password = click.prompt(f"Password [{current_password}]", type=str, default=current_password or "")

        # Status
        current_status = credential.get('status', 'untested')
        click.echo(f"\nCurrent Status: {current_status}")
        click.echo("  [1] Untested")
        click.echo("  [2] Valid")
        click.echo("  [3] Invalid")
        click.echo("  [0] Keep current")
        status_choice = click.prompt("Select status", type=int, default=0)
        status_map = {1: 'untested', 2: 'valid', 3: 'invalid'}
        status = status_map.get(status_choice, current_status)

        # Build update
        updates = {}
        if username != credential.get('username'):
            updates['username'] = username or None
        if password != credential.get('password'):
            updates['password'] = password or None
        if status != credential.get('status'):
            updates['status'] = status

        if not updates:
            click.echo(click.style("\nNo changes made.", fg='yellow'))
            click.pause()
            return

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("CHANGES:", bold=True))
        for key, value in updates.items():
            click.echo(f"  {key}: {value}")
        click.echo("-" * 80)

        if not click.confirm("\nSave changes?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Update database using the private method
        cm._update_credential(cred_id, **updates)
        click.echo(click.style("\n✓ Credential updated successfully!", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Credential ID!", fg='red'))
        click.pause()


def _delete_credential(engagement_id: int, cm: 'CredentialsManager'):
    """Delete a credential."""
    try:
        cred_id = click.prompt("\nEnter Credential ID to delete", type=int)
        credentials = cm.list_credentials(engagement_id)
        credential = next((c for c in credentials if c.get('id') == cred_id), None)

        if not credential:
            click.echo(click.style("\n✗ Credential not found!", fg='red'))
            click.pause()
            return

        # Show credential details
        click.echo("\n" + "-" * 80)
        click.echo(click.style("CREDENTIAL TO DELETE:", bold=True))
        click.echo(f"ID: {credential.get('id')}")
        click.echo(f"Host: {credential.get('ip_address')}")
        click.echo(f"Service: {credential.get('service')}")
        click.echo(f"Username: {credential.get('username') or 'N/A'}")
        click.echo(f"Password: {credential.get('password') or 'N/A'}")
        click.echo("-" * 80)

        if not click.confirm(click.style("\nAre you sure you want to delete this credential?", fg='red'), default=False):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Delete from database
        conn = cm.db.get_connection()
        conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        conn.commit()
        conn.close()

        click.echo(click.style("\n✓ Credential deleted successfully!", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Credential ID!", fg='red'))
        click.pause()


def view_osint(engagement_id: int):
    """Display and manage OSINT data in engagement."""
    om = OsintManager()

    # Active filter
    filter_type = None

    while True:
        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo("OSINT DATA")
        click.echo("=" * 80 + "\n")

        # Show active filter
        if filter_type:
            click.echo(click.style(f"Active Filter: Type = {filter_type}", bold=True))
            click.echo()

        # Get data with filter
        all_data = om.list_osint_data(engagement_id, data_type=filter_type)

        if not all_data:
            click.echo("No OSINT data found with current filters.")
        else:
            # Group by type
            by_type = {}
            for item in all_data:
                dtype = item.get('data_type', 'unknown')
                if dtype not in by_type:
                    by_type[dtype] = []
                by_type[dtype].append(item)

            click.echo(f"Total records: {len(all_data)}\n")

            for dtype in sorted(by_type.keys()):
                items = by_type[dtype]
                click.echo(click.style(f"{dtype.upper()} ({len(items)})", bold=True, fg='cyan'))
                click.echo("-" * 80)

                # Table header
                click.echo(f"  {'ID':<6} {'Value':<50} {'Source':<20}")
                click.echo("  " + "-" * 78)

                for item in items[:20]:  # Limit to 20 per type
                    item_id = item.get('id', '?')
                    value = (item.get('value', 'N/A'))[:50]
                    source = (item.get('source', 'unknown'))[:20]
                    click.echo(f"  {item_id:<6} {value:<50} {source:<20}")

                if len(items) > 20:
                    click.echo(f"  ... and {len(items) - 20} more")

                click.echo()

        # Menu options
        click.echo("-" * 80)
        click.echo("Options:")
        click.echo("  [1] Filter by Type")
        click.echo("  [2] Clear Filter")
        click.echo("  [3] Add New OSINT Data")
        click.echo("  [4] Delete OSINT Data")
        click.echo("  [0] Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filter_type = _filter_osint_by_type(engagement_id, om)
            elif choice == 2:
                filter_type = None
                click.echo(click.style("✓ Filter cleared", fg='green'))
                click.pause()
            elif choice == 3:
                _add_new_osint_data(engagement_id, om)
            elif choice == 4:
                _delete_osint_data(engagement_id, om)
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def _filter_osint_by_type(engagement_id: int, om: 'OsintManager'):
    """Prompt for OSINT data type filter."""
    all_data = om.list_osint_data(engagement_id)
    types = sorted(set([item.get('data_type') for item in all_data if item.get('data_type')]))

    if not types:
        click.echo(click.style("\nNo data types found.", fg='yellow'))
        click.pause()
        return None

    click.echo("\nAvailable types:")
    click.echo("  [0] Clear filter")
    for idx, dtype in enumerate(types, 1):
        click.echo(f"  [{idx}] {dtype}")

    try:
        choice = click.prompt("Select type", type=int, default=0)
        if 1 <= choice <= len(types):
            return types[choice - 1]
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _add_new_osint_data(engagement_id: int, om: 'OsintManager'):
    """Add new OSINT data manually."""
    click.clear()
    click.echo("\n" + "=" * 80)
    click.echo("ADD NEW OSINT DATA")
    click.echo("=" * 80 + "\n")

    try:
        # Data type
        click.echo("Common types: email, domain, subdomain, username, ip, phone, leak")
        data_type = click.prompt("\nData Type", type=str)

        # Value
        value = click.prompt("Value (e.g., user@example.com, example.com)", type=str)

        # Source
        source = click.prompt("Source (e.g., theHarvester, manual, leak-site)", type=str, default="manual")

        # Additional info (optional)
        additional_info = click.prompt("Additional Info (press Enter to skip)", type=str, default="")

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("SUMMARY:", bold=True))
        click.echo(f"Type: {data_type}")
        click.echo(f"Value: {value}")
        click.echo(f"Source: {source}")
        click.echo(f"Additional Info: {additional_info or 'N/A'}")
        click.echo("-" * 80)

        if not click.confirm("\nAdd this OSINT data?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Add to database
        osint_id = om.add_osint_data(
            engagement_id=engagement_id,
            data_type=data_type,
            value=value,
            source=source,
            additional_info=additional_info or None
        )

        click.echo(click.style(f"\n✓ OSINT data added successfully! (ID: {osint_id})", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        click.echo(click.style("\nCancelled.", fg='yellow'))
        click.pause()


def _delete_osint_data(engagement_id: int, om: 'OsintManager'):
    """Delete OSINT data."""
    try:
        osint_id = click.prompt("\nEnter OSINT Data ID to delete", type=int)

        # Get the data
        all_data = om.list_osint_data(engagement_id)
        osint = next((item for item in all_data if item.get('id') == osint_id), None)

        if not osint:
            click.echo(click.style("\n✗ OSINT data not found!", fg='red'))
            click.pause()
            return

        # Show details
        click.echo("\n" + "-" * 80)
        click.echo(click.style("OSINT DATA TO DELETE:", bold=True))
        click.echo(f"ID: {osint.get('id')}")
        click.echo(f"Type: {osint.get('data_type')}")
        click.echo(f"Value: {osint.get('value')}")
        click.echo(f"Source: {osint.get('source')}")
        click.echo("-" * 80)

        if not click.confirm(click.style("\nAre you sure you want to delete this OSINT data?", fg='red'), default=False):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Delete from database
        if om.delete_osint_data(osint_id):
            click.echo(click.style("\n✓ OSINT data deleted successfully!", fg='green'))
        else:
            click.echo(click.style("\n✗ Failed to delete OSINT data!", fg='red'))

        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid OSINT Data ID!", fg='red'))
        click.pause()


def view_web_paths(engagement_id: int):
    """Display and manage web paths in engagement."""
    hm = HostManager()
    wpm = WebPathsManager()

    # Active filter
    filter_host_id = None

    while True:
        click.clear()
        click.echo("\n" + "=" * 80)
        click.echo("WEB PATHS")
        click.echo("=" * 80 + "\n")

        # Show active filter
        if filter_host_id:
            filter_host = next((h for h in hm.list_hosts(engagement_id) if h['id'] == filter_host_id), None)
            if filter_host:
                click.echo(click.style(f"Active Filter: Host {filter_host.get('ip_address')}", bold=True))
                click.echo()

        # Get paths
        if filter_host_id:
            all_paths = wpm.list_web_paths(host_id=filter_host_id)
        else:
            all_paths = wpm.list_web_paths(engagement_id=engagement_id)

        if not all_paths:
            click.echo("No web paths found.")
        else:
            # Group by host
            paths_by_host = {}
            for path in all_paths:
                host_id = path.get('host_id')
                if host_id not in paths_by_host:
                    paths_by_host[host_id] = []
                paths_by_host[host_id].append(path)

            click.echo(f"Total paths: {len(all_paths)}\n")

            # Display paths grouped by host
            for host_id, paths in paths_by_host.items():
                host_info = next((h for h in hm.list_hosts(engagement_id) if h['id'] == host_id), None)
                host_ip = host_info.get('ip_address', 'Unknown') if host_info else 'Unknown'

                click.echo(click.style(f"Host: {host_ip} ({len(paths)} paths)", bold=True, fg='cyan'))
                click.echo("-" * 80)

                # Table header
                click.echo(f"  {'ID':<6} {'Status':<8} {'URL':<50} {'Size':<10}")
                click.echo("  " + "-" * 78)

                for path in paths[:20]:  # Limit per host
                    path_id = path.get('id', '?')
                    path_url = path.get('url', '/')[:50]
                    status = path.get('status_code', '?')
                    size = path.get('content_length', '?')

                    # Color code status
                    if str(status).startswith('2'):
                        status_colored = click.style(f"{status:<8}", fg='green')
                    elif str(status).startswith('3'):
                        status_colored = click.style(f"{status:<8}", fg='yellow')
                    elif str(status).startswith('4'):
                        status_colored = click.style(f"{status:<8}", fg='red')
                    elif str(status).startswith('5'):
                        status_colored = click.style(f"{status:<8}", fg='magenta')
                    else:
                        status_colored = f"{status:<8}"

                    click.echo(f"  {path_id:<6} {status_colored} {path_url:<50} {size:<10}")

                if len(paths) > 20:
                    click.echo(f"  ... and {len(paths) - 20} more")

                click.echo()

        # Menu options
        click.echo("-" * 80)
        click.echo("Options:")
        click.echo("  [1] Filter by Host")
        click.echo("  [2] Clear Filter")
        click.echo("  [3] Add New Web Path")
        click.echo("  [4] Delete Web Path")
        click.echo("  [0] Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                filter_host_id = _filter_webpath_by_host(engagement_id, hm)
            elif choice == 2:
                filter_host_id = None
                click.echo(click.style("✓ Filter cleared", fg='green'))
                click.pause()
            elif choice == 3:
                _add_new_web_path(engagement_id, hm, wpm)
            elif choice == 4:
                _delete_web_path(engagement_id, wpm)
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def _filter_webpath_by_host(engagement_id: int, hm: 'HostManager'):
    """Prompt for host filter for web paths."""
    hosts = hm.list_hosts(engagement_id)

    if not hosts:
        click.echo(click.style("\nNo hosts found.", fg='yellow'))
        click.pause()
        return None

    click.echo("\nSelect host:")
    click.echo("  [0] Clear filter")
    for idx, host in enumerate(hosts[:20], 1):
        click.echo(f"  [{idx}] {host.get('ip_address')} - {host.get('hostname', 'N/A')}")

    try:
        choice = click.prompt("Host", type=int, default=0)
        if 1 <= choice <= len(hosts):
            return hosts[choice - 1]['id']
        return None
    except (KeyboardInterrupt, click.Abort):
        return None


def _add_new_web_path(engagement_id: int, hm: 'HostManager', wpm: 'WebPathsManager'):
    """Add a new web path manually."""
    click.clear()
    click.echo("\n" + "=" * 80)
    click.echo("ADD NEW WEB PATH")
    click.echo("=" * 80 + "\n")

    try:
        # Host selection
        hosts = hm.list_hosts(engagement_id)

        if not hosts:
            click.echo(click.style("✗ No hosts found. Please add hosts first!", fg='red'))
            click.pause()
            return

        click.echo("Select host:")
        for idx, host in enumerate(hosts[:20], 1):
            click.echo(f"  [{idx}] {host.get('ip_address')} - {host.get('hostname', 'N/A')}")

        host_choice = click.prompt("Select host", type=int)
        if not (1 <= host_choice <= len(hosts)):
            click.echo(click.style("✗ Invalid host selection!", fg='red'))
            click.pause()
            return

        host_id = hosts[host_choice - 1]['id']

        # URL/Path
        url = click.prompt("\nURL or Path (e.g., /admin, https://example.com/api)", type=str)

        # Status code (optional)
        status_str = click.prompt("HTTP Status Code (press Enter to skip)", type=str, default="")
        status_code = int(status_str) if status_str.isdigit() else None

        # Content length (optional)
        size_str = click.prompt("Content Length in bytes (press Enter to skip)", type=str, default="")
        content_length = int(size_str) if size_str.isdigit() else None

        # Confirmation
        click.echo("\n" + "-" * 80)
        click.echo(click.style("SUMMARY:", bold=True))
        click.echo(f"Host: {hosts[host_choice - 1].get('ip_address')}")
        click.echo(f"URL: {url}")
        click.echo(f"Status Code: {status_code or 'N/A'}")
        click.echo(f"Content Length: {content_length or 'N/A'}")
        click.echo("-" * 80)

        if not click.confirm("\nAdd this web path?", default=True):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Add to database
        path_id = wpm.add_web_path(
            host_id=host_id,
            url=url,
            status_code=status_code,
            content_length=content_length
        )

        click.echo(click.style(f"\n✓ Web path added successfully! (ID: {path_id})", fg='green'))
        click.pause()

    except (KeyboardInterrupt, click.Abort):
        click.echo(click.style("\nCancelled.", fg='yellow'))
        click.pause()


def _delete_web_path(engagement_id: int, wpm: 'WebPathsManager'):
    """Delete a web path."""
    try:
        path_id = click.prompt("\nEnter Web Path ID to delete", type=int)
        path = wpm.get_web_path(path_id)

        if not path:
            click.echo(click.style("\n✗ Web path not found!", fg='red'))
            click.pause()
            return

        # Show path details
        click.echo("\n" + "-" * 80)
        click.echo(click.style("WEB PATH TO DELETE:", bold=True))
        click.echo(f"ID: {path.get('id')}")
        click.echo(f"URL: {path.get('url')}")
        click.echo(f"Status: {path.get('status_code', 'N/A')}")
        click.echo(f"Size: {path.get('content_length', 'N/A')}")
        click.echo("-" * 80)

        if not click.confirm(click.style("\nAre you sure you want to delete this web path?", fg='red'), default=False):
            click.echo(click.style("Cancelled.", fg='yellow'))
            click.pause()
            return

        # Delete from database
        if wpm.delete_web_path(path_id):
            click.echo(click.style("\n✓ Web path deleted successfully!", fg='green'))
        else:
            click.echo(click.style("\n✗ Failed to delete web path!", fg='red'))

        click.pause()

    except (KeyboardInterrupt, click.Abort):
        return
    except ValueError:
        click.echo(click.style("\n✗ Invalid Web Path ID!", fg='red'))
        click.pause()


def test_credentials_menu():
    """Interactive credential testing menu."""
    from menuscript.core.credential_tester import CredentialTester
    from menuscript.storage.engagements import EngagementManager

    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("✗ No engagement selected!", fg='red'))
        click.pause()
        return

    engagement_id = current_ws['id']

    click.clear()
    click.echo("\n" + "=" * 80)
    click.echo("TEST CREDENTIALS AGAINST HOSTS")
    click.echo("=" * 80 + "\n")
    
    click.echo(click.style("This will test all credentials with passwords against all active hosts.", fg='cyan'))
    click.echo(click.style("Valid credentials will automatically create Findings.", fg='cyan', bold=True))
    click.echo()

    tester = CredentialTester()
    
    # Quick stats
    creds = tester.cm.list_credentials(engagement_id)
    testable = [c for c in creds if c.get('password')]
    
    click.echo(f"Found {len(creds)} total credentials ({len(testable)} have passwords to test)")
    click.echo()
    
    if not testable:
        click.echo(click.style("No credentials with passwords found to test.", fg='yellow'))
        click.pause("\nPress any key to continue...")
        return
    
    if not click.confirm("Start credential testing?", default=True):
        return
    
    click.echo()
    click.echo(click.style("Testing credentials... This may take a few minutes.", fg='yellow'))
    click.echo()
    
    # Run the tests
    results = tester.test_all_credentials(engagement_id)
    
    # Display results
    click.echo()
    click.echo(click.style("=" * 80, fg='cyan'))
    click.echo(click.style("CREDENTIAL TESTING COMPLETE", bold=True))
    click.echo(click.style("=" * 80, fg='cyan'))
    click.echo()
    click.echo(f"Total Tests:          {results['total_tests']}")
    click.echo(click.style(f"✓ Successful:         {results['successful']}", fg='green', bold=True))
    click.echo(click.style(f"✗ Failed:             {results['failed']}", fg='red'))
    click.echo(click.style(f"📋 Findings Created:  {results['findings_created']}", fg='yellow', bold=True))
    click.echo()
    
    # Show successful authentications
    if results['successful'] > 0:
        click.echo(click.style("Successful Authentications:", bold=True, fg='green'))
        for test in results['results']:
            if test['success']:
                click.echo(f"  ✓ {test['service'].upper()}: credential ID {test['credential_id']} on host ID {test['host_id']}")
        click.echo()
    
    click.pause("Press any key to continue...")



def import_data_menu():
    """Interactive data import menu."""
    from pathlib import Path

    while True:
        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo("IMPORT DATA")
        click.echo("=" * 70 + "\n")

        click.echo("Import data from external sources into the current engagement.\n")

        # Menu options
        click.echo(click.style("IMPORT SOURCES:", bold=True))
        click.echo("  [1] Metasploit Framework (XML export)")
        click.echo("  [2] Nmap (XML export) - Coming soon")
        click.echo("  [3] Nessus (.nessus file) - Coming soon")
        click.echo("  [0] Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select import source", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                _import_msf_data()
            elif choice in [2, 3]:
                click.echo(click.style("\n  ⚠️  This import source is coming soon!", fg='yellow'))
                click.pause("\nPress any key to continue...")
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def _import_msf_data():
    """Import Metasploit Framework data."""
    from menuscript.importers.msf_importer import MSFImporter
    from menuscript.storage.engagements import EngagementManager

    click.echo()
    click.echo(click.style("IMPORT METASPLOIT DATA", bold=True, fg='cyan'))
    click.echo()
    click.echo("Export from MSF console:")
    click.echo("  msf6 > db_export -f xml /path/to/export.xml")
    click.echo()

    # Prompt for file path
    xml_file = click.prompt("Enter path to MSF XML export file", type=str)

    # Check if file exists
    from pathlib import Path
    if not Path(xml_file).exists():
        click.echo(click.style(f"\n✗ File not found: {xml_file}", fg='red'))
        click.pause("\nPress any key to continue...")
        return

    # Ask for verbose output
    verbose = click.confirm("Show detailed import progress?", default=True)

    click.echo()
    click.echo(click.style("🔄 Starting import...", fg='cyan'))
    click.echo()

    # Get current engagement
    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("✗ No engagement selected!", fg='red'))
        click.pause("\nPress any key to continue...")
        return

    engagement_id = current_ws['id']

    # Perform import
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
        click.pause("Press any key to continue...")

    except Exception as e:
        click.echo()
        click.echo(click.style(f"✗ Import failed: {e}", fg='red'))
        if verbose:
            import traceback
            traceback.print_exc()
        click.pause("\nPress any key to continue...")


def manage_reports_menu():
    """Interactive reports management menu."""
    from pathlib import Path
    import os
    import subprocess

    while True:
        click.clear()
        click.echo("\n" + "=" * 70)
        click.echo("MANAGE REPORTS")
        click.echo("=" * 70 + "\n")

        # List existing reports
        reports_dir = Path("reports")
        reports = []

        if reports_dir.exists():
            reports = sorted(reports_dir.glob("*.*"), key=lambda p: p.stat().st_mtime, reverse=True)

        if reports:
            click.echo(click.style(f"Found {len(reports)} report(s):\n", fg='cyan'))

            for idx, rpt in enumerate(reports[:10], 1):
                size = rpt.stat().st_size
                mtime = os.path.getmtime(rpt)
                import datetime
                mtime_str = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                file_type = "HTML" if rpt.suffix == '.html' else "Markdown"

                click.echo(f"  [{idx}] {rpt.name}")
                click.echo(f"      Type: {file_type} | Size: {size:,} bytes | Modified: {mtime_str}")
                click.echo()

            if len(reports) > 10:
                click.echo(f"  ... and {len(reports) - 10} more\n")
        else:
            click.echo(click.style("No reports found.\n", fg='yellow'))

        # Menu options
        click.echo(click.style("OPTIONS:", bold=True))
        click.echo("  [1] Generate New Report")
        click.echo("  [2] View Report (open in browser/editor)")
        click.echo("  [3] Delete Report")
        click.echo("  [4] List All Reports")
        click.echo("  [5] Import Data (Metasploit, Nmap, etc.)")
        click.echo("  [0] Back to Main Menu")
        click.echo()

        try:
            choice = click.prompt("Select option", type=int, default=0)

            if choice == 0:
                return
            elif choice == 1:
                generate_report_menu()
            elif choice == 2:
                if not reports:
                    click.echo(click.style("No reports available to view.", fg='yellow'))
                    click.pause()
                else:
                    _view_report(reports)
            elif choice == 3:
                if not reports:
                    click.echo(click.style("No reports available to delete.", fg='yellow'))
                    click.pause()
                else:
                    _delete_report(reports)
            elif choice == 4:
                _list_all_reports()
            elif choice == 5:
                import_data_menu()
            else:
                click.echo(click.style("Invalid selection!", fg='red'))
                click.pause()

        except (KeyboardInterrupt, click.Abort):
            return


def _view_report(reports: list):
    """View a report by opening it."""
    import subprocess

    click.echo()
    report_num = click.prompt("Enter report number to view (0 to cancel)", type=int, default=0)

    if report_num == 0 or report_num > len(reports):
        return

    selected_report = reports[report_num - 1]

    try:
        if selected_report.suffix == '.html':
            subprocess.run(['xdg-open', str(selected_report)], check=False)
            click.echo(click.style(f"✓ Opening {selected_report.name} in browser...", fg='green'))
        else:
            # Try to open markdown in default editor
            subprocess.run(['xdg-open', str(selected_report)], check=False)
            click.echo(click.style(f"✓ Opening {selected_report.name} in editor...", fg='green'))

        click.pause("\nPress any key to continue...")
    except Exception as e:
        click.echo(click.style(f"✗ Error opening report: {e}", fg='red'))
        click.pause()


def _delete_report(reports: list):
    """Delete a report file."""
    import os

    click.echo()
    report_num = click.prompt("Enter report number to delete (0 to cancel)", type=int, default=0)

    if report_num == 0 or report_num > len(reports):
        return

    selected_report = reports[report_num - 1]

    if click.confirm(f"Are you sure you want to delete '{selected_report.name}'?", default=False):
        try:
            os.remove(selected_report)
            click.echo(click.style(f"✓ Deleted {selected_report.name}", fg='green'))
        except Exception as e:
            click.echo(click.style(f"✗ Error deleting report: {e}", fg='red'))
    else:
        click.echo("Cancelled.")

    click.pause("\nPress any key to continue...")


def _list_all_reports():
    """List all reports with details."""
    from pathlib import Path
    import os
    import datetime

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo("ALL REPORTS")
    click.echo("=" * 70 + "\n")

    reports_dir = Path("reports")

    if not reports_dir.exists():
        click.echo("No reports directory found.")
        click.pause()
        return

    reports = sorted(reports_dir.glob("*.*"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not reports:
        click.echo("No reports found.")
    else:
        for rpt in reports:
            size = rpt.stat().st_size
            mtime = datetime.datetime.fromtimestamp(rpt.stat().st_mtime)
            file_type = "HTML" if rpt.suffix == '.html' else "Markdown"

            click.echo(f"📄 {rpt.name}")
            click.echo(f"   Type: {file_type}")
            click.echo(f"   Size: {size:,} bytes")
            click.echo(f"   Modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo()

    click.pause("Press any key to continue...")


def generate_report_menu():
    """Interactive report generation menu."""
    from menuscript.reporting.generator import ReportGenerator
    from menuscript.storage.engagements import EngagementManager
    import datetime

    em = EngagementManager()
    current_ws = em.get_current()

    if not current_ws:
        click.echo(click.style("No engagement selected!", fg='red'))
        click.pause()
        return

    click.clear()
    click.echo("\n" + "=" * 70)
    click.echo(f"GENERATE REPORT - {current_ws['name']}")
    click.echo("=" * 70 + "\n")

    # Show engagement stats
    stats = em.stats(current_ws['id'])
    click.echo("Engagement summary:")
    click.echo(f"  • Hosts:       {stats['hosts']}")
    click.echo(f"  • Services:    {stats['services']}")
    click.echo(f"  • Findings:    {stats['findings']}")
    click.echo()

    # Report format selection
    click.echo("Select report format:")
    click.echo("  [1] HTML (web browser)")
    click.echo("  [2] Markdown")
    click.echo("  [3] Both")
    click.echo("  [0] Cancel")
    click.echo()

    try:
        format_choice = click.prompt("Format", type=int, default=1)

        if format_choice == 0:
            return

        if format_choice not in [1, 2, 3]:
            click.echo(click.style("Invalid format selection", fg='red'))
            click.pause()
            return

        # Generate report
        click.echo()
        click.echo(click.style("Generating report...", fg='cyan'))

        rg = ReportGenerator(current_ws['id'])
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        engagement_name = current_ws['name']

        generated_files = []

        if format_choice in [1, 3]:  # HTML
            html_filename = f"reports/{engagement_name}_{timestamp}.html"
            rg.generate_html(html_filename)
            generated_files.append(('HTML', html_filename))

        if format_choice in [2, 3]:  # Markdown
            md_filename = f"reports/{engagement_name}_{timestamp}.md"
            rg.generate_markdown(md_filename)
            generated_files.append(('Markdown', md_filename))

        click.echo()
        click.echo(click.style("✓ Report generated successfully!", fg='green', bold=True))
        click.echo()

        for fmt, filename in generated_files:
            import os
            file_size = os.path.getsize(filename)
            click.echo(f"  {fmt} Report:")
            click.echo(f"    File: {filename}")
            click.echo(f"    Size: {file_size:,} bytes")

        click.echo()

        # Ask if user wants to open HTML report
        if format_choice in [1, 3]:
            if click.confirm("Open HTML report in browser?", default=True):
                import subprocess
                html_file = [f for fmt, f in generated_files if fmt == 'HTML'][0]
                try:
                    subprocess.run(['xdg-open', html_file], check=False)
                    click.echo(click.style("✓ Opening report in browser...", fg='green'))
                except Exception as e:
                    click.echo(click.style(f"Could not open browser: {e}", fg='yellow'))

        click.echo()
        click.pause("Press any key to continue...")

    except (KeyboardInterrupt, click.Abort):
        return
    except Exception as e:
        click.echo()
        click.echo(click.style(f"✗ Error generating report: {e}", fg='red'))
        click.pause()


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

        elif action == 'manage_hosts':
            manage_hosts_menu()

        elif action == 'manage_services':
            manage_services_menu()

        elif action == 'manage_findings':
            manage_findings_menu()

        elif action == 'manage_credentials':
            manage_credentials_menu()

        elif action == 'manage_reports':
            manage_reports_menu()

        elif action == 'manage_engagements':
            manage_engagements_menu()

        elif action == 'view_additional_data':
            view_additional_data_menu()

        elif action == 'launch_tool':
            tool_name = result.get('tool')

            # Show tool configuration menu
            job_params = show_tool_menu(tool_name)

            if not job_params:
                continue

            # Check if user wants to go back
            if job_params.get('action') == 'back':
                continue

            # Confirm before launching
            term_width = get_terminal_width()

            click.echo("\n" + "=" * term_width)
            click.echo("CONFIRM JOB".center(term_width))
            click.echo("=" * term_width)
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
