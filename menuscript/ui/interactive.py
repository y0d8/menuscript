#!/usr/bin/env python3
"""
menuscript.ui.interactive - Interactive menu system for tool selection
"""
import click
from typing import Dict, Any, Optional, List
from menuscript.engine.loader import discover_plugins
from menuscript.engine.background import enqueue_job
from menuscript.storage.workspaces import WorkspaceManager


def show_main_menu() -> Optional[str]:
    """Show main tool selection menu and return selected tool name."""
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
    click.echo("MENUSCRIPT - Interactive Tool Launcher")
    click.echo("=" * 70 + "\n")

    # Show current workspace
    wm = WorkspaceManager()
    current_ws = wm.get_current()
    if current_ws:
        click.echo(f"Workspace: {current_ws['name']}\n")
    else:
        click.echo(click.style("⚠ No workspace selected! Use 'menuscript workspace use <name>'", fg='yellow'))
        click.echo()

    # Display tools by category
    tool_list = []
    idx = 1

    for category in sorted(by_category.keys()):
        click.echo(click.style(f"{category.upper()}", bold=True, fg='cyan'))
        click.echo("-" * 70)

        for name, plugin in sorted(by_category[category], key=lambda x: x[0]):
            help_info = getattr(plugin, 'HELP', {})
            desc = help_info.get('description', 'No description')

            click.echo(f"  {idx:2}. {name:<20} - {desc}")
            tool_list.append(name)
            idx += 1

        click.echo()

    click.echo("  0. Exit")
    click.echo()

    # Get user selection
    try:
        choice = click.prompt("Select a tool", type=int, default=0)

        if choice == 0:
            return None

        if 1 <= choice <= len(tool_list):
            return tool_list[choice - 1]
        else:
            click.echo(click.style("Invalid selection!", fg='red'))
            return None

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


def run_interactive_menu():
    """Main interactive menu loop."""
    while True:
        # Show main menu
        tool_name = show_main_menu()

        if not tool_name:
            click.echo("\nGoodbye!")
            break

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

        # Ask to continue
        click.echo()
        if not click.confirm("Launch another job?", default=True):
            click.echo("\nGoodbye!")
            break
