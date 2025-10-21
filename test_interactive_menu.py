#!/usr/bin/env python3
"""
Test script to verify interactive menu components
"""
from menuscript.engine.loader import discover_plugins
from menuscript.storage.workspaces import WorkspaceManager

def test_plugin_loading():
    """Test that all plugins load correctly."""
    print("Testing plugin loading...")
    plugins = discover_plugins()

    print(f"\nFound {len(plugins)} plugins:")
    for name, plugin in sorted(plugins.items()):
        help_info = getattr(plugin, 'HELP', {})
        category = getattr(plugin, 'category', 'unknown')
        presets = help_info.get('presets', [])
        print(f"  - {name:<15} [{category}] - {len(presets)} presets")

    return plugins


def test_plugin_help(plugins):
    """Test that plugins have HELP info with presets."""
    print("\n\nTesting plugin HELP information...")

    for name, plugin in sorted(plugins.items()):
        help_info = getattr(plugin, 'HELP', {})

        if not help_info:
            print(f"  ✗ {name}: No HELP information")
            continue

        has_name = 'name' in help_info
        has_desc = 'description' in help_info
        has_presets = 'presets' in help_info and len(help_info['presets']) > 0

        status = "✓" if (has_name and has_desc) else "⚠"
        preset_info = f"{len(help_info.get('presets', []))} presets" if has_presets else "no presets"

        print(f"  {status} {name:<15} - {preset_info}")

        # Show preset details
        if has_presets:
            for preset in help_info['presets']:
                print(f"      • {preset.get('name', 'unnamed')}: {preset.get('desc', 'no description')}")


def test_workspace():
    """Test workspace detection."""
    print("\n\nTesting workspace...")
    wm = WorkspaceManager()
    current = wm.get_current()

    if current:
        print(f"  ✓ Current workspace: {current['name']}")
    else:
        print("  ⚠ No workspace selected")
        workspaces = wm.list()
        if workspaces:
            print(f"  Available workspaces: {', '.join([w['name'] for w in workspaces])}")


if __name__ == "__main__":
    print("=" * 70)
    print("INTERACTIVE MENU COMPONENT TEST")
    print("=" * 70)

    plugins = test_plugin_loading()
    test_plugin_help(plugins)
    test_workspace()

    print("\n" + "=" * 70)
    print("Test complete!")
    print("=" * 70)
    print("\nTo test the interactive menu, run:")
    print("  menuscript interactive")
    print()
