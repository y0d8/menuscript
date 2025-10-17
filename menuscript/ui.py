#!/usr/bin/env python3
# menuscript UI (v0.5.0) — DB-backed history, grouped view, export & rerun
# Notes for learning:
# - History now comes from SQLite via menuscript.storage.db
# - We group by tool, and show ALL entries (no pagination)
# - Export pulls an entry by list index (1-based) in current view

import sys, os
from typing import List, Dict, Any
from .utils import nmap_installed, detect_local_subnet
from .scanner import run_nmap
from .storage.db import get_scans, get_scan
# (history.py kept for export helpers if needed in future, not used for reads)

VERSION = "0.5.0"

# ANSI colors
CSI = '\033['
RESET = CSI + '0m'
BOLD = CSI + '1m'
GREEN = CSI + '32m'
RED = CSI + '31m'
CYAN = CSI + '36m'
MAG = CSI + '35m'

# === Branding ===
BANNER = r'''
  ____   ____   _   _    _    ____  _   _  ____  _   _  ____  ____ 
 / ___| / ___| | | | |  / \  / ___|| | | |/ ___|| | | |/ ___||  _ \
 \___ \| |     | |_| | / _ \ \___ \| | | | |  _ | | | | |  _ | |_) |
  ___) | |___  |  _  |/ ___ \ ___) | |_| | |_| || |_| | |_| ||  _ < 
 |____/ \____| |_| |_/_/   \_\____/ \___/ \____| \___/ \____||_| \_\
                                                                  
                         $0u! H@cK3R$
'''
FOOTER = 'y0d8 & CyberSoul SecurITy'

def print_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(MAG + BANNER + RESET)
    print(f"{BOLD}menuscript v{VERSION}{RESET}")
    print(FOOTER)
    print()
    print(RED + 'LEGAL:' + RESET + ' Use only on systems you own or have explicit permission to test.')
    print()

def print_header():
    print('=' * 60)
    print(' menuscript — quick nmap launcher')
    print('=' * 60)
    if not nmap_installed():
        print('WARNING: nmap not found on PATH. Install nmap to run scans.')
    print()

def prompt(text: str) -> str:
    try:
        return input(text).strip()
    except KeyboardInterrupt:
        print('\nReturning to menu.')
        return ''
    except EOFError:
        return ''

# ---- Nmap run & helpers ----

def _render_table(per_host: List[Dict[str, Any]]):
    """Pretty-print discovery results (optional table)."""
    rows = []
    for h in per_host or []:
        addr = h.get('addr') or ''
        state = 'Up' if h.get('up') else 'Down'
        openp = str(h.get('open') or 0)
        rows.append((addr, state, openp))
    if not rows:
        print('No hosts to display.')
        return
    col1 = max([len(r[0]) for r in rows] + [4])
    col2 = max([len(r[1]) for r in rows] + [5])
    col3 = max([len(r[2]) for r in rows] + [10])
    sep = '+' + '-'*(col1+2) + '+' + '-'*(col2+2) + '+' + '-'*(col3+2) + '+'
    header = f'| {"Host".ljust(col1)} | {"State".ljust(col2)} | {"Open Ports".ljust(col3)} |'
    print(sep); print(header); print(sep)
    for addr, state, openp in rows:
        color = GREEN if state == 'Up' else RED
        line = f'| {addr.ljust(col1)} | {state.ljust(col2)} | {openp.rjust(col3)} |'
        print(color + line + RESET)
    print(sep)

def _ask_show_table(summary: Dict[str, Any]):
    if summary and isinstance(summary, dict) and 'per_host' in summary:
        ans = prompt('Show discovery table now? (Y/n) > ').lower()
        if ans in ('', 'y', 'yes'):
            _render_table(summary.get('per_host'))

def _run_and_record_legacy(target: str, args: List[str], label: str, tool="nmap"):
    """
    Temporary: we still use the existing scanner.run_nmap() to run scans and print output.
    Results are written to legacy history.json by scanner.add_history_entry (if used in scanner),
    but the UI reads history from SQLite (manager/db handles DB writes for plugin era).
    """
    xml_choice = prompt('Save XML output? (y/N) > ').lower() in ('y','yes')
    print('\nStarting scan — live output below (ctrl+C to cancel)\n')
    try:
        logpath, rc, xmlpath, summary = run_nmap(target, args, label, save_xml=xml_choice)
    except EnvironmentError as e:
        print(f'Error: {e}')
        return
    print(f'\nScan finished: log saved to {logpath} (rc={rc})')
    if xml_choice and xmlpath:
        print(f'XML saved to: {xmlpath}')
        if summary:
            print('XML Summary:')
            print(f'  Hosts total: {summary.get("hosts_total")}')
            print(f'  Hosts up:    {summary.get("hosts_up")}')
            print(f'  Open ports:  {summary.get("open_ports")}')
            _ask_show_table(summary)
        else:
            print('No XML summary available (parsing failed).')
    print()

PRESETS = {
    '1': ('Discovery Scan (ping only)', ['-sn']),
    '2': ('Fast Scan (-F)', ['-v', '-PS', '-F']),
    '3': ('Service & OS (full)', ['-sV', '-O', '-p1-65535']),
}

def handle_preset_choice(choice: str):
    preset = PRESETS.get(choice)
    if not preset:
        print('Invalid preset.')
        return
    desc, args = preset
    print(f'\nPreset: {desc}\nArgs: {" ".join(args)}')
    target = prompt('Target (IP, host, CIDR) > ')
    if not target:
        print('No target provided. Returning to menu.')
        return
    label = prompt('Label for this scan (optional) > ')
    _run_and_record_legacy(target, args, label, tool="nmap")

def handle_custom():
    raw = prompt('Enter custom nmap args (e.g. -sV -p22-80) > ')
    if not raw:
        print('No args, returning.')
        return
    args = raw.split()
    target = prompt('Target (IP, host, CIDR) > ')
    if not target:
        print('No target provided. Returning to menu.')
        return
    label = prompt('Label for this scan (optional) > ')
    _run_and_record_legacy(target, args, label, tool="nmap")

def handle_scan_my_lan():
    subnet = detect_local_subnet()
    if not subnet:
        print('Could not auto-detect your local subnet. Enter it manually (e.g. 192.168.1.0/24).')
        subnet = prompt('Subnet > ')
        if not subnet:
            print('No subnet provided. Returning to menu.')
            return
    print(f'Using subnet: {subnet}')
    label = prompt('Label for this scan (optional) > ')
    _run_and_record_legacy(subnet, ['-sn'], label or 'lan', tool="nmap")

# ---- DB-backed History (H2) ----

def _group_by_tool(scans: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups = {}
    for s in scans:
        t = (s.get("tool") or "").lower()
        groups.setdefault(t, []).append(s)
    # Newest first inside each tool group
    for k in groups:
        groups[k].sort(key=lambda x: x.get("id", 0), reverse=True)
    return dict(sorted(groups.items(), key=lambda kv: kv[0]))  # alphabetical tool order

def _print_history_list(scans: List[Dict[str, Any]]):
    """Render a flat list of scans with 1-based indices."""
    if not scans:
        print('No history yet.')
        return
    for i, e in enumerate(scans, start=1):
        args_str = ' '.join(e.get('args') or [])
        xml_mark = ' [xml]' if e.get('xml') else ''
        print(f"{i}) {e.get('ts')} | {e.get('tool')} | {e.get('target')} | {args_str} | label={e.get('label')} | log={e.get('log')}{xml_mark}")
    print(f"\nShowing {len(scans)} results   |   Storage: DB mode   |   menuscript v{VERSION}\n")

def history_view_all() -> List[Dict[str, Any]]:
    scans = get_scans(limit=100000, tool=None)  # H-on: show all
    _print_history_list(scans)
    return scans

def history_view_by_tool():
    scans_all = get_scans(limit=100000)
    groups = _group_by_tool(scans_all)
    if not groups:
        print('No history yet.')
        return
    print("\nTools in history:")
    tools = list(groups.keys())
    for i, t in enumerate(tools, start=1):
        print(f" {i}) {t} ({len(groups[t])})")
    print(" 0) Back")
    sel = prompt('Choose tool > ')
    if not sel.isdigit():
        print('Invalid choice.')
        return
    idx = int(sel)
    if idx == 0 or not (1 <= idx <= len(tools)):
        return
    chosen = tools[idx-1]
    print(f"\n=== {chosen} history ===")
    _print_history_list(groups[chosen])

def history_rerun(scans: List[Dict[str, Any]]):
    if not scans:
        print('No history to re-run.')
        return
    sel = prompt('Entry number to re-run (1-based) > ')
    if not sel.isdigit():
        print('Invalid index.')
        return
    idx = int(sel)
    if idx < 1 or idx > len(scans):
        print('Out of range.')
        return
    e = scans[idx-1]
    target = e.get('target') or ''
    args = e.get('args') or []
    label = e.get('label')
    tool = (e.get('tool') or 'nmap').lower()
    print(f"\nSelected: target={target}, args={' '.join(args)}, label={label}, tool={tool}")
    action = prompt('Run now (r), Edit first (e), Back (b) > ').lower()
    if action == 'b':
        return
    if action == 'e':
        new_args_raw = prompt(f"Args [{ ' '.join(args) or '-sn' } ] > ").strip()
        if new_args_raw:
            args = new_args_raw.split()
        new_target = prompt(f"Target [{ target } ] > ").strip()
        if new_target:
            target = new_target
        label = prompt(f"Label [{ label or '' } ] > ").strip() or label
    elif action != 'r':
        print('Unknown choice.')
        return
    # For now, we re-use legacy runner; plugin engine will hook here next
    _run_and_record_legacy(target, args, label, tool=tool)

def history_export(scans: List[Dict[str, Any]]):
    if not scans:
        print('No history to export.')
        return
    fmt = prompt('Format (json/csv) > ').lower()
    if fmt not in ('json','csv'):
        print('Unknown format.')
        return
    sel = prompt('Entry number to export (1-based, ENTER for latest) > ')
    if not sel:
        entry = scans[0]
    elif sel.isdigit():
        idx = int(sel)
        if idx < 1 or idx > len(scans):
            print('Out of range.')
            return
        entry = scans[idx-1]
    else:
        print('Invalid index.')
        return
    # Export using a simple inline writer (avoid legacy)
    from pathlib import Path
    import json, csv
    export_dir = Path.home() / ".menuscript" / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    def safe(s): return "".join(c if (c.isalnum() or c in '._-') else '_' for c in str(s or ''))
    base = f"{safe(entry.get('ts'))}_{safe(entry.get('tool'))}_{safe(entry.get('target'))}"
    if entry.get('label'):
        base += f"_{safe(entry.get('label'))}"
    if fmt == 'json':
        path = export_dir / f"{base}.json"
        with path.open('w', encoding='utf-8') as f:
            json.dump(entry, f, indent=2)
    else:
        path = export_dir / f"{base}.csv"
        per_host = entry.get("per_host") or []
        if not per_host:
            # minimal CSV row when no per_host breakdown
            per_host = [{"addr":"", "up": "", "open": (entry.get("summary") or {}).get("open_ports", 0)}]
        with path.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["timestamp","tool","target","label","host","up","open_ports","log","xml"])
            for h in per_host:
                w.writerow([
                    entry.get("ts",""),
                    entry.get("tool",""),
                    entry.get("target",""),
                    entry.get("label",""),
                    h.get("addr",""),
                    "" if h.get("up") is None else bool(h.get("up")),
                    h.get("open",0),
                    entry.get("log",""),
                    entry.get("xml",""),
                ])
    print(f"Exported {fmt.upper()} to: {path}")

def history_menu():
    while True:
        print('\nHistory Menu:')
        print(' 1) View all history')
        print(' 2) View by tool')
        print(' 3) Re-run scan')
        print(' 4) Export scan')
        print(' 5) Back')
        print()
        choice = prompt('Choice > ')
        if choice == '1':
            scans = history_view_all()
        elif choice == '2':
            history_view_by_tool()
            scans = None
        elif choice == '3':
            scans = history_view_all()
            history_rerun(scans)
        elif choice == '4':
            scans = history_view_all()
            history_export(scans)
        elif choice == '5' or choice.lower() in ('b','back'):
            return
        else:
            print('Unknown choice.')

# ---- Main menu ----

def show_menu():
    print_header()
    detected = detect_local_subnet()
    if detected:
        print(f' 0) Scan my LAN (auto-detect)  [{detected}]')
    else:
        print(' 0) Scan my LAN (auto-detect)  [no subnet detected]')
    print(' 1) Discovery Scan (ping only)')
    print(' 2) Fast Scan')
    print(' 3) Full Service/OS Scan')
    print(' 4) Custom Scan')
    print(' 5) History')
    print(' 6) Exit')
    print()

def run_menu_loop():
    print_banner()
    while True:
        show_menu()
        choice = prompt('Choice > ')
        if choice == '0':
            handle_scan_my_lan()
        elif choice in ('1', '2', '3'):
            handle_preset_choice(choice)
        elif choice == '4':
            handle_custom()
        elif choice == '5':
            history_menu()
        elif choice == '6' or choice.lower() in ('q', 'quit', 'exit'):
            print('Goodbye!')
            sys.exit(0)
        else:
            print('Invalid choice. Try again.\n')
