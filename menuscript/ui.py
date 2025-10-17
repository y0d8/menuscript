#!/usr/bin/env python3
from .scanner import run_nmap
from .history import load_history, add_history_entry
from .utils import nmap_installed, detect_local_subnet
import sys, os

# ANSI colors
CSI = '\033['
RESET = CSI + '0m'
BOLD = CSI + '1m'
GREEN = CSI + '32m'
RED = CSI + '31m'
CYAN = CSI + '36m'
MAG = CSI + '35m'

BANNER = r"""
╔═╗┌─┐┌┬┐┬ ┬  menuscript v0.4.0
║ ║├─┘ │ │ │  y0d8 & S0ul H@ck3r$ — Recon Suite
╚═╝┴   ┴ └─┘
"""

def print_banner():
    os.system('clear')  # always start clean
    print(MAG + BANNER + RESET)
    print(BOLD + 'menuscript — y0d8 & S0ul H@ck3r$ Recon Suite' + RESET)
    print(CYAN + 'Nmap Automation | Clean. Fast. Simple.' + RESET)
    print()
    # Always show disclaimer (per your choice)
    print(RED + 'LEGAL:' + RESET + ' Use only on systems you own or have explicit permission to test.')
    print()

def print_header():
    print('=' * 60)
    print(' menuscript — quick nmap launcher')
    print('=' * 60)
    if not nmap_installed():
        print('WARNING: nmap not found on PATH. Install nmap to run scans.')
    print()

def prompt(text):
    try:
        return input(text).strip()
    except KeyboardInterrupt:
        print('\nReturning to menu.')
        return ''
    except EOFError:
        return ''

def _render_table(per_host):
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

def _ask_show_table(summary):
    if summary and isinstance(summary, dict) and 'per_host' in summary:
        ans = prompt('Show discovery table now? (Y/n) > ').lower()
        if ans in ('', 'y', 'yes'):
            _render_table(summary.get('per_host'))

def _run_and_record(target, args, label):
    xml_choice = prompt('Save XML output? (y/N) > ').lower() in ('y','yes')
    print('\nStarting scan — live output below (ctrl+C to cancel)\n')
    logpath, rc, xmlpath, summary = run_nmap(target, args, label, save_xml=xml_choice)
    add_history_entry(target, args, label, logpath, xmlpath)
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

def handle_preset_choice(choice):
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
    _run_and_record(target, args, label)

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
    _run_and_record(target, args, label)

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
    _run_and_record(subnet, ['-sn'], label or 'lan')

def view_history():
    history = load_history()
    if not history:
        print('No history yet.')
        return
    print('\nRecent scans:')
    for i, e in enumerate(history[:20], start=1):
        a = e.get('args')
        args_str = ' '.join(a) if isinstance(a, list) else (str(a) if a else '')
        xml_mark = ' [xml]' if e.get('xml') else ''
        print(f"{i}) {e.get('ts')} | {e.get('target')} | {args_str} | label={e.get('label')} | log={e.get('log')}{xml_mark}")
    print()

def rerun_from_history():
    history = load_history()
    if not history:
        print('No history to re-run.')
        return
    print('\nSelect a history entry to re-run (or 0 to cancel):')
    max_show = min(len(history), 20)
    for i in range(max_show):
        e = history[i]
        a = e.get('args')
        args_str = ' '.join(a) if isinstance(a, list) else (str(a) if a else '')
        print(f"{i+1}) {e.get('ts')} | {e.get('target')} | {args_str} | label={e.get('label')}")
    print(' 0) Cancel\n')
    sel = prompt('Choice > ')
    if not sel.isdigit():
        print('Invalid choice.')
        return
    idx = int(sel)
    if idx == 0:
        return
    if idx < 1 or idx > max_show:
        print('Out of range.')
        return
    entry = history[idx-1]
    target = entry.get('target') or ''
    a = entry.get('args')
    args = a if isinstance(a, list) else (a.split() if isinstance(a, str) else [])
    label = entry.get('label')
    print(f"\nSelected: target={target}, args={' '.join(args)}, label={label}")
    action = prompt('Run now (r), Edit first (e), or Back (b)? > ').lower()
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
    _run_and_record(target, args, label)

def history_menu():
    while True:
        print('\nHistory Menu:')
        print(' 1) View recent history')
        print(' 2) Re-run previous scan')
        print(' 3) Back')
        print()
        ch = prompt('Choice > ')
        if ch == '1':
            view_history()
        elif ch == '2':
            rerun_from_history()
        elif ch == '3' or ch.lower() in ('b', 'back'):
            return
        else:
            print('Unknown choice.')

def show_menu():
    detected = detect_local_subnet()
    print_header()
    if detected:
        print(f' 0) Scan my LAN (auto-detect)  [{detected}]')
    else:
        print(' 0) Scan my LAN (auto-detect)  [no subnet detected]')
    print(' 1) Discovery Scan (recommended for quick host discovery)')
    print(' 2) Fast Scan (TCP ping + fast port scan)')
    print(' 3) Full Service/OS Scan (noisy; slow)')
    print(' 4) Custom nmap args')
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
        elif choice in ('1','2','3'):
            handle_preset_choice(choice)
        elif choice == '4':
            handle_custom()
        elif choice == '5':
            history_menu()
        elif choice == '6' or choice.lower() in ('q','quit','exit'):
            print('Bye.')
            sys.exit(0)
        else:
            print('Unknown choice. Try again.\n')
