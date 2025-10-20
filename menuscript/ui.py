#!/usr/bin/env python3
# menuscript UI (v0.6.0) — DB-backed history, grouped view, export & rerun
# Notes for learning:
# - History now comes from SQLite via menuscript.storage.db
# - We group by tool, and show ALL entries (no pagination)
# - Export pulls an entry by list index (1-based) in current view

import sys, os
from typing import List, Dict, Any
from .utils import nmap_installed, detect_local_subnet

# Ensure enqueue_job is available for the TUI enqueue flow.
# If the background engine isn't available in this environment, provide a friendly stub
# so the UI can show a controlled error instead of a NameError.
try:
    from .engine.background import enqueue_job
except Exception:
    def enqueue_job(tool, target, args=None, label=None):
        raise RuntimeError("enqueue_job not available in this environment (background engine missing).")
from .engine.background import list_jobs, get_job, start_worker
from .engine.loader import discover_plugins
from .engine.manager import run_scan_sync
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


def handle_gobuster():
    """
    TUI handler to run Gobuster plugin via the manager.
    Prompts for target (URL), extra args (user-provided), and an optional label.
    Requires the user to supply -w <wordlist> in args for Gobuster to run.
    """
    print('\n--- Gobuster (Web Plugin) ---')
    target = prompt('Target (URL) > ')
    if not target:
        print('No target provided; returning.')
        return
    print('\n' + '\033[31m\033[1m' + 'REMINDER: Gobuster will run next — make sure you provided -w <wordlist>. Example: /usr/share/wordlists/dirb/common.txt' + '\033[0m')
    args_raw = prompt('Gobuster args (e.g. dir -u http://example.com -w /path/wordlist -t 10) > ')
    if not args_raw:
        print('No args provided. You must include \' -w <wordlist>\' for Gobuster to run.')
        return
    args = args_raw.split()
    # Basic safety check: require -w (wordlist) in args
    if not any(a == '-w' for a in args):
        print('Gobuster requires a wordlist (-w). Please provide -w <path>. Aborting.')
        return
    label = prompt('Label for this scan (optional) > ')
    print('\\nStarting Gobuster scan — this will run synchronously (wait until it completes).')
    sid = None
    try:
        sid = run_scan_sync('gobuster', target, args, label, save_xml=False)
    except Exception as e:
        print(f'Error launching gobuster: {e}')
        return
    print(f'Scan scheduled/completed with id: {sid}')
    print()

def handle_web_plugins():
    print('\n' + '\033[31m\033[1m' + 'NOTE: Gobuster requires -w <wordlist> to run. Example: /usr/share/wordlists/dirb/common.txt' + '\033[0m')
    """
    Web Plugins submenu (TUI). Keep this minimal: user chooses a plugin to run or Back.
    """
    while True:
        print()
        print('--- Web Plugins ---')
        print('  1) Gobuster')
        print('  b) Back')
        print()
        ch = prompt('Choice > ').strip().lower()
        if ch in ('1','gobuster'):
            handle_gobuster()
        elif ch in ('b','back'):
            return
        else:
            print('Unknown choice. Use 1 or b (back).')


def show_menu():
    detected = detect_local_subnet()
    print_header()
    if detected:
        print(f' 0) Scan my LAN (auto-detect)  [{detected}]')
    else:
        print(' 0) Scan my LAN (auto-detect)  [no subnet detected]')
    print()
    print('Recon Plugins (Network)')
    print('  1) Discovery Scan (ping only)')
    print('  2) Fast Scan')
    print('  3) Full Service/OS Scan')
    print()
    print('Web Plugins')
    print('  7) Web Plugins (Gobuster, etc.)')
    print()
    print('  4) Custom Scan')
    print('  5) History')
    print('  6) Exit')
    print()
    print('System')
    print('  8) Background Jobs')
    print('  9) Network Plugins')
    print()


def run_menu_loop():
    print_banner()
    while True:
        show_menu()
        choice = prompt('Choice > ').strip().lower()
        if choice == '0':
            handle_scan_my_lan()
        elif choice in ('1', '2', '3'):
            handle_preset_choice(choice)
        elif choice == '4':
            handle_custom()
        elif choice == '5':
            history_menu()
        elif choice == '8':
            background_jobs_menu()
        elif choice == '6' or choice.lower() in ('q', 'quit', 'exit'):
            print('Goodbye!')
            sys.exit(0)
        # web plugins (if present) — typically printed as 7 in the menu
        elif choice == '7':
            try:
                from .ui import handle_web_plugins
                handle_web_plugins()
            except Exception:
                # if not present, show message and continue
                print('Web Plugins are not available.')
        # background jobs (system) — printed as 8
        elif choice == '8':
            try:
                # reuse CLI job menu if exposed; fallback to _cmd_jobs via main
                from .main import _cmd_jobs
                _cmd_jobs(['list'])
            except Exception:
                # if a background jobs TUI exists, call it; else notify
                print('Background jobs command not available from TUI.')
        # network plugins (printed as 9)
        elif choice == '9':
            try:
                handle_network_plugins()
            except NameError:
                print('Network plugins are not available.')
        else:
            print('Invalid choice. Try again.\\n')



def _status_icon_txt(s: str) -> str:
    m = {"queued":"● queued","running":"▶ running","done":"✔ done","failed":"✖ failed"}
    return m.get((s or "").lower(), s or "?")

def _print_jobs_grouped():
    # Group order: running -> queued -> done -> failed
    groups = [("running","RUNNING"), ("queued","QUEUED"), ("done","DONE"), ("failed","FAILED")]
    print(" BACKGROUND JOBS")
    print("──────────────────────────────────────────────────────────────────────────────")
    jobs = list_jobs(limit=200)
    if not jobs:
        print(" (no jobs)")
        return
    for key, title in groups:
        subset = [j for j in jobs if (j.get("status") or "").lower() == key]
        if not subset:
            continue
        print(f" {title}")
        print(" ID   TOOL        STATUS      TARGET                          CREATED")
        print(" ───────────────────────────────────────────────────────────────────────────")
        for j in subset:
            st = (j.get("status") or "").lower()
            icon = _status_icon_txt(st)
            print(f"{str(j['id']).ljust(4)} {j['tool'][:10].ljust(10)}  {icon[:10].ljust(10)}  {j['target'][:30].ljust(30)}  {j.get('created_at','')}")
        print()

def _jobs_tail_prompt():
    jid = prompt('Job id to tail > ')
    if not jid or not jid.isdigit():
        print('Invalid job id.')
        return
    j = get_job(int(jid))
    if not j:
        print('Job not found.')
        return
    scan_id = j.get('result_scan_id')
    if not scan_id:
        print('Job has no scan result yet.')
        return
    try:
        from .storage.db import get_scan
        rec = get_scan(scan_id)
        if rec and rec.get('log'):
            try:
                with open(rec['log'], 'r', encoding='utf-8', errors='ignore') as fh:
                    lines = fh.readlines()
                print(''.join(lines[-200:]))
            except Exception as e:
                print('Could not read log file:', e)
        else:
            print('No log path recorded for scan.')
    except Exception as e:
        print('Cannot load scan record:', e)

def handle_background_jobs():
    while True:
        print('\\n--- Background Jobs ---')
        print('  1) View queued jobs')
        print('  2) View running jobs')
        print('  3) View completed jobs')
        print('  4) Tail job log')
        print('  v) View live output')
        print('  5) Start worker')
        print('  6) Stop worker')
        print('  r) Refresh')
        print('  b) Back')
        print()
        ch = prompt('Choice > ').strip().lower()
        if ch in ('1','2','3','r'):
            _print_jobs_grouped()
        elif ch == '4':
            _jobs_tail_prompt()
        elif ch == 'v':
            view_job_live_prompt()
        elif ch == '5':
            print('Run worker:')
            print('  1) Foreground (monitor in this terminal)')
            print('  2) Background (detach)')
            sel = prompt('Choice > ').strip()
            fg = (sel == '1')
            start_worker(detach=(not fg))
            print('Worker started ' + ('(foreground thread).' if fg else '(daemon background thread).'))
        elif ch == '6':
            stop_worker()
            print('Worker stop signal sent.')
        elif ch in ('b','back'):
            return
        else:
            print('Unknown choice.')



# ----------------------------
# Live job output viewer (T3)
# ----------------------------
def view_job_live_prompt():
    """Prompt for a job id and launch the live viewer."""
    jid = prompt('Job id to view live > ')
    if not jid or not jid.isdigit():
        print('Invalid job id.')
        return
    view_job_live(int(jid))

def view_job_live(job_id: int, refresh_interval: float = 1.0, max_lines: int = 300):
    """
    Framed live tail viewer (T3).
    - refresh_interval: seconds between updates
    - max_lines: how many tail lines to show
    Controls:
      q or b + ENTER -> quit viewer and return to job menu
    Implementation notes:
    - tries to locate log path via storage.get_scan(scan_id) if result_scan_id exists
    - falls back to ~/.menuscript/artifacts/<job_id>.log when missing
    """
    import os, sys, time, json, select
    # lookup job record
    j = None
    try:
        j = get_job(job_id)
    except Exception as _e:
        print('Could not load job:', _e)
        return
    if not j:
        print('Job not found.')
        return
    # attempt to find log path
    log_path = None
    scan_id = j.get('result_scan_id')
    if scan_id:
        try:
            from .storage.db import get_scan
            rec = get_scan(scan_id)
            if rec and rec.get('log'):
                log_path = rec.get('log')
        except Exception:
            # ignore, fallback later
            pass
    if not log_path:
        # default fallback
        log_dir = os.path.join(os.path.expanduser('~'), '.menuscript', 'artifacts')
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f'{job_id}.log')
    # viewer loop
    print(f'Opening live view for job {job_id} (log: {log_path}) — press q then ENTER to quit')
    last_size = 0
    try:
        while True:
            # clear screen
            os.system('clear' if os.name == 'posix' else 'cls')
            # header frame
            print('╭' + '─'*74 + '╮')
            title = f' Live Output — Job {job_id} '
            print('│' + title.center(74) + '│')
            print('├' + '─'*74 + '┤')
            # read last lines safely
            lines = []
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding="utf-8", errors="replace") as fh:
                        all_lines = fh.readlines()
                        if len(all_lines) > max_lines:
                            lines = all_lines[-max_lines:]
                        else:
                            lines = all_lines
                else:
                    lines = ['(log file not found yet — waiting for output...)']
            except Exception as e:
                lines = [f'(error reading log: {e})']
            # print content with side padding
            for L in lines:
                # ensure single-line prints (no embedded control sequences)
                L = L.rstrip('\n')
                # clamp to width 74
                if len(L) > 74:
                    L = L[-74:]
                print('│' + L.ljust(74) + '│')
            # footer
            print('├' + '─'*74 + '┤')
            print('│' + f' Press q + ENTER to quit | Refresh every {refresh_interval}s '.ljust(74) + '│')
            print('╰' + '─'*74 + '╯')
            # wait with non-blocking check for input
            # select.select works on POSIX; on Windows this might behave differently.
            sys.stdout.flush()
            rlist, _, _ = select.select([sys.stdin], [], [], refresh_interval)
            if rlist:
                inp = sys.stdin.readline().strip().lower()
                if inp in ('q','b'):
                    break
            # check job status and exit when done (optional)
            try:
                j = get_job(job_id)
                if j and (j.get('status') in ('done','failed')):
                    print('\nJob finished (status: {}). Press ENTER to return.'.format(j.get('status')))
                    # wait for user to press enter
                    _ = sys.stdin.readline()
                    break
            except Exception:
                # ignore and continue
                pass
    except KeyboardInterrupt:
        # ctrl-C behaves like quit
        pass
    finally:
        # small tidy
        print('Exiting live view.')
    print(" 8) Background Jobs")






def _print_plugin_help_block(helpdata: dict):
    """Pretty-print H2 style help for plugin HELP dict."""
    if not helpdata:
        print("No help available for this plugin.")
        return
    print()
    print(helpdata.get("name", "Plugin") )
    print("─" * max(10, len(helpdata.get("name", ""))))
    print("Description:")
    for line in helpdata.get("description","").splitlines():
        print("  " + line)
    print()
    print("Usage:")
    print("  " + helpdata.get("usage",""))
    print()
    if helpdata.get("examples"):
        print("Examples:")
        for ex in helpdata.get("examples",[]):
            print("  " + ex)
        print()
    if helpdata.get("flags"):
        print("Useful Flags:")
        for flag, desc in helpdata.get("flags",[]):
            print(f"  {flag.ljust(18)} {desc}")
        print()
    if helpdata.get("presets"):
        print("Presets:")
        for i, p in enumerate(helpdata.get("presets",[]), start=1):
            print(f"  {i}) {p.get('name')} - {p.get('desc')}")
        print()
    print("Legal:")
    print("  Use only on systems you own or have explicit permission to test.")
    print()

def handle_network_plugins():
    """
    TUI submenu with H2 help + presets + run/enqueue flow.
    """
    try:
        plugins = discover_plugins()
    except Exception as e:
        print("Could not discover plugins:", e)
        return
    net = [p for p in plugins.values() if getattr(p, "category", "") == "network"]
    if not net:
        print("No network plugins discovered.")
        return
    while True:
        print("\\n--- Network Plugins ---")
        for i, p in enumerate(net, start=1):
            print(f"  {i}) {p.name} ({p.tool})")
        print("  h) Help (short)")
        print("  b) Back")
        choice = prompt("Choice > ").strip().lower()
        if not choice:
            continue
        if choice in ("b","back"):
            return
        if choice == "h":
            print("Choose a plugin number to show detailed help.")
            continue
        if not choice.isdigit() or not (1 <= int(choice) <= len(net)):
            print("Invalid choice.")
            continue
        sel = int(choice) - 1
        plugin = net[sel]
        # attempt to read HELP metadata
        helpdata = getattr(plugin, "HELP", None)
        # Plugin submenu: presets / help / custom
        while True:
            print(f"\\n--- {plugin.name} ({plugin.tool}) ---")
            # show presets if available
            presets = []
            if helpdata and helpdata.get("presets"):
                presets = helpdata.get("presets")
                for idx, pdef in enumerate(presets, start=1):
                    print(f"  {idx}) {pdef.get('name')}  - {pdef.get('desc')}")
            print("  c) Custom args")
            print("  h) Full Help")
            print("  b) Back")
            ch = prompt("Choice > ").strip().lower()
            if not ch:
                continue
            if ch in ("b","back"):
                break
            if ch == "h":
                _print_plugin_help_block(helpdata or {})
                continue
            if ch == "c":
                args_raw = prompt("Custom args (e.g. -Tuning 9 -ssl) > ").strip()
                args = args_raw.split() if args_raw else []
            elif ch.isdigit() and presets and (1 <= int(ch) <= len(presets)):
                args = presets[int(ch)-1].get("args",[])
                print("Selected preset args:", " ".join(args))
            else:
                print("Invalid choice.")
                continue

            # confirm label and run/enqueue
            label = prompt("Label (optional) > ").strip()
            mode = prompt("Run now or enqueue? (r/e) [e] > ").strip().lower() or "e"
            if mode.startswith("r"):
                try:
                    rc, logp = plugin.run(target=prompt("Target (enter host/domain/ip) > ").strip(), args=args, label=label)
                    print(f"Run completed rc={rc} log={logp}")
                    try:
                        from .history import add_history_entry
                        add_history_entry(target, args, label or "", logp, "", tool=plugin.tool)
                    except Exception:
                        pass
                except Exception as e:
                    print("Run failed:", e)
            else:
                target = prompt("Target (enter host/domain/ip) > ").strip()
                if not target:
                    print("No target provided. Aborting enqueue.")
                else:
                    try:
                        jid = enqueue_job(plugin.tool, target, args, label)
                        print(f"Enqueued job {jid} for {plugin.tool}")
                    except Exception as e:
                        print("Could not enqueue:", e)
            # after run/enqueue return to plugin submenu
    # end while

# ---- Background Jobs TUI (auto-added) ----
# Provides: list jobs, view details, tail log, start worker
def _format_status(s):
    try:
        if s == 'done':
            return GREEN + 'done' + RESET
        if s == 'running':
            return CYAN + 'running' + RESET
        if s == 'queued':
            return MAG + 'queued' + RESET
        return RED + str(s) + RESET
    except Exception:
        return str(s)

def _print_job_row(j):
    jid = j.get('id')
    tool = j.get('tool') or ''
    target = j.get('target') or ''
    status = _format_status(j.get('status'))
    created = j.get('created_at') or ''
    print(f"{str(jid).ljust(4)} {tool.ljust(10)} {target.ljust(30)} {status.ljust(10)} {created}")

def background_jobs_menu():
    while True:
        print()
        print('='*60)
        print('--- Background Jobs ---')
        print(' 1) List jobs')
        print(' 2) View job details')
        print(' 3) Tail job log')
        print(' 4) Start worker (background)')
        print(' 5) Start worker (foreground)')
        print(' b) Back')
        ch = prompt('Choice > ').strip().lower()
        if ch in ('1','list'):
            jobs = []
            try:
                jobs = list_jobs(limit=200)
            except Exception as e:
                print('Could not load jobs:', e)
                jobs = []
            if not jobs:
                print('No jobs.')
            else:
                print()
                print('ID   Tool       Target                         Status     Created')
                print('-'*80)
                for j in jobs:
                    _print_job_row(j)
                print('-'*80)
        elif ch in ('2','view'):
            jid = prompt('Job ID > ')
            if not jid:
                continue
            try:
                jidn = int(jid)
            except Exception:
                print('Invalid id.')
                continue
            rec = get_job(jidn)
            if not rec:
                print('Job not found.')
                continue
            # pretty print limited fields
            for k in ('id','tool','target','args','label','status','created_at','started_at','finished_at','error','log'):
                print(f"{k}: {rec.get(k)}")
        elif ch in ('3','tail'):
            jid = prompt('Job ID > ')
            if not jid:
                continue
            try:
                jidn = int(jid)
            except Exception:
                print('Invalid id.')
                continue
            rec = get_job(jidn)
            if not rec:
                print('Job not found.')
                continue
            logp = rec.get('log') or ''
            if not logp or not os.path.exists(logp):
                print('Log not found:', logp)
                continue
            try:
                with open(logp, 'r', encoding='utf-8', errors='replace') as fh:
                    lines = fh.readlines()[-200:]
                    print(''.join(lines))
            except Exception as e:
                print('Could not read log:', e)
        elif ch == '4':
            try:
                start_worker(detach=True)
                print('Worker started (background). Check data/logs/worker.log')
            except Exception as e:
                print('Could not start worker:', e)
        elif ch == '5':
            try:
                start_worker(detach=False, fg=True)
            except KeyboardInterrupt:
                print('\nWorker stopped (foreground).')
            except Exception as e:
                print('Could not start worker:', e)
        elif ch in ('b','back'):
            return
        else:
            print('Unknown choice.')
# ---- end Background Jobs TUI ----

