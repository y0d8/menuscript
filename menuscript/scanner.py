#!/usr/bin/env python3
import subprocess, xml.etree.ElementTree as ET
from pathlib import Path
from .utils import SCANS_DIR, ensure_dirs, timestamp_str, join_cmd, nmap_installed
ensure_dirs()

def _make_paths(target, label):
    safe_label = (label.replace(' ', '_') if label else 'scan')
    ts = timestamp_str()
    base = f'nmap_{ts}_{safe_label}_{target.replace("/", "_")}'
    return SCANS_DIR/(base + '.log'), SCANS_DIR/(base + '.xml')

def _parse_nmap_xml_summary(xmlpath: Path):
    try:
        tree = ET.parse(xmlpath)
        root = tree.getroot()
    except Exception:
        return None
    hosts = root.findall('host')
    hosts_total = len(hosts)
    hosts_up = 0
    open_ports = 0
    per_host = []
    for h in hosts:
        addr = None
        a = h.find('address')
        if a is not None:
            addr = a.get('addr')
        st = h.find('status')
        up = (st is not None and st.get('state') == 'up')
        if up: hosts_up += 1
        ports = h.find('ports')
        open_count = 0
        if ports is not None:
            for p in ports.findall('port'):
                state = p.find('state')
                if state is not None and state.get('state') == 'open':
                    open_count += 1
        open_ports += open_count
        per_host.append({'addr': addr, 'up': up, 'open': open_count})
    return {'hosts_total': hosts_total, 'hosts_up': hosts_up, 'open_ports': open_ports, 'per_host': per_host}

def run_nmap(target, nmap_args, label=None, save_xml=False):
    if not nmap_installed():
        raise EnvironmentError('nmap is not installed or not on PATH.')
    logpath, xmlpath = _make_paths(target, label or 'scan')
    cmd = ['nmap'] + list(nmap_args)
    if save_xml:
        cmd += ['-oX', str(xmlpath)]
    cmd += [target]
    with open(logpath, 'w', encoding='utf-8', errors='replace') as lf:
        lf.write(f'$ {join_cmd(cmd)}\\n\\n')
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
        try:
            for line in proc.stdout:
                print(line.rstrip())
                lf.write(line)
        except KeyboardInterrupt:
            proc.terminate()
            proc.wait(timeout=5)
            print('\\n[scan cancelled by user]')
            lf.write('\\n[scan cancelled by user]\\n')
            return logpath, -1, (xmlpath if save_xml else None), None
        rc = proc.wait()
        lf.write(f'\\n# exit_code: {rc}\\n')
    summary = None
    if save_xml and xmlpath.exists():
        summary = _parse_nmap_xml_summary(xmlpath)
    return logpath, rc, (xmlpath if save_xml else None), summary
