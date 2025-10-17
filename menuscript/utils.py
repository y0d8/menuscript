#!/usr/bin/env python3
from pathlib import Path
import json, shutil, subprocess, re, platform, ipaddress

APP_DIR = Path.home()/'.menuscript'
SCANS_DIR = APP_DIR/'scans'
HISTORY_FILE = APP_DIR/'recon_history.json'

def ensure_dirs():
    APP_DIR.mkdir(exist_ok=True)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)

def nmap_installed():
    return shutil.which('nmap') is not None

def timestamp_str():
    from datetime import datetime
    return datetime.now().strftime('%Y%m%d-%H%M%S')

def join_cmd(args):
    import shlex
    return ' '.join(shlex.quote(a) for a in args)

def read_json(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
    except Exception:
        return ''

def _hexmask_to_prefix(hexmask):
    try:
        if hexmask.startswith('0x'):
            val = int(hexmask, 16)
            mask_bytes = [(val >> (i*8)) & 0xFF for i in (3,2,1,0)]
            bits = ''.join(f'{b:08b}' for b in mask_bytes)
            return bits.count('1')
    except Exception:
        pass
    return None

def detect_local_subnet():
    system = platform.system().lower()
    cidr = None
    if system == 'linux':
        out = _run(['ip', 'route', 'get', '8.8.8.8'])
        m = re.search(r'src (\S+)', out)
        if m:
            ip_src = m.group(1)
            out2 = _run(['ip','-o','-4','addr','show'])
            m2 = re.search(rf'{re.escape(ip_src)}/(\d+)', out2)
            if m2:
                cidr = f'{ip_src}/{m2.group(1)}'
    else:
        out = _run(['route', '-n', 'get', '8.8.8.8'])
        m = re.search(r'source address: (\S+)', out)
        if m:
            ip_src = m.group(1)
            ic = _run(['ifconfig'])
            m3 = re.search(rf'{re.escape(ip_src)} netmask (0x[0-9a-fA-F]+)', ic)
            if m3:
                prefix = _hexmask_to_prefix(m3.group(1))
                if prefix:
                    cidr = f'{ip_src}/{prefix}'
    if not cidr:
        out3 = _run(['ip','-o','-4','addr','show'])
        m4 = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', out3)
        if m4:
            cidr = f'{m4.group(1)}/{m4.group(2)}'
    if not cidr:
        return None
    try:
        return str(ipaddress.ip_interface(cidr).network)
    except Exception:
        try:
            ip = cidr.split('/')[0]
            return str(ipaddress.ip_network(ip + '/24', strict=False))
        except Exception:
            return None
