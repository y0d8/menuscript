#!/usr/bin/env python3
"""
Developer utilities for menuscript.

Command: menuscript dev repair
- Detects venv issues, stale metadata, bad sys.path
- Cleans .pyc caches
- Reinstalls editable package
- Verifies installed version and import path
- Prints helpful guidance (no destructive data ops)
"""
from __future__ import annotations
import os, sys, subprocess, shutil
from pathlib import Path

CSI = '\033['; RESET = CSI+'0m'; BOLD = CSI+'1m'; GREEN = CSI+'32m'; RED = CSI+'31m'; CYAN = CSI+'36m'

def _ok(msg): print(GREEN + "✔ " + msg + RESET)
def _info(msg): print(CYAN + "• " + msg + RESET)
def _warn(msg): print(RED + "! " + msg + RESET)

def _run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def dev_repair():
    project = Path.cwd()
    venv = os.environ.get("VIRTUAL_ENV")
    py = shutil.which("python") or sys.executable
    pip = shutil.which("pip") or shutil.which("pip3")

    _info(f"Python: {py}")
    _info(f"Pip:    {pip or 'not found'}")
    _info(f"Venv:   {venv or '(not active)'}")

    # 1) Sanity: are we in the repo root (setup.py present)?
    setup_py = project / "setup.py"
    if not setup_py.exists():
        _warn("setup.py not found in current directory. Run from your project root (e.g., ~/apps/menuscript_app).")
        return 2
    _ok("Project root looks good (setup.py found).")

    # 2) Check import path for menuscript
    try:
        import importlib.util
        spec = importlib.util.find_spec("menuscript")
        _info(f"import find_spec: {spec}")
    except Exception as e:
        _warn(f"find_spec error: {e}")

    # 3) Show currently installed version
    _info("Checking installed version via pip show...")
    show = _run([py, "-m", "pip", "show", "menuscript"])
    print(show.stdout.strip() or "(not installed)")

    # 4) Uninstall any existing install
    _info("Uninstalling any existing 'menuscript'...")
    _run([py, "-m", "pip", "uninstall", "-y", "menuscript"])

    # 5) Clean site-packages leftovers (dist-info + old copies)
    _info("Cleaning old site-packages metadata...")
    site = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    for pat in ("menuscript-*.dist-info", "menuscript"):
        for p in site.glob(pat):
            try:
                if p.is_dir(): shutil.rmtree(p, ignore_errors=True)
                else: p.unlink(missing_ok=True)
            except Exception: pass
    _ok("Site-packages cleanup complete.")

    # 6) Clean .pyc caches in project
    _info("Cleaning .pyc caches in project...")
    for p in project.rglob("__pycache__"):
        shutil.rmtree(p, ignore_errors=True)
    _ok("Bytecode caches cleaned.")

    # 7) Reinstall editable from source
    _info("Reinstalling editable package (pip install -e .)...")
    inst = _run([py, "-m", "pip", "install", "-e", "."])
    print(inst.stdout)

    # 8) Verify version again
    _info("Verifying installed version...")
    show2 = _run([py, "-m", "pip", "show", "menuscript"])
    print(show2.stdout)

    # 9) Verify import location
    try:
        import menuscript
        _ok(f"'menuscript' imports from: {menuscript.__file__}")
    except Exception as e:
        _warn(f"Import failed after reinstall: {e}")
        return 1

    _ok("Dev repair complete. If version still mismatches, ensure no stray pyproject.toml remains and venv is active.")
    return 0
