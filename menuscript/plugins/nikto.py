from typing import List, Optional, Tuple
import shutil, os, time, subprocess
from .plugin_base import Plugin

class NiktoPlugin(Plugin):
    name = "Nikto HTTP Scanner"
    tool = "nikto"
    category = "network"

    def _find_exe(self) -> Optional[str]:
        return shutil.which("nikto")

    def run(self, target: str, args: List[str], label: Optional[str] = None, save_xml: bool = False) -> Tuple[int, str]:
        exe = self._find_exe()
        if not exe:
            raise RuntimeError("nikto binary not found on PATH")

        cmd = [exe, "-h", target] + (args or [])

        log_dir = os.path.expanduser("~/.menuscript/artifacts")
        os.makedirs(log_dir, exist_ok=True)
        fname = f"nikto_{label or 'scan'}_{int(time.time())}.log"
        log_path = os.path.join(log_dir, fname)

        with open(log_path, "wb") as out:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for chunk in iter(lambda: proc.stdout.read(4096), b""):
                out.write(chunk)
                out.flush()
            rc = proc.wait()
        return rc, log_path

plugin = NiktoPlugin()


# HELP metadata for TUI + CLI help (H2 style)
HELP = {
    "name": "Nikto HTTP Scanner",
    "description": "Nikto is a web server scanner that performs comprehensive tests against web servers for multiple items including dangerous files, outdated software, and misconfigurations.",
    "usage": "menuscript jobs enqueue nikto <target> --args \"<flags>\"",
    "examples": [
        "menuscript jobs enqueue nikto 10.10.10.10 --args \"-Tuning 9\"",
        "menuscript run nikto http://example.com"
    ],
    "flags": [
        ["-Tuning <codes>", "Select test categories (e.g. 1,2,3)"],
        ["-ssl", "Force SSL mode"],
        ["-port <port>", "Specify port"],
        ["-timeout <secs>", "Timeout in seconds"]
    ],
    "presets": [
        {"name":"Quick Scan","args":["-Tuning","1,2"],"desc":"Light, fast checks"},
        {"name":"Full Scan","args":["-Tuning","9"],"desc":"Comprehensive tests (slower)"},
        {"name":"Stealth","args":["-Tuning","1","-timeout","30"],"desc":"Lower noise; shorter timeouts"},
    ]
}

