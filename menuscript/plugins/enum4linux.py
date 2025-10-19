from typing import List, Optional, Tuple
import shutil, os, time, subprocess
from .plugin_base import Plugin

class Enum4linuxPlugin(Plugin):
    name = "enum4linux (SMB)"
    tool = "enum4linux"
    category = "network"

    def _find_exe(self) -> Optional[str]:
        return shutil.which("enum4linux")

    def run(self, target: str, args: List[str], label: Optional[str] = None, save_xml: bool = False) -> Tuple[int, str]:
        exe = self._find_exe()
        if not exe:
            raise RuntimeError("enum4linux not found on PATH")

        cmd = [exe] + (args or [])
        # ensure target appended if not present
        if target and target not in cmd:
            cmd.append(target)

        log_dir = os.path.expanduser("~/.menuscript/artifacts")
        os.makedirs(log_dir, exist_ok=True)
        fname = f"enum4linux_{label or 'scan'}_{int(time.time())}.log"
        log_path = os.path.join(log_dir, fname)

        with open(log_path, "wb") as out:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for chunk in iter(lambda: proc.stdout.read(4096), b""):
                out.write(chunk)
                out.flush()
            rc = proc.wait()

        return rc, log_path

plugin = Enum4linuxPlugin()


# HELP metadata for TUI + CLI help (H2 style)
HELP = {
    "name": "enum4linux (SMB)",
    "description": "enum4linux is a tool for enumerating information from Windows and Samba systems via SMB.",
    "usage": "menuscript jobs enqueue enum4linux <target> --args \"<flags>\"",
    "examples": [
        "menuscript jobs enqueue enum4linux 10.10.10.5 --args \"-a\""
    ],
    "flags": [
        ["-a", "Run all enumeration (default commonly used)"],
        ["-u <user>", "Enumerate details for specific user"],
        ["-o <outfile>", "Output to file"]
    ],
    "presets": [
        {"name":"Quick SMB","args":["-a"],"desc":"Run typical SMB enumeration"},
        {"name":"User Lookup","args":["-u","Administrator"],"desc":"Check specific user details"},
    ]
}

