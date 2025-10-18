from typing import List, Optional, Tuple
import shutil, os, time, subprocess
from .plugin_base import Plugin

class TheHarvesterPlugin(Plugin):
    name = "theHarvester (OSINT)"
    tool = "theharvester"
    category = "network"

    def _find_exe(self) -> Optional[str]:
        return shutil.which("theHarvester")

    def run(self, target: str, args: List[str], label: Optional[str]=None, save_xml: bool = False) -> Tuple[int, str]:
        exe = self._find_exe()
        if not exe:
            raise RuntimeError("theHarvester binary not found on PATH")

        cmd = [exe, "-d", target] + (args or [])

        log_dir = os.path.expanduser("~/.menuscript/artifacts")
        os.makedirs(log_dir, exist_ok=True)
        fname = f"theharv_{label or 'scan'}_{int(time.time())}.log"
        log_path = os.path.join(log_dir, fname)

        with open(log_path, "wb") as out:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for chunk in iter(lambda: proc.stdout.read(4096), b""):
                out.write(chunk)
                out.flush()
            rc = proc.wait()

        return rc, log_path

plugin = TheHarvesterPlugin()
