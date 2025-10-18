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
