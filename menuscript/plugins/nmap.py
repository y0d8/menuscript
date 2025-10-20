# menuscript/plugins/nmap.py
from typing import List, Optional, Tuple
from .plugin_base import Plugin
from ..scanner import run_nmap

HELP = {
  "name": "Nmap (core)",
  "description": "Nmap network scanner (wrapped for help/presets).",
  "usage": "menuscript jobs enqueue nmap <target> --args \"<nmap flags>\"",
  "examples": ["menuscript jobs enqueue nmap 10.0.0.0/24 --args \"-sn\"",],
  "flags": [["-sn","Ping scan"], ["-sV","Service detection"], ["-O","OS detection"]],
  "presets": [
    {"name":"Discovery","args":["-sn"],"desc":"Ping sweep"},
    {"name":"Fast","args":["-v","-PS","-F"],"desc":"Fast probes"},
    {"name":"Full","args":["-sV","-O","-p1-65535"],"desc":"Service+OS, full ports"}
  ]
}

class NmapPlugin(Plugin):
    name = "Nmap"
    tool = "nmap"
    category = "network"

    def run(self, target: str, args: List[str], label: Optional[str] = None, save_xml: bool = False) -> Tuple[int,str]:
        # reuse existing run_nmap helper (returns logpath, rc, xmlpath, summary)
        logpath, rc, xmlpath, summary = run_nmap(target, args, label, save_xml=save_xml)
        return rc, logpath

plugin = NmapPlugin()



# Ensure loader-friendly metadata: provide default tool id if missing
try:
    if plugin is not None and (getattr(plugin, "tool", None) is None):
        plugin.tool = "nmap"
    if plugin is not None and (getattr(plugin, "name", None) is None):
        plugin.name = plugin.tool
except Exception:
    pass
