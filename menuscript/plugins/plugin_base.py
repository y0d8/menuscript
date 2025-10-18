# simple plugin contract
from typing import List, Optional, Tuple

class Plugin:
    """
    Minimal plugin contract.
    Implementations must provide:
      - name: human name
      - tool: canonical short tool id (used for jobs CLI)
      - category: e.g. "network" or "web"
      - run(self, target, args, label, save_xml=False) -> Tuple[int, str]
           should run the tool synchronously and return (rc, log_path)
    """

    name: str = "Base Plugin"
    tool: str = "base"
    category: str = "misc"

    def run(self, target: str, args: List[str], label: Optional[str] = None, save_xml: bool = False) -> Tuple[int, str]:
        raise NotImplementedError("Plugins must implement run()")
