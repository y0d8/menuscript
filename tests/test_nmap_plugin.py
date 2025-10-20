import types
import pytest
from pathlib import Path

def test_nmap_plugin_run(monkeypatch, tmp_path):
    """
    Test the nmap plugin run flow by monkeypatching the underlying scanner.run_nmap
    so we don't rely on an actual nmap install.
    """
    # Prepare a fake run_nmap implementation
    fake_summary = {"hosts_total":1, "hosts_up":1, "open_ports": [22], "per_host":[{"addr":"127.0.0.1","up":True,"open":[22]}]}
    def fake_run_nmap(target, args, label, save_xml=False):
        # emulate (logpath, rc, xmlpath, summary)
        logp = tmp_path / "nmap.log"
        logp.write_text("NMAP FAKE OUTPUT")
        return (str(logp), 0, None, fake_summary)

    # Monkeypatch the plugin's import
    import menuscript.plugins.nmap as nmap_plugin
    monkeypatch.setattr(nmap_plugin.scanner, "run_nmap", fake_run_nmap)

    # Run plugin
    plugin = nmap_plugin.Plugin()
    prepared = plugin.prepare("127.0.0.1", ["-sn"], "unittest")
    res = plugin.run(prepared)
    assert res["tool"] == "nmap"
    assert res["target"] == "127.0.0.1"
    assert isinstance(res["summary"], dict)
    assert res["per_host"][0]["addr"] == "127.0.0.1"
