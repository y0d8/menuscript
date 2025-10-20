import pytest
from pathlib import Path
import menuscript.plugins.gobuster as gb

def fake_run(cmd, stdout, stderr, text, timeout):
    class R:
        def __init__(self):
            self.returncode = 0
            self.stdout = "/admin (Status: 200) [Size: 123]\\n/login (Status: 401)\\n"
    return R()

def test_gobuster_plugin_run(monkeypatch, tmp_path):
    monkeypatch.setattr("subprocess.run", fake_run)
    p = gb.Plugin()
    prepared = p.prepare("http://example.com", ["dir", "-u", "http://example.com", "-w", "/dev/null"], "unittest")
    res = p.run(prepared)
    assert res["tool"] == "gobuster"
    assert isinstance(res["summary"], dict)
    assert res["summary"].get("count", 0) >= 1
    assert any(item.get("path") == "/admin" for item in res["per_host"])
