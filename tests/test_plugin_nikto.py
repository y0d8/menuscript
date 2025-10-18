import pytest
from menuscript.plugins.nikto import NiktoPlugin
import time, os

def test_nikto_no_exe(monkeypatch):
    np = NiktoPlugin()
    monkeypatch.setattr(np, "_find_exe", lambda: None)
    with pytest.raises(RuntimeError):
        np.run("example.com", [], "t")

def test_nikto_run_fake(monkeypatch, tmp_path):
    np = NiktoPlugin()
    fake = tmp_path / "fake_nikto.sh"
    fake.write_text("#!/bin/sh\necho fake-nikto\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setattr(np, "_find_exe", lambda: str(fake))
    rc, log = np.run("example.com", [], "t")
    assert rc == 0
    assert os.path.exists(log)
    assert "fake-nikto" in open(log).read()
