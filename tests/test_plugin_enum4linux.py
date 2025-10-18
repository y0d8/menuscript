import pytest
from menuscript.plugins.enum4linux import Enum4linuxPlugin
import os, time

def test_enum_no_exe(monkeypatch):
    p = Enum4linuxPlugin()
    monkeypatch.setattr(p, "_find_exe", lambda: None)
    with pytest.raises(RuntimeError):
        p.run("10.0.0.1", [], "t")

def test_enum_fake(monkeypatch, tmp_path):
    p = Enum4linuxPlugin()
    fake = tmp_path / "fake_enum.sh"
    fake.write_text("#!/bin/sh\necho enum4linux\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setattr(p, "_find_exe", lambda: str(fake))
    rc, log = p.run("10.0.0.1", [], "t")
    assert rc == 0
    assert os.path.exists(log)
    assert "enum4linux" in open(log).read()
