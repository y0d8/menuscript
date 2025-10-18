import pytest
from menuscript.plugins.theharvester import TheHarvesterPlugin
import os, time

def test_theharv_no_exe(monkeypatch):
    p = TheHarvesterPlugin()
    monkeypatch.setattr(p, "_find_exe", lambda: None)
    with pytest.raises(RuntimeError):
        p.run("example.com", [], "t")

def test_theharv_fake(monkeypatch, tmp_path):
    p = TheHarvesterPlugin()
    fake = tmp_path / "fake_theharv.sh"
    fake.write_text("#!/bin/sh\necho theharv\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setattr(p, "_find_exe", lambda: str(fake))
    rc, log = p.run("example.com", [], "t")
    assert rc == 0
    assert os.path.exists(log)
    assert "theharv" in open(log).read()
