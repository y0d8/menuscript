from menuscript.config import read_config, write_config, enable_plugin, disable_plugin, reset_plugins

def test_enable_disable_reset_roundtrip(tmp_path, monkeypatch):
    from pathlib import Path
    # isolate config
    monkeypatch.setenv("HOME", str(tmp_path))
    # reset
    reset_plugins()
    cfg = read_config()
    assert cfg["plugins"]["enabled"] == []
    enable_plugin("NaMe")
    cfg = read_config()
    assert "name" in cfg["plugins"]["enabled"]
    disable_plugin("name")
    cfg = read_config()
    assert "name" in cfg["plugins"]["disabled"]
    reset_plugins()
    cfg = read_config()
    assert cfg["plugins"]["enabled"] == [] and cfg["plugins"]["disabled"] == []
