#!/usr/bin/env python3
"""
Config helpers for menuscript.

Config file lives at ~/.menuscript/config.json and supports:
{
  "plugins": { "enabled": [], "disabled": [] },
  "settings": { "wordlists": null, "proxy": null, "threads": 10 }
}

Backward compatibility: we also accept the old flat shape:
{ "enabled": [], "disabled": [] }
"""
from __future__ import annotations
from pathlib import Path
import json

CONFIG_PATH = Path.home() / ".menuscript" / "config.json"

DEFAULT_CONFIG = {
    "plugins": {"enabled": [], "disabled": []},
    "settings": {"wordlists": None, "proxy": None, "threads": 10},
}

def _ensure_dir():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

def _normalize(data: dict) -> dict:
    # Accept both new {"plugins":{...}} and old flat {"enabled":[], "disabled":[]}
    if not isinstance(data, dict):
        return DEFAULT_CONFIG.copy()
    if "plugins" in data and isinstance(data["plugins"], dict):
        plugins = data["plugins"]
        plugins.setdefault("enabled", [])
        plugins.setdefault("disabled", [])
        data.setdefault("settings", {"wordlists": None, "proxy": None, "threads": 10})
        return data
    # old flat form
    enabled = data.get("enabled", []) or []
    disabled = data.get("disabled", []) or []
    return {"plugins": {"enabled": enabled, "disabled": disabled}, "settings": {"wordlists": None, "proxy": None, "threads": 10}}

def read_config() -> dict:
    _ensure_dir()
    try:
        if CONFIG_PATH.exists():
            return _normalize(json.loads(CONFIG_PATH.read_text()))
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        return DEFAULT_CONFIG.copy()
    except Exception:
        # auto-repair
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        return DEFAULT_CONFIG.copy()

def write_config(cfg: dict) -> None:
    _ensure_dir()
    CONFIG_PATH.write_text(json.dumps(_normalize(cfg), indent=2))

def list_plugins_config() -> tuple[list[str], list[str]]:
    cfg = read_config()
    e = [x.lower() for x in cfg["plugins"]["enabled"]]
    d = [x.lower() for x in cfg["plugins"]["disabled"]]
    return e, d

def enable_plugin(name: str) -> None:
    name = name.lower()
    cfg = read_config()
    e, d = list_plugins_config()
    if name not in e:
        e.append(name)
    if name in d:
        d.remove(name)
    cfg["plugins"]["enabled"] = e
    cfg["plugins"]["disabled"] = d
    write_config(cfg)

def disable_plugin(name: str) -> None:
    name = name.lower()
    cfg = read_config()
    e, d = list_plugins_config()
    if name in e:
        e.remove(name)
    if name not in d:
        d.append(name)
    cfg["plugins"]["enabled"] = e
    cfg["plugins"]["disabled"] = d
    write_config(cfg)

def reset_plugins() -> None:
    cfg = read_config()
    cfg["plugins"] = {"enabled": [], "disabled": []}
    write_config(cfg)
