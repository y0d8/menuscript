#!/usr/bin/env python3
"""
Simple plugin loader for menuscript (L1).
"""
from __future__ import annotations
import pkgutil
import importlib
from typing import Dict, Any


def _safe_import_module(fullname: str):
    """Import module and return it, or None on error."""
    try:
        return importlib.import_module(fullname)
    except Exception as e:
        try:
            print(f"[plugin loader] could not import {fullname}: {e}")
        except Exception:
            pass
        return None


def discover_plugins() -> Dict[str, Any]:
    """
    Return mapping of plugin_key -> plugin_object
    plugin_key is plugin.tool if set and truthy, otherwise module name.
    """
    plugins = {}
    
    try:
        pkg = importlib.import_module("menuscript.plugins")
    except Exception as e:
        print("[plugin loader] cannot import menuscript.plugins:", e)
        return plugins

    for finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
        if name in ("plugin_base", "plugin_template", "__init__"):
            continue
        
        full = f"menuscript.plugins.{name}"
        mod = _safe_import_module(full)
        if not mod:
            continue
        
        plugin = getattr(mod, "plugin", None)
        if not plugin:
            continue

        try:
            module_help = getattr(mod, "HELP", None)
            if module_help and not getattr(plugin, "HELP", None):
                plugin.HELP = module_help
        except Exception:
            pass

        try:
            if not getattr(plugin, "name", None):
                if module_help and isinstance(module_help, dict):
                    plugin.name = module_help.get("name") or name
                else:
                    plugin.name = name
        except Exception:
            pass
        
        try:
            if not getattr(plugin, "tool", None):
                if module_help and isinstance(module_help, dict):
                    plugin.tool = module_help.get("tool") or name
                else:
                    plugin.tool = getattr(plugin, "name", name)
        except Exception:
            pass
        
        try:
            if not getattr(plugin, "category", None):
                if module_help and isinstance(module_help, dict):
                    plugin.category = module_help.get("category") or "network"
                else:
                    plugin.category = "network"
        except Exception:
            pass

        key = getattr(plugin, "tool", None) or getattr(plugin, "name", None) or name
        try:
            key = str(key).lower()
        except Exception:
            key = name

        plugins[key] = plugin

    return plugins


load = discover_plugins
