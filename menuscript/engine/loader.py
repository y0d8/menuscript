"""
Simple plugin loader for menuscript (L1).
Behavior:
 - Import every module in package 'menuscript.plugins'
 - If module defines a non-None 'plugin' attribute, register it.
 - Skip 'plugin_base' and 'plugin_template'.
 - Return dict keyed by plugin.tool if available, otherwise module name.
This loader is intentionally tiny and robust for predictability.
"""
from __future__ import annotations
import pkgutil
import importlib
from types import ModuleType
from typing import Dict, Any

def _safe_import_module(fullname: str):
    try:
        mod = importlib.import_module(fullname)
        return mod
    except Exception as e:
        # Import failed (syntax error or runtime); ignore the module but log
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
        # skip base/template helpers
        if name in ("plugin_base", "plugin_template", "__init__"):
            continue
        full = f"menuscript.plugins.{name}"
        mod = _safe_import_module(full)
        if not mod:
            continue
        # register only if module exposes 'plugin' attribute and it's not None
        plugin = getattr(mod, "plugin", None)
        if not plugin:
            # tolerate modules that don't export plugin instance
            continue

        # If module defines HELP metadata at module-level, copy it to the plugin instance
        try:
            module_help = getattr(mod, "HELP", None)
            if module_help and getattr(plugin, "HELP", None) is None:
                try:
                    plugin.HELP = module_help
                except Exception:
                    pass
        except Exception:
            pass

        # Ensure plugin has name/tool/category fallback values from HELP or module name
        try:
            if getattr(plugin, "name", None) in (None, ""):
                plugin.name = getattr(plugin, "tool", None) or (module_help.get("name") if module_help else None) or name
            if getattr(plugin, "tool", None) in (None, ""):
                # prefer explicit tool, else slugify module name
                plugin.tool = getattr(plugin, "tool", None) or (module_help.get("tool") if module_help else None) or name
            if getattr(plugin, "category", None) in (None, ""):
                plugin.category = (module_help.get("category") if module_help else None) or "network"
        except Exception:
            pass

        # compute key
        key = getattr(plugin, "tool", None) or getattr(plugin, "name", None) or name
        try:
            key = str(key).lower()
        except Exception:
            key = name
        
        # COPY module-level HELP into plugin instance (if present) so CLI help works.
        try:
            module_help = getattr(mod, "HELP", None)
            if module_help and not getattr(plugin, "HELP", None):
                try:
                    plugin.HELP = module_help
                except Exception:
                    pass
        except Exception:
            pass

        # Ensure plugin has reasonable name/tool fallback values
        try:
            if not getattr(plugin, "name", None):
                plugin.name = (module_help.get("name") if isinstance(module_help, dict) else None) or getattr(plugin, "name", None) or name
        except Exception:
            pass
        try:
            if not getattr(plugin, "tool", None):
                plugin.tool = (module_help.get("tool") if isinstance(module_help, dict) else None) or getattr(plugin, "tool", None) or name
        except Exception:
            pass

        
        # --- Normalize plugin instance (PluginBase compatibility) ---
        # If module defines HELP at module level, copy to instance unless already present.
        try:
            module_help = getattr(mod, "HELP", None)
            if module_help and not getattr(plugin, "HELP", None):
                try:
                    plugin.HELP = module_help
                except Exception:
                    pass
        except Exception:
            pass

        # Ensure name/tool/category sensible defaults
        try:
            if not getattr(plugin, "name", None):
                plugin.name = getattr(plugin, "name", None) or (module_help.get("name") if isinstance(module_help, dict) else None) or name
        except Exception:
            pass
        try:
            if not getattr(plugin, "tool", None):
                plugin.tool = getattr(plugin, "tool", None) or (module_help.get("tool") if isinstance(module_help, dict) else None) or name
        except Exception:
            pass
        try:
            if not getattr(plugin, "category", None):
                plugin.category = getattr(plugin, "category", None) or (module_help.get("category") if isinstance(module_help, dict) else None) or "network"
        except Exception:
            pass

        plugins[key] = plugin

        plugin = getattr(mod, "plugin", None)
        if not plugin:
            # try to tolerate modules that expose a 'Plugin' class named <Name>Plugin
            # but we intentionally do NOT instantiate automatically unless plugin exists.
            continue

        # If module defines HELP metadata at module-level, copy it to the plugin instance
        # so CLI/UI can read help from the plugin object (getattr(p, 'HELP', None)).
        try:
            module_help = getattr(mod, 'HELP', None)
            if module_help and getattr(plugin, 'HELP', None) is None:
                try:
                    plugin.HELP = module_help
                except Exception:
                    # best-effort; ignore if assignment fails
                    pass
        except Exception:
            pass

        # Ensure plugin has name/tool fallback values (use HELP or module/name)
        try:
            if getattr(plugin, 'name', None) is None:
                plugin.name = getattr(plugin, 'tool', None) or getattr(mod, 'HELP', {}).get('name') if hasattr(mod, 'HELP') else None
            if getattr(plugin, 'tool', None) is None:
                # try to pick from HELP, then module name
                plugin.tool = getattr(plugin, 'tool', None) or (getattr(mod, 'HELP', {}).get('name') if hasattr(mod, 'HELP') else None) or name
        except Exception:
            pass

        # compute key
        key = getattr(plugin, "tool", None) or getattr(plugin, "name", None) or name
        # normalize to lower-case string key
        try:
            key = str(key).lower()
        except Exception:
            key = name
        
        # COPY module-level HELP into plugin instance (if present) so CLI help works.
        try:
            module_help = getattr(mod, "HELP", None)
            if module_help and not getattr(plugin, "HELP", None):
                try:
                    plugin.HELP = module_help
                except Exception:
                    pass
        except Exception:
            pass

        # Ensure plugin has reasonable name/tool fallback values
        try:
            if not getattr(plugin, "name", None):
                plugin.name = (module_help.get("name") if isinstance(module_help, dict) else None) or getattr(plugin, "name", None) or name
        except Exception:
            pass
        try:
            if not getattr(plugin, "tool", None):
                plugin.tool = (module_help.get("tool") if isinstance(module_help, dict) else None) or getattr(plugin, "tool", None) or name
        except Exception:
            pass

        
        # --- Normalize plugin instance (PluginBase compatibility) ---
        # If module defines HELP at module level, copy to instance unless already present.
        try:
            module_help = getattr(mod, "HELP", None)
            if module_help and not getattr(plugin, "HELP", None):
                try:
                    plugin.HELP = module_help
                except Exception:
                    pass
        except Exception:
            pass

        # Ensure name/tool/category sensible defaults
        try:
            if not getattr(plugin, "name", None):
                plugin.name = getattr(plugin, "name", None) or (module_help.get("name") if isinstance(module_help, dict) else None) or name
        except Exception:
            pass
        try:
            if not getattr(plugin, "tool", None):
                plugin.tool = getattr(plugin, "tool", None) or (module_help.get("tool") if isinstance(module_help, dict) else None) or name
        except Exception:
            pass
        try:
            if not getattr(plugin, "category", None):
                plugin.category = getattr(plugin, "category", None) or (module_help.get("category") if isinstance(module_help, dict) else None) or "network"
        except Exception:
            pass

        plugins[key] = plugin
    return plugins

# convenience alias
load = discover_plugins
