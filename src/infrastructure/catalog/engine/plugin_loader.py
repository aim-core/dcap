"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/engine/plugin_loader.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Professional Plugin Loader
 * PURPOSE:     Load proprietary DCAP Pro constructs with caching
 * DOMAIN:      Catalog
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-27
 * UPDATED:     2026-05-29
 * VERSION:     v0.5.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
import importlib.util
import sys
from pathlib import Path

def load_pro_plugin():
    plugin_path = Path(__file__).parent.parent.parent.parent.parent / "constructs_extended_source.cp314-win_amd64.pyd"
    if not plugin_path.exists():
        return ()
    try:
        spec = importlib.util.spec_from_file_location("constructs_extended_source", plugin_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, "EXTENDED_CONSTRUCTS", ())
    except Exception:
        return ()
    return ()

def get_extended_constructs():
    if not hasattr(get_extended_constructs, "_cache"):
        get_extended_constructs._cache = load_pro_plugin()
    return get_extended_constructs._cache