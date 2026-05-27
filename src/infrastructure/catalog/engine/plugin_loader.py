"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/engine/plugin_loader.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Professional Plugin Loader
 * PURPOSE:     Load proprietary DCAP Pro constructs if available
 * DOMAIN:      Catalog
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-27
 * UPDATED:     2026-05-27
 * VERSION:     v0.4.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
"""
DCAP Plugin Loader — Professional Intelligence Interface.
Loads proprietary security constructs if available.
"""

import importlib.util
import sys
from pathlib import Path

def load_pro_plugin():
    """Load DCAP Pro constructs from compiled extension."""
    plugin_path = Path.cwd() / "dcap_pro.pyd"
    if not plugin_path.exists():
        return ()
    
    try:
        spec = importlib.util.spec_from_file_location("dcap_pro", plugin_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, "PRO_CONSTRUCTS", ())
    except Exception:
        pass
    
    return ()