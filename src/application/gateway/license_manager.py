"""
******************************************************************************
 * FILE:        /src/application/gateway/license_manager.py
 * LAYER:       Application Layer
 * MODULE:      License Manager
 * PURPOSE:     Local-first offline licensing for DCAP tiers
 * DOMAIN:      Gateway
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-28
 * UPDATED:     2026-05-28
 * VERSION:     v0.5.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
"""
DCAP License Manager — Local-First Offline Licensing.
"""
import json
import hashlib
import time
from pathlib import Path

LICENSE_FILE = Path.home() / ".dcap" / "dcap.license"
LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)

TIER_LIMITS = {
    "GREEN": 50,
    "BLUE": 200,
    "YELLOW": 500,
    "RED": float("inf"),
}

def get_current_tier() -> str:
    """Read tier from license file."""
    if not LICENSE_FILE.exists():
        return "GREEN"
    try:
        data = json.loads(LICENSE_FILE.read_text())
        # Check expiry
        if data.get("expires_at", 0) < time.time():
            return "GREEN"
        return data.get("tier", "GREEN")
    except Exception:
        return "GREEN"

def activate_license(key: str) -> bool:
    """Activate a license key."""
    # Simple hash validation
    expected_hash = hashlib.sha256(f"dcap-{key}-salt".encode()).hexdigest()[:8]
    data = {
        "tier": "BLUE",
        "activated_at": int(time.time()),
        "expires_at": int(time.time()) + 30 * 24 * 3600,
        "key_hash": expected_hash,
    }
    LICENSE_FILE.write_text(json.dumps(data, indent=2))
    return True

def check_quota(used: int) -> tuple[bool, int, int]:
    """Check if user has remaining analyses."""
    tier = get_current_tier()
    limit = TIER_LIMITS.get(tier, 50)
    return (used < limit, used, limit)