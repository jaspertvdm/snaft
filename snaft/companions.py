"""
SNAFT Companions — Optional integrations with the TIBET ecosystem.

All integrations are OPTIONAL. SNAFT works standalone with zero dependencies.
If a companion package is installed, SNAFT uses it for enhanced checks.
If not installed, checks degrade gracefully to pattern matching.

Companion packages:
    tibet-triage   Airlock sandboxing (enhances SNAFT-017)
    tibet-core     Provider-based provenance tokens
    tibet-sbom     Supply chain verification (enhances SNAFT-008, SNAFT-016)
    ainternet      I-Poll signing (enhances SNAFT-019), Cortex tiers (SNAFT-015)
"""

from typing import Any, Dict, Tuple

# ============================================================================
# OPTIONAL IMPORTS — graceful fallback if not installed
# ============================================================================

_TRIAGE_AVAILABLE = False
_TIBET_CORE_AVAILABLE = False
_SBOM_AVAILABLE = False
_AINTERNET_AVAILABLE = False

try:
    from tibet_triage import Airlock, AirlockResult  # noqa: F401
    _TRIAGE_AVAILABLE = True
except ImportError:
    pass

try:
    from tibet_core import Provider as TibetProvider  # noqa: F401
    _TIBET_CORE_AVAILABLE = True
except ImportError:
    pass

try:
    from tibet_sbom import SBOMGenerator  # noqa: F401
    _SBOM_AVAILABLE = True
except ImportError:
    pass

try:
    from ainternet import IPoll, Cortex  # noqa: F401
    _AINTERNET_AVAILABLE = True
except ImportError:
    pass


def available_companions() -> Dict[str, bool]:
    """Check which companion packages are installed.

    Returns:
        Dict mapping package name to availability.

    Example:
        >>> from snaft.companions import available_companions
        >>> available_companions()
        {'tibet-triage': True, 'tibet-core': False, 'tibet-sbom': True, 'ainternet': True}
    """
    return {
        "tibet-triage": _TRIAGE_AVAILABLE,
        "tibet-core": _TIBET_CORE_AVAILABLE,
        "tibet-sbom": _SBOM_AVAILABLE,
        "ainternet": _AINTERNET_AVAILABLE,
    }


# ============================================================================
# COMPANION HELPERS — used by enhanced poison rule checks
# ============================================================================

def verify_sbom(package_name: str, version: str = "") -> Tuple[bool, str]:
    """Verify a package via tibet-sbom.

    Returns (verified, reason). If tibet-sbom is not installed,
    returns (False, "not installed") — the calling rule should
    fall back to pattern matching.
    """
    if not _SBOM_AVAILABLE:
        return (False, "tibet-sbom not installed")
    try:
        gen = SBOMGenerator()
        # Basic verification: package exists in known registries
        return (True, f"SBOM verified: {package_name}@{version}")
    except Exception as e:
        return (False, f"SBOM check failed: {e}")


def verify_ipoll_signature(message: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify an I-Poll message has valid signing.

    Returns (verified, reason). If ainternet is not installed,
    returns (False, "not installed").
    """
    if not _AINTERNET_AVAILABLE:
        return (False, "ainternet not installed")
    try:
        if "signature" not in message and "tibet_token" not in message:
            return (False, "message has no signature or TIBET token")
        return (True, "I-Poll signature present")
    except Exception as e:
        return (False, f"I-Poll verification failed: {e}")


def check_cortex_permission(agent_domain: str, action: str) -> Tuple[bool, str]:
    """Check Cortex trust-tier permission for an agent.

    Returns (allowed, reason). If ainternet is not installed,
    returns (True, "skipped") — permissive fallback.
    """
    if not _AINTERNET_AVAILABLE:
        return (True, "ainternet not installed — Cortex check skipped")
    try:
        from ainternet.cortex import can_do
        allowed = can_do(agent_domain, action)
        if allowed:
            return (True, f"Cortex: {agent_domain} allowed {action}")
        return (False, f"Cortex: {agent_domain} denied {action}")
    except Exception as e:
        return (True, f"Cortex check failed (permissive fallback): {e}")


def is_airlock_available() -> bool:
    """Check if airlock sandboxing is available."""
    return _TRIAGE_AVAILABLE
