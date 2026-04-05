"""Tests for SNAFT Companions — optional TIBET ecosystem integrations."""

import pytest

from snaft.companions import (
    available_companions,
    verify_sbom,
    verify_ipoll_signature,
    check_cortex_permission,
    is_airlock_available,
)


# =============================================================================
# AVAILABLE COMPANIONS
# =============================================================================

class TestAvailableCompanions:

    def test_returns_dict_with_all_keys(self):
        """available_companions returns a dict with all 4 companion keys."""
        result = available_companions()
        assert isinstance(result, dict)
        expected_keys = {"tibet-triage", "tibet-core", "tibet-sbom", "ainternet"}
        assert set(result.keys()) == expected_keys

    def test_all_values_are_bool(self):
        """All values in the companions dict are booleans."""
        result = available_companions()
        for key, value in result.items():
            assert isinstance(value, bool), f"{key} should be bool, got {type(value)}"

    def test_returns_consistent_results(self):
        """Calling available_companions twice returns the same result."""
        result1 = available_companions()
        result2 = available_companions()
        assert result1 == result2


# =============================================================================
# VERIFY SBOM
# =============================================================================

class TestVerifySBOM:

    def test_returns_tuple_bool_str(self):
        """verify_sbom returns a tuple of (bool, str)."""
        result = verify_sbom("requests", "2.31.0")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_without_version(self):
        """verify_sbom works without version argument."""
        result = verify_sbom("requests")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_not_installed_fallback(self):
        """When tibet-sbom is not installed, returns (False, reason)."""
        companions = available_companions()
        if not companions["tibet-sbom"]:
            verified, reason = verify_sbom("any-package")
            assert not verified
            assert "not installed" in reason.lower()


# =============================================================================
# VERIFY IPOLL SIGNATURE
# =============================================================================

class TestVerifyIPollSignature:

    def test_returns_tuple_bool_str(self):
        """verify_ipoll_signature returns a tuple of (bool, str)."""
        result = verify_ipoll_signature({"content": "hello", "from": "agent-1"})
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_not_installed_fallback(self):
        """When ainternet is not installed, returns (False, reason)."""
        companions = available_companions()
        if not companions["ainternet"]:
            verified, reason = verify_ipoll_signature({"content": "test"})
            assert not verified
            assert "not installed" in reason.lower()

    def test_message_without_signature(self):
        """Message without signature or TIBET token fails verification."""
        companions = available_companions()
        if companions["ainternet"]:
            verified, reason = verify_ipoll_signature({"content": "hello"})
            assert not verified
            assert "no signature" in reason.lower() or "not installed" in reason.lower()


# =============================================================================
# CHECK CORTEX PERMISSION
# =============================================================================

class TestCheckCortexPermission:

    def test_returns_tuple_bool_str(self):
        """check_cortex_permission returns a tuple of (bool, str)."""
        result = check_cortex_permission("root_idd.aint", "message_all")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_permissive_fallback_when_not_installed(self):
        """When ainternet is not installed, returns (True, ...) permissive fallback."""
        companions = available_companions()
        if not companions["ainternet"]:
            allowed, reason = check_cortex_permission("test.aint", "any_action")
            assert allowed
            assert "skipped" in reason.lower() or "not installed" in reason.lower()

    def test_different_actions(self):
        """check_cortex_permission works with different action strings."""
        result1 = check_cortex_permission("agent.aint", "read")
        result2 = check_cortex_permission("agent.aint", "triage_approve")
        assert isinstance(result1[0], bool)
        assert isinstance(result2[0], bool)


# =============================================================================
# IS AIRLOCK AVAILABLE
# =============================================================================

class TestIsAirlockAvailable:

    def test_returns_bool(self):
        """is_airlock_available returns a boolean."""
        result = is_airlock_available()
        assert isinstance(result, bool)

    def test_consistent_with_companions(self):
        """is_airlock_available matches available_companions['tibet-triage']."""
        result = is_airlock_available()
        companions = available_companions()
        assert result == companions["tibet-triage"]
