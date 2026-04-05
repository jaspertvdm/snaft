"""Tests for SNAFT BlockList — network-level blocking by domain, IP, or pattern."""

import pytest

from snaft.blocking import BlockList


# =============================================================================
# BLOCK BY AINS DOMAIN
# =============================================================================

class TestBlockAINS:

    def test_block_ains_domain(self):
        """Block an .aint domain and verify it is blocked."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Rogue agent detected")
        blocked, reason = bl.is_blocked("evil.aint")
        assert blocked
        assert reason == "Rogue agent detected"

    def test_block_ains_auto_appends_suffix(self):
        """Auto-appends .aint suffix when missing."""
        bl = BlockList()
        bl.block_ains("evil", "Rogue agent")
        blocked, reason = bl.is_blocked("evil.aint")
        assert blocked
        assert reason == "Rogue agent"

    def test_block_ains_case_insensitive(self):
        """Domain blocking is case-insensitive."""
        bl = BlockList()
        bl.block_ains("Evil.AINT", "Bad actor")
        blocked, _ = bl.is_blocked("evil.aint")
        assert blocked

    def test_unblocked_domain_passes(self):
        """Unblocked domain is not flagged."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Rogue agent")
        blocked, reason = bl.is_blocked("good.aint")
        assert not blocked
        assert reason == ""


# =============================================================================
# BLOCK BY IP
# =============================================================================

class TestBlockIP:

    def test_block_ip_address(self):
        """Block an IP address and verify it is blocked."""
        bl = BlockList()
        bl.block_ip("192.168.1.100", "Port scan source")
        blocked, reason = bl.is_blocked("192.168.1.100")
        assert blocked
        assert reason == "Port scan source"

    def test_different_ip_passes(self):
        """Different IP is not blocked."""
        bl = BlockList()
        bl.block_ip("192.168.1.100", "Port scan source")
        blocked, _ = bl.is_blocked("192.168.1.200")
        assert not blocked


# =============================================================================
# BLOCK BY PATTERN
# =============================================================================

class TestBlockPattern:

    def test_block_wildcard_pattern(self):
        """Block a wildcard pattern and verify subdomains match."""
        bl = BlockList()
        bl.block_pattern("*.spam.aint", "Known spam network")
        blocked, reason = bl.is_blocked("agent.spam.aint")
        assert blocked
        assert reason == "Known spam network"

    def test_pattern_matches_multiple(self):
        """Wildcard pattern matches different subdomains."""
        bl = BlockList()
        bl.block_pattern("*.spam.aint", "Spam network")
        blocked1, _ = bl.is_blocked("bot1.spam.aint")
        blocked2, _ = bl.is_blocked("bot2.spam.aint")
        assert blocked1
        assert blocked2

    def test_pattern_no_false_positive(self):
        """Pattern does not match unrelated domains."""
        bl = BlockList()
        bl.block_pattern("*.spam.aint", "Spam network")
        blocked, _ = bl.is_blocked("good.agent.aint")
        assert not blocked

    def test_ip_wildcard_pattern(self):
        """Block an IP wildcard pattern."""
        bl = BlockList()
        bl.block_pattern("10.0.0.*", "Internal network")
        blocked, reason = bl.is_blocked("10.0.0.55")
        assert blocked
        assert reason == "Internal network"


# =============================================================================
# UNBLOCK
# =============================================================================

class TestUnblock:

    def test_unblock_removes_block(self):
        """Unblocking removes the block entry."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Rogue agent")
        blocked_before, _ = bl.is_blocked("evil.aint")
        assert blocked_before

        bl.unblock("evil.aint")
        blocked_after, _ = bl.is_blocked("evil.aint")
        assert not blocked_after

    def test_unblock_returns_entry(self):
        """Unblock returns the removed entry."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Rogue agent")
        entry = bl.unblock("evil.aint")
        assert entry is not None
        assert entry.identifier == "evil.aint"

    def test_unblock_nonexistent_returns_none(self):
        """Unblocking a nonexistent entry returns None."""
        bl = BlockList()
        entry = bl.unblock("nonexistent.aint")
        assert entry is None

    def test_unblock_without_suffix(self):
        """Unblocking without .aint suffix works via fallback."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Rogue agent")
        entry = bl.unblock("evil")
        assert entry is not None


# =============================================================================
# IS_BLOCKED RETURNS REASON TEXT
# =============================================================================

class TestIsBlockedReason:

    def test_is_blocked_returns_reason_text(self):
        """is_blocked returns the reason as the second element."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Data exfiltration attempt")
        blocked, reason = bl.is_blocked("evil.aint")
        assert blocked
        assert reason == "Data exfiltration attempt"

    def test_not_blocked_returns_empty_reason(self):
        """Not blocked returns empty reason string."""
        bl = BlockList()
        blocked, reason = bl.is_blocked("good.aint")
        assert not blocked
        assert reason == ""


# =============================================================================
# LIST, COUNT, CLEAR
# =============================================================================

class TestListCountClear:

    def test_list_blocked_returns_all(self):
        """list_blocked returns all entries as dicts."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Bad")
        bl.block_ip("10.0.0.1", "Scanner")
        bl.block_pattern("*.spam.aint", "Spam")

        entries = bl.list_blocked()
        assert len(entries) == 3
        assert all(isinstance(e, dict) for e in entries)

        identifiers = {e["identifier"] for e in entries}
        assert "evil.aint" in identifiers
        assert "10.0.0.1" in identifiers
        assert "*.spam.aint" in identifiers

    def test_count_returns_correct_number(self):
        """count returns the number of active blocks."""
        bl = BlockList()
        assert bl.count() == 0

        bl.block_ains("evil.aint", "Bad")
        assert bl.count() == 1

        bl.block_ip("10.0.0.1", "Scanner")
        assert bl.count() == 2

    def test_clear_removes_all(self):
        """clear removes all entries and returns count."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Bad")
        bl.block_ip("10.0.0.1", "Scanner")
        bl.block_pattern("*.spam.aint", "Spam")

        removed = bl.clear()
        assert removed == 3
        assert bl.count() == 0

    def test_clear_empty_list(self):
        """clear on empty list returns 0."""
        bl = BlockList()
        removed = bl.clear()
        assert removed == 0


# =============================================================================
# LOAD AND EXPORT ROUNDTRIP
# =============================================================================

class TestLoadExport:

    def test_export_returns_list_of_dicts(self):
        """export returns serializable list of dicts."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Bad")
        bl.block_ip("10.0.0.1", "Scanner")

        exported = bl.export()
        assert isinstance(exported, list)
        assert len(exported) == 2
        assert all("identifier" in e for e in exported)
        assert all("block_type" in e for e in exported)
        assert all("reason" in e for e in exported)

    def test_load_restores_entries(self):
        """load restores entries from serialized dicts."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Bad")
        bl.block_ip("10.0.0.1", "Scanner")
        bl.block_pattern("*.spam.aint", "Spam")

        exported = bl.export()

        # Create a new blocklist and load the data
        bl2 = BlockList()
        bl2.load(exported)

        assert bl2.count() == 3
        blocked, reason = bl2.is_blocked("evil.aint")
        assert blocked
        assert reason == "Bad"

        blocked_ip, reason_ip = bl2.is_blocked("10.0.0.1")
        assert blocked_ip
        assert reason_ip == "Scanner"

        blocked_pattern, reason_pattern = bl2.is_blocked("bot.spam.aint")
        assert blocked_pattern
        assert reason_pattern == "Spam"

    def test_load_clears_existing(self):
        """load clears existing entries before loading new ones."""
        bl = BlockList()
        bl.block_ains("old.aint", "Old block")

        bl.load([{
            "identifier": "new.aint",
            "block_type": "ains",
            "reason": "New block",
        }])

        assert bl.count() == 1
        blocked_old, _ = bl.is_blocked("old.aint")
        assert not blocked_old
        blocked_new, _ = bl.is_blocked("new.aint")
        assert blocked_new

    def test_roundtrip_preserves_data(self):
        """Full export/load roundtrip preserves all data."""
        bl = BlockList()
        bl.block_ains("evil.aint", "Data exfil", blocked_by="root_idd")
        bl.block_ip("192.168.1.100", "Port scan", blocked_by="triage")
        bl.block_pattern("*.bad.aint", "Known bad", blocked_by="system")

        exported = bl.export()
        bl2 = BlockList()
        bl2.load(exported)
        re_exported = bl2.export()

        # Compare identifiers and reasons (timestamps may differ slightly due to from_dict)
        orig_ids = {e["identifier"] for e in exported}
        new_ids = {e["identifier"] for e in re_exported}
        assert orig_ids == new_ids

        orig_reasons = {e["reason"] for e in exported}
        new_reasons = {e["reason"] for e in re_exported}
        assert orig_reasons == new_reasons
