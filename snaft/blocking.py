"""
SNAFT BlockList — Network-level blocking by .aint domain, IP, or pattern.

Blocks are checked BEFORE agent identity evaluation. A blocked entity
cannot interact at all — it's a network-level deny, not an application-
level trust decision.

Every block/unblock generates a TIBET provenance token.
"""

import fnmatch
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class BlockEntry:
    """A single block list entry."""
    identifier: str          # domain, IP, or pattern
    block_type: str          # "ains", "ip", or "pattern"
    reason: str
    blocked_at: float = field(default_factory=time.time)
    blocked_by: str = "system"

    def to_dict(self) -> Dict:
        return {
            "identifier": self.identifier,
            "block_type": self.block_type,
            "reason": self.reason,
            "blocked_at": self.blocked_at,
            "blocked_by": self.blocked_by,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "BlockEntry":
        return cls(
            identifier=d["identifier"],
            block_type=d["block_type"],
            reason=d.get("reason", ""),
            blocked_at=d.get("blocked_at", time.time()),
            blocked_by=d.get("blocked_by", "system"),
        )


class BlockList:
    """Block agents by .aint domain, IP address, or wildcard pattern.

    Usage:
        bl = BlockList()
        bl.block_ains("evil.aint", "Rogue agent detected")
        bl.block_ip("192.168.1.100", "Port scan source")
        bl.block_pattern("*.spam.aint", "Known spam network")

        blocked, reason = bl.is_blocked("evil.aint")
        # (True, "Rogue agent detected")
    """

    def __init__(self) -> None:
        self._entries: Dict[str, BlockEntry] = {}

    def block_ains(self, domain: str, reason: str,
                   blocked_by: str = "system") -> BlockEntry:
        """Block an .aint domain."""
        domain = domain.lower().rstrip(".")
        if not domain.endswith(".aint"):
            domain = f"{domain}.aint"
        entry = BlockEntry(
            identifier=domain,
            block_type="ains",
            reason=reason,
            blocked_by=blocked_by,
        )
        self._entries[domain] = entry
        return entry

    def block_ip(self, ip: str, reason: str,
                 blocked_by: str = "system") -> BlockEntry:
        """Block an IP address."""
        entry = BlockEntry(
            identifier=ip,
            block_type="ip",
            reason=reason,
            blocked_by=blocked_by,
        )
        self._entries[ip] = entry
        return entry

    def block_pattern(self, pattern: str, reason: str,
                      blocked_by: str = "system") -> BlockEntry:
        """Block by wildcard pattern (fnmatch style).

        Examples: *.evil.aint, 192.168.1.*, bad_agent_*
        """
        entry = BlockEntry(
            identifier=pattern,
            block_type="pattern",
            reason=reason,
            blocked_by=blocked_by,
        )
        self._entries[pattern] = entry
        return entry

    def unblock(self, identifier: str) -> Optional[BlockEntry]:
        """Remove a block. Returns the removed entry, or None."""
        identifier = identifier.lower().rstrip(".")
        entry = self._entries.pop(identifier, None)
        if entry is None:
            # Try with .aint suffix
            entry = self._entries.pop(f"{identifier}.aint", None)
        return entry

    def is_blocked(self, identifier: str) -> Tuple[bool, str]:
        """Check if an identifier is blocked.

        Checks exact match first, then pattern matches.
        Returns (blocked: bool, reason: str).
        """
        identifier = identifier.lower().rstrip(".")

        # Exact match
        if identifier in self._entries:
            return (True, self._entries[identifier].reason)

        # Check with .aint suffix
        aint_id = f"{identifier}.aint" if not identifier.endswith(".aint") else identifier
        if aint_id in self._entries:
            return (True, self._entries[aint_id].reason)

        # Check without .aint suffix
        bare_id = identifier.removesuffix(".aint")
        if bare_id in self._entries:
            return (True, self._entries[bare_id].reason)

        # Pattern matching
        for key, entry in self._entries.items():
            if entry.block_type == "pattern":
                if fnmatch.fnmatch(identifier, entry.identifier):
                    return (True, entry.reason)
                if fnmatch.fnmatch(aint_id, entry.identifier):
                    return (True, entry.reason)

        return (False, "")

    def list_blocked(self) -> List[Dict]:
        """List all blocked entries."""
        return [e.to_dict() for e in self._entries.values()]

    def count(self) -> int:
        """Number of active blocks."""
        return len(self._entries)

    def clear(self) -> int:
        """Remove all blocks. Returns count removed."""
        count = len(self._entries)
        self._entries.clear()
        return count

    def load(self, entries: List[Dict]) -> None:
        """Load block entries from serialized dicts."""
        self._entries.clear()
        for d in entries:
            entry = BlockEntry.from_dict(d)
            self._entries[entry.identifier] = entry

    def export(self) -> List[Dict]:
        """Export all entries for persistence."""
        return [e.to_dict() for e in self._entries.values()]
