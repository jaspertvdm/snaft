"""
SNAFT Provenance — Lightweight TIBET token generation for firewall decisions.

Every firewall decision generates a cryptographic provenance token.
No decision without evidence. No action without a trail.

Token structure (TIBET):
    ERIN      — What's IN the action (the content being checked)
    ERAAN     — What's attached (dependencies, prior tokens)
    EROMHEEN  — Context around the action (environment, state)
    ERACHTER  — Intent behind the action (why this is happening)
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProvenanceToken:
    """Cryptographic evidence of a firewall decision."""

    token_id: str
    timestamp: float
    agent_id: str
    action: str          # "ALLOW", "BLOCK", "WARN", "ISOLATE"
    rule_name: str       # Which rule triggered
    reason: str          # Human-readable reason

    # TIBET dimensions
    erin: str            # Hash of what was checked (content)
    eraan: str           # Parent token ID (chain link)
    eromheen: str        # Hash of context
    erachter: str        # Intent that was evaluated

    # Integrity
    signature: str = ""  # HMAC of all fields
    chain_depth: int = 0

    @property
    def is_allow(self) -> bool:
        return self.action == "ALLOW"

    @property
    def is_block(self) -> bool:
        return self.action == "BLOCK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "action": self.action,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "erin": self.erin,
            "eraan": self.eraan,
            "eromheen": self.eromheen,
            "erachter": self.erachter,
            "signature": self.signature,
            "chain_depth": self.chain_depth,
        }

    def __str__(self) -> str:
        icon = {"ALLOW": "\u2705", "BLOCK": "\U0001f6d1", "WARN": "\u26a0\ufe0f", "ISOLATE": "\U0001f6a8"}.get(self.action, "?")
        return f"{icon} [{self.token_id[:12]}] {self.action} agent={self.agent_id} rule={self.rule_name}"


class ProvenanceChain:
    """Maintains an append-only chain of provenance tokens."""

    def __init__(self, secret_key: str = "snaft-default-key"):
        self._chain: List[ProvenanceToken] = []
        self._secret = secret_key.encode()

    def _hash_content(self, content: Any) -> str:
        """Create deterministic hash of content."""
        raw = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _generate_id(self, agent_id: str, timestamp: float) -> str:
        """Generate unique token ID."""
        raw = f"{agent_id}:{timestamp}:{len(self._chain)}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:12]
        return f"SNAFT-{h.upper()}"

    def _sign(self, token: ProvenanceToken) -> str:
        """HMAC signature over all token fields."""
        import hmac
        payload = (
            f"{token.token_id}:{token.timestamp}:{token.agent_id}:"
            f"{token.action}:{token.rule_name}:{token.erin}:"
            f"{token.eraan}:{token.eromheen}:{token.erachter}"
        )
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()[:24]

    def mint(
        self,
        agent_id: str,
        action: str,
        rule_name: str,
        reason: str,
        erin: Any,
        erachter: str,
        eromheen: Optional[Dict] = None,
        parent_token: Optional[ProvenanceToken] = None,
    ) -> ProvenanceToken:
        """Mint a new provenance token for a firewall decision."""
        now = time.time()
        token_id = self._generate_id(agent_id, now)

        token = ProvenanceToken(
            token_id=token_id,
            timestamp=now,
            agent_id=agent_id,
            action=action,
            rule_name=rule_name,
            reason=reason,
            erin=self._hash_content(erin),
            eraan=parent_token.token_id if parent_token else "GENESIS",
            eromheen=self._hash_content(eromheen or {}),
            erachter=erachter,
            chain_depth=(parent_token.chain_depth + 1) if parent_token else 0,
        )
        token.signature = self._sign(token)

        self._chain.append(token)
        return token

    def verify(self, token: ProvenanceToken) -> bool:
        """Verify a token's signature integrity."""
        expected = self._sign(token)
        return token.signature == expected

    def get_chain(self, agent_id: Optional[str] = None) -> List[ProvenanceToken]:
        """Get the full chain, optionally filtered by agent."""
        if agent_id:
            return [t for t in self._chain if t.agent_id == agent_id]
        return list(self._chain)

    def get_last(self, agent_id: str) -> Optional[ProvenanceToken]:
        """Get the last token for an agent."""
        for t in reversed(self._chain):
            if t.agent_id == agent_id:
                return t
        return None

    @property
    def depth(self) -> int:
        return len(self._chain)

    def export(self) -> List[Dict]:
        """Export full chain as list of dicts."""
        return [t.to_dict() for t in self._chain]
