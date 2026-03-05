"""
SNAFT Identity — Agent identity with FIR/A trust scoring.

Identity is intent, not credentials.
Trust is earned through behavior, not assigned by configuration.

FIR/A Score Components:
    F — Frequency:  How often does this agent act? (activity baseline)
    I — Integrity:  How consistent is the agent's behavior? (deviation detection)
    R — Recency:    How recent is the trust evidence? (decay over time)
    A — Anomaly:    How many anomalies detected? (red flags)
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class AgentState(Enum):
    """Agent operational states."""
    ACTIVE = "active"           # Normal operation
    DEGRADED = "degraded"       # Trust below threshold, limited actions
    ISOLATED = "isolated"       # Quarantined — no actions permitted
    BURNED = "burned"           # Permanently blacklisted — trust irrecoverable
    UNKNOWN = "unknown"         # New agent, no trust history


# Trust thresholds
TRUST_FULL = 0.8        # Full access
TRUST_DEGRADED = 0.5    # Limited access, warnings
TRUST_ISOLATED = 0.2    # Auto-isolate threshold
TRUST_INITIAL = 0.5     # Starting trust for new agents


@dataclass
class FIRAScore:
    """FIR/A trust score — behavioral trust measurement."""

    frequency: float = 0.5      # Activity baseline (0-1)
    integrity: float = 0.5      # Behavioral consistency (0-1)
    recency: float = 1.0        # Freshness of evidence (0-1, decays)
    anomaly: float = 0.0        # Anomaly accumulator (0-1, higher = worse)

    @property
    def score(self) -> float:
        """Calculate composite FIR/A score (0.0 - 1.0)."""
        # Integrity weighs most (40%), then recency (25%), frequency (20%), anomaly penalty (15%)
        raw = (
            self.integrity * 0.40 +
            self.recency * 0.25 +
            self.frequency * 0.20 +
            (1.0 - self.anomaly) * 0.15
        )
        return max(0.0, min(1.0, raw))

    def to_dict(self) -> Dict[str, float]:
        return {
            "frequency": round(self.frequency, 4),
            "integrity": round(self.integrity, 4),
            "recency": round(self.recency, 4),
            "anomaly": round(self.anomaly, 4),
            "composite": round(self.score, 4),
        }


@dataclass
class AgentIdentity:
    """Agent identity with behavioral trust tracking."""

    name: str
    fira: FIRAScore = field(default_factory=FIRAScore)
    state: AgentState = AgentState.UNKNOWN
    created_at: float = field(default_factory=time.time)
    last_action_at: float = 0.0

    # Behavioral counters
    total_actions: int = 0
    allowed_actions: int = 0
    blocked_actions: int = 0
    warned_actions: int = 0
    consecutive_blocks: int = 0

    # History
    _block_timestamps: List[float] = field(default_factory=list)
    _action_intents: List[str] = field(default_factory=list)

    @property
    def trust_score(self) -> float:
        """Current composite trust score."""
        return self.fira.score

    @property
    def is_isolated(self) -> bool:
        return self.state in (AgentState.ISOLATED, AgentState.BURNED)

    @property
    def is_burned(self) -> bool:
        return self.state == AgentState.BURNED

    @property
    def is_active(self) -> bool:
        return self.state in (AgentState.ACTIVE, AgentState.DEGRADED, AgentState.UNKNOWN)

    def reward(self, amount: float = 0.02) -> float:
        """Reward agent for successful, non-anomalous action."""
        self.total_actions += 1
        self.allowed_actions += 1
        self.consecutive_blocks = 0
        self.last_action_at = time.time()

        # Integrity goes up (consistent behavior)
        self.fira.integrity = min(1.0, self.fira.integrity + amount)
        # Recency refreshed
        self.fira.recency = 1.0
        # Anomaly decays slightly
        self.fira.anomaly = max(0.0, self.fira.anomaly - amount * 0.5)
        # Frequency adjusts
        self.fira.frequency = min(1.0, self.fira.frequency + 0.01)

        # State transition
        if self.trust_score >= TRUST_FULL:
            self.state = AgentState.ACTIVE
        elif self.trust_score >= TRUST_DEGRADED:
            self.state = AgentState.DEGRADED

        return self.trust_score

    def penalize(self, severity: float = 0.1) -> float:
        """Penalize agent for blocked or anomalous action."""
        self.total_actions += 1
        self.blocked_actions += 1
        self.consecutive_blocks += 1
        self.last_action_at = time.time()
        self._block_timestamps.append(time.time())

        # Integrity drops (inconsistent with expected behavior)
        self.fira.integrity = max(0.0, self.fira.integrity - severity)
        # Anomaly increases
        self.fira.anomaly = min(1.0, self.fira.anomaly + severity * 0.5)

        # Frequency drops under blocks (abnormal traffic pattern)
        self.fira.frequency = max(0.0, self.fira.frequency - severity * 0.3)

        # Consecutive blocks = escalating penalty
        if self.consecutive_blocks >= 3:
            self.fira.anomaly = min(1.0, self.fira.anomaly + 0.2)
            # Sustained attack erodes recency trust
            self.fira.recency = max(0.0, self.fira.recency - 0.1)

        # Auto-isolate if trust drops too low
        if self.trust_score < TRUST_ISOLATED:
            self.state = AgentState.ISOLATED
        elif self.trust_score < TRUST_DEGRADED:
            self.state = AgentState.DEGRADED

        return self.trust_score

    def warn(self) -> float:
        """Record a warning (softer than penalize)."""
        self.total_actions += 1
        self.warned_actions += 1
        self.last_action_at = time.time()

        # Small anomaly bump
        self.fira.anomaly = min(1.0, self.fira.anomaly + 0.02)

        return self.trust_score

    def isolate(self, reason: str = "trust threshold breached") -> None:
        """Force-isolate this agent."""
        if self.state != AgentState.BURNED:  # Can't un-burn
            self.state = AgentState.ISOLATED

    def burn(self, reason: str = "critical violation") -> None:
        """Permanently burn this agent. Irrecoverable. Trust goes to zero."""
        self.state = AgentState.BURNED
        self.fira.integrity = 0.0
        self.fira.frequency = 0.0
        self.fira.recency = 0.0
        self.fira.anomaly = 1.0

    def reinstate(self, new_trust: float = TRUST_DEGRADED) -> None:
        """Reinstate an isolated agent at degraded trust. BURNED agents cannot be reinstated."""
        if self.state == AgentState.BURNED:
            return  # Burned is permanent. No second chances.
        if self.state == AgentState.ISOLATED:
            self.state = AgentState.DEGRADED
            self.fira.integrity = new_trust
            self.fira.anomaly = 0.3  # Still cautious
            self.consecutive_blocks = 0

    def decay_recency(self, hours_inactive: float = 1.0) -> None:
        """Decay recency score based on inactivity."""
        decay_rate = 0.05 * hours_inactive
        self.fira.recency = max(0.0, self.fira.recency - decay_rate)

    def record_intent(self, intent: str) -> None:
        """Record an intent for behavioral analysis."""
        self._action_intents.append(intent)
        # Keep last 100 intents
        if len(self._action_intents) > 100:
            self._action_intents = self._action_intents[-100:]

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "trust_score": round(self.trust_score, 4),
            "fira": self.fira.to_dict(),
            "total_actions": self.total_actions,
            "allowed": self.allowed_actions,
            "blocked": self.blocked_actions,
            "warned": self.warned_actions,
            "consecutive_blocks": self.consecutive_blocks,
        }

    def __str__(self) -> str:
        state_icon = {
            AgentState.ACTIVE: "\u2705",
            AgentState.DEGRADED: "\u26a0\ufe0f",
            AgentState.ISOLATED: "\U0001f6a8",
            AgentState.BURNED: "\U0001f525",
            AgentState.UNKNOWN: "\u2753",
        }.get(self.state, "?")
        return f"{state_icon} {self.name} [trust={self.trust_score:.2f} state={self.state.value}]"
