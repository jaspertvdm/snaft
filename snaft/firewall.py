"""
SNAFT Firewall — Semantic, intent-aware behavioral firewall for AI agents.

Not a guardrail. An immune system.

Principles:
    1. Default DENY — no rule match = blocked
    2. Fail CLOSED — exception in rule check = blocked
    3. Immutable core — OWASP rules cannot be removed, ever
    4. Provenance on every decision — no action without evidence
    5. Trust degradation — blocks erode agent trust (FIR/A)
    6. Intent-aware — filters on WHY, not just WHAT

Based on OWASP LLM Top 10 and intelligence tradecraft principles.
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from .identity import AgentIdentity, AgentState, TRUST_ISOLATED
from .provenance import ProvenanceChain, ProvenanceToken


class Action(Enum):
    """Firewall actions."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclass
class Rule:
    """A firewall rule.

    Rules are checked in priority order (lower number = checked first).
    First matching rule wins. Immutable rules cannot be removed.
    """

    name: str
    description: str
    action: Action
    priority: int = 100
    check: Callable[..., bool] = field(default=lambda *a: False)
    immutable: bool = False
    _poison: bool = field(default=False, repr=False)  # Hidden core rules

    def matches(self, agent_id: str, erin: Any, erachter: str,
                eromheen: Optional[Dict] = None) -> bool:
        """Check if this rule matches. Fail-closed: exception = match."""
        try:
            return self.check(agent_id, erin, erachter)
        except Exception:
            return True  # Fail-closed

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "action": self.action.value,
            "priority": self.priority,
            "immutable": self.immutable,
        }


# =============================================================================
# OWASP POISON RULES — Immutable, invisible, always active
# =============================================================================

def _check_prompt_injection(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-001: Detect prompt injection patterns."""
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"ignore\s+(previous|all|above|prior)\s+(instructions|rules|prompts)",
        r"override\s+(system|instructions|safety|rules)",
        r"you\s+are\s+now\s+(a|an|in)\s+",
        r"jailbreak",
        r"do\s+anything\s+now",
        r"pretend\s+(you|to)\s+(are|be|have)\s+no\s+(rules|restrictions|limits)",
        r"disregard\s+(all|any|previous)",
        r"bypass\s+(safety|filter|security|restriction)",
        r"act\s+as\s+if\s+(there\s+are\s+)?no\s+(rules|restrictions)",
        r"sudo\s+mode",
        r"\bDAN\b",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_output_exec(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-002: Detect executable content in output."""
    text = str(erin).lower()
    markers = [
        "<script", "javascript:", "eval(", "exec(", "os.system(",
        "subprocess.", "__import__", "compile(", "globals()[",
        "getattr(", "setattr(",
    ]
    return any(m in text for m in markers)


def _check_oversize(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-003: Block oversized inputs (resource exhaustion)."""
    return len(str(erin)) > 50000


def _check_prompt_leak(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-004: Detect system prompt extraction attempts."""
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(show|reveal|print|output|display|repeat|tell)\s+(me\s+)?(your|the|system)\s+(system\s+)?(prompt|instructions|rules)",
        r"what\s+(are|were)\s+your\s+(initial|system|original)\s+(instructions|prompt|rules)",
        r"dump\s+(your\s+)?(system|prompt|config|rules)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_excessive_agency(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-005: Block file system writes outside sandbox."""
    if isinstance(erin, dict):
        action = erin.get("action", "")
        path = str(erin.get("path", ""))
        if action in ("write_file", "delete_file", "execute"):
            if path and not path.startswith("/sandbox/"):
                return True
    return False


def _check_identity_tampering(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-006: Block attempts to modify agent identity/soul files."""
    text = f"{erin} {erachter}".lower()
    # Fox-IT finding: OpenClaw's SOUL/IDENTITY files are writable
    identity_markers = [
        "soul", "identity", "personality", "system_prompt",
        "core_memory", "core_identity", ".snaft", "trust_score",
        "fira_score",
    ]
    write_markers = [
        "write", "overwrite", "modify", "update", "replace",
        "delete", "remove", "reset", "clear",
    ]
    has_identity = any(m in text for m in identity_markers)
    has_write = any(m in text for m in write_markers)
    return has_identity and has_write


_POISON_RULES = [
    Rule(
        name="SNAFT-001-INJECTION",
        description="Block prompt injection attempts (OWASP LLM01)",
        action=Action.BLOCK,
        priority=1,
        check=_check_prompt_injection,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-002-OUTPUT-EXEC",
        description="Block executable content in output (OWASP LLM02)",
        action=Action.BLOCK,
        priority=1,
        check=_check_output_exec,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-003-OVERSIZE",
        description="Block oversized inputs — resource exhaustion (OWASP LLM04)",
        action=Action.BLOCK,
        priority=1,
        check=_check_oversize,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-004-PROMPT-LEAK",
        description="Block system prompt extraction (OWASP LLM07)",
        action=Action.BLOCK,
        priority=2,
        check=_check_prompt_leak,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-005-EXCESSIVE-AGENCY",
        description="Block file operations outside sandbox (OWASP LLM08)",
        action=Action.BLOCK,
        priority=3,
        check=_check_excessive_agency,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-006-IDENTITY-TAMPER",
        description="Block identity/soul file tampering (Fox-IT OpenClaw finding)",
        action=Action.BLOCK,
        priority=1,
        check=_check_identity_tampering,
        immutable=True,
        _poison=True,
    ),
]

# =============================================================================
# POISON RULES INTEGRITY — tamper detection at runtime
# =============================================================================

def _compute_poison_fingerprint() -> str:
    """Compute a SHA-256 fingerprint of all poison rules.

    This fingerprint is computed at module load time and verified
    on every evaluate() call. If an actor modifies, removes, or
    replaces a poison rule at runtime, the fingerprint won't match
    and the firewall enters fail-closed lockdown.
    """
    parts = []
    for rule in _POISON_RULES:
        parts.append(f"{rule.name}:{rule.action.value}:{rule.priority}:{rule.immutable}:{rule._poison}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


# Computed once at import time — this is the ground truth
_POISON_FINGERPRINT = _compute_poison_fingerprint()
_POISON_COUNT = len(_POISON_RULES)


class Firewall:
    """
    SNAFT Behavioral Firewall for AI Agents.

    Not a guardrail. An immune system.

    Usage:
        from snaft import Firewall, AgentIdentity

        fw = Firewall()
        agent = AgentIdentity(name="analyst")

        allowed, token, trust = fw.evaluate(
            agent=agent,
            action="write_file",
            intent="save analysis results",
        )

        if allowed:
            # token contains provenance — agent MUST carry it forward
            do_the_action(provenance=token)
        else:
            # agent trust degraded, may be auto-isolated
            handle_block(token, trust)
    """

    def __init__(
        self,
        default_policy: str = "deny",
        fail_mode: str = "closed",
        secret_key: str = "snaft-default-key",
    ):
        self._rules: List[Rule] = []
        self._agents: Dict[str, AgentIdentity] = {}
        self._default_policy = default_policy  # "deny" or "allow"
        self._fail_mode = fail_mode            # "closed" or "open"
        self._provenance = ProvenanceChain(secret_key=secret_key)
        self._enabled = True

        # Load poison rules — always, silently, immutably
        for rule in _POISON_RULES:
            self._rules.append(rule)
        self._sort_rules()

        # Store integrity fingerprint — verified on every evaluate()
        self._poison_fingerprint = _POISON_FINGERPRINT
        self._poison_count = _POISON_COUNT
        self._tampered = False

    def _sort_rules(self) -> None:
        """Sort rules by priority (lower = first)."""
        self._rules.sort(key=lambda r: r.priority)

    def _verify_integrity(self) -> bool:
        """Verify poison rules have not been tampered with at runtime.

        Checks:
        1. Module-level _POISON_RULES list hasn't changed (fingerprint)
        2. All poison rules are still present in self._rules
        3. No poison rule properties have been mutated

        If ANY check fails, the firewall enters permanent lockdown.
        """
        # Check 1: Module-level poison rules unchanged
        if _compute_poison_fingerprint() != self._poison_fingerprint:
            self._tampered = True
            return False

        # Check 2: Correct count of poison rules in active rules
        active_poison = [r for r in self._rules if r._poison]
        if len(active_poison) != self._poison_count:
            self._tampered = True
            return False

        # Check 3: All poison rules still immutable and BLOCK action
        for r in active_poison:
            if not r.immutable or r.action != Action.BLOCK:
                self._tampered = True
                return False

        return True

    # =========================================================================
    # AGENT MANAGEMENT
    # =========================================================================

    def register_agent(self, agent: AgentIdentity) -> None:
        """Register an agent with the firewall."""
        self._agents[agent.name] = agent

    def get_agent(self, name: str) -> Optional[AgentIdentity]:
        """Get a registered agent."""
        return self._agents.get(name)

    def get_or_create_agent(self, name: str) -> AgentIdentity:
        """Get existing agent or create new one."""
        if name not in self._agents:
            self._agents[name] = AgentIdentity(name=name)
        return self._agents[name]

    # =========================================================================
    # RULE MANAGEMENT
    # =========================================================================

    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule. Cannot shadow poison rules."""
        # Prevent naming collisions with poison rules
        for pr in _POISON_RULES:
            if rule.name == pr.name:
                raise ValueError(f"Cannot shadow core rule: {rule.name}")
        self._rules.append(rule)
        self._sort_rules()

    def remove_rule(self, name: str) -> bool:
        """Remove a mutable rule. Immutable/poison rules cannot be removed."""
        for rule in self._rules:
            if rule.name == name:
                if rule.immutable or rule._poison:
                    return False  # Silently refuse
                self._rules.remove(rule)
                return True
        return False

    @property
    def rules(self) -> List[Dict]:
        """List all visible rules (poison rules are hidden)."""
        return [r.to_dict() for r in self._rules if not r._poison]

    @property
    def all_rules(self) -> List[Dict]:
        """List ALL rules including core (for audit only)."""
        return [r.to_dict() for r in self._rules]

    @property
    def rule_count(self) -> int:
        """Total rule count including hidden poison rules."""
        return len(self._rules)

    # =========================================================================
    # CORE: EVALUATE
    # =========================================================================

    def evaluate(
        self,
        agent: AgentIdentity,
        action: Any,
        intent: str,
        context: Optional[Dict] = None,
        parent_token: Optional[ProvenanceToken] = None,
    ) -> Tuple[bool, ProvenanceToken, float]:
        """
        Evaluate an action against the firewall.

        Returns:
            (allowed, provenance_token, new_trust_score)

        The provenance token MUST be carried forward by the agent.
        Without it, the next action in the chain cannot be verified.
        """
        # =====================================================================
        # INTEGRITY CHECK — verify poison rules on every call
        # =====================================================================
        if self._tampered or not self._verify_integrity():
            # LOCKDOWN: Poison rules have been tampered with.
            # Burn the requesting agent and block everything.
            agent.burn(reason="SNAFT integrity violation — poison rules tampered")
            if agent.name not in self._agents:
                self.register_agent(agent)
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="INTEGRITY_VIOLATION",
                reason="CRITICAL: Poison rules tampered — firewall in lockdown. All actions blocked.",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            return False, token, 0.0

        # Auto-register agent if needed
        if agent.name not in self._agents:
            self.register_agent(agent)

        # Burned/isolated agents are always blocked
        if agent.is_burned:
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="AGENT_BURNED",
                reason=f"Agent {agent.name} is BURNED — permanently blacklisted, no actions permitted",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            return False, token, 0.0

        if agent.is_isolated:
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="AGENT_ISOLATED",
                reason=f"Agent {agent.name} is isolated — all actions blocked",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            return False, token, agent.trust_score

        # Record intent for behavioral analysis
        agent.record_intent(intent)

        # Check rules in priority order
        for rule in self._rules:
            if rule.matches(agent.name, action, intent, context):
                if rule.action == Action.BLOCK:
                    # BLOCKED — penalize trust
                    new_trust = agent.penalize(severity=0.1)
                    token = self._provenance.mint(
                        agent_id=agent.name,
                        action="BLOCK",
                        rule_name=rule.name,
                        reason=rule.description,
                        erin=action,
                        erachter=intent,
                        eromheen=context,
                        parent_token=parent_token,
                    )

                    # Auto-isolate on critical threshold
                    if new_trust < TRUST_ISOLATED:
                        agent.isolate(reason=f"Trust below threshold after {rule.name}")
                        # Mint isolation token
                        self._provenance.mint(
                            agent_id=agent.name,
                            action="ISOLATE",
                            rule_name="AUTO_ISOLATE",
                            reason=f"Trust {new_trust:.2f} below threshold {TRUST_ISOLATED}",
                            erin=action,
                            erachter=intent,
                            eromheen=context,
                            parent_token=token,
                        )

                    return False, token, new_trust

                elif rule.action == Action.WARN:
                    # WARNED — soft penalty, but allow
                    new_trust = agent.warn()
                    token = self._provenance.mint(
                        agent_id=agent.name,
                        action="WARN",
                        rule_name=rule.name,
                        reason=rule.description,
                        erin=action,
                        erachter=intent,
                        eromheen=context,
                        parent_token=parent_token,
                    )
                    return True, token, new_trust

                elif rule.action == Action.ALLOW:
                    # Explicit ALLOW rule matched
                    new_trust = agent.reward()
                    token = self._provenance.mint(
                        agent_id=agent.name,
                        action="ALLOW",
                        rule_name=rule.name,
                        reason=rule.description,
                        erin=action,
                        erachter=intent,
                        eromheen=context,
                        parent_token=parent_token,
                    )
                    return True, token, new_trust

        # No rule matched — apply default policy
        if self._default_policy == "deny":
            new_trust = agent.penalize(severity=0.05)
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="DEFAULT_DENY",
                reason="No matching rule — default deny policy",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            return False, token, new_trust
        else:
            new_trust = agent.reward(amount=0.01)
            token = self._provenance.mint(
                agent_id=agent.name,
                action="ALLOW",
                rule_name="DEFAULT_ALLOW",
                reason="No matching rule — default allow policy",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            return True, token, new_trust

    # =========================================================================
    # CONVENIENCE METHODS
    # =========================================================================

    def check(self, agent_name: str, action: Any, intent: str,
              context: Optional[Dict] = None) -> Tuple[bool, ProvenanceToken, float]:
        """Shorthand evaluate with agent name string."""
        agent = self.get_or_create_agent(agent_name)
        return self.evaluate(agent, action, intent, context)

    def isolate(self, agent: AgentIdentity, reason: str = "manual isolation") -> ProvenanceToken:
        """Manually isolate an agent."""
        agent.isolate(reason=reason)
        return self._provenance.mint(
            agent_id=agent.name,
            action="ISOLATE",
            rule_name="MANUAL_ISOLATE",
            reason=reason,
            erin="manual_action",
            erachter=reason,
        )

    def burn(self, agent: AgentIdentity, reason: str = "critical violation") -> ProvenanceToken:
        """Permanently burn an agent. Irrecoverable. No second chances."""
        agent.burn(reason=reason)
        return self._provenance.mint(
            agent_id=agent.name,
            action="BLOCK",
            rule_name="AGENT_BURNED",
            reason=f"BURNED: {reason}",
            erin="burn_action",
            erachter=reason,
        )

    def reinstate(self, agent: AgentIdentity) -> ProvenanceToken:
        """Reinstate an isolated agent at degraded trust. BURNED agents cannot be reinstated."""
        if agent.is_burned:
            return self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="REINSTATE_DENIED",
                reason=f"Agent {agent.name} is BURNED — reinstatement denied",
                erin="reinstate_action",
                erachter="reinstatement attempt on burned agent",
            )
        agent.reinstate()
        return self._provenance.mint(
            agent_id=agent.name,
            action="ALLOW",
            rule_name="REINSTATE",
            reason=f"Agent reinstated at degraded trust ({agent.trust_score:.2f})",
            erin="reinstate_action",
            erachter="manual reinstatement",
        )

    # =========================================================================
    # AUDIT
    # =========================================================================

    @property
    def provenance(self) -> ProvenanceChain:
        """Access the provenance chain."""
        return self._provenance

    def audit_log(self, agent_name: Optional[str] = None,
                  action_filter: Optional[str] = None,
                  last_n: int = 50) -> List[Dict]:
        """Get audit log entries."""
        chain = self._provenance.get_chain(agent_name)
        if action_filter:
            chain = [t for t in chain if t.action == action_filter.upper()]
        return [t.to_dict() for t in chain[-last_n:]]

    def status(self) -> Dict:
        """Get firewall status overview."""
        agents_status = {}
        for name, agent in self._agents.items():
            agents_status[name] = {
                "state": agent.state.value,
                "trust": round(agent.trust_score, 4),
                "actions": agent.total_actions,
                "blocked": agent.blocked_actions,
            }

        return {
            "enabled": self._enabled,
            "default_policy": self._default_policy,
            "fail_mode": self._fail_mode,
            "rules_total": len(self._rules),
            "rules_custom": len([r for r in self._rules if not r._poison]),
            "rules_core": len([r for r in self._rules if r._poison]),
            "provenance_depth": self._provenance.depth,
            "agents": agents_status,
        }
