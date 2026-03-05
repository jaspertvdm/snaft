"""
SNAFT — Semantic Network-Aware Firewall for Trust

Not a guardrail. An immune system.

Usage:
    from snaft import Firewall

    fw = Firewall()
    allowed, token, trust = fw.check("my-agent", "read_file", "load config")

    if allowed:
        do_action(provenance=token)
    else:
        handle_block(token)

Or with full agent identity:

    from snaft import Firewall, AgentIdentity, Rule, Action

    fw = Firewall()
    agent = AgentIdentity(name="analyst")
    fw.register_agent(agent)

    fw.add_rule(Rule(
        name="allow-read",
        description="Allow file reads",
        action=Action.ALLOW,
        priority=10,
        check=lambda aid, erin, intent: "read" in intent,
    ))

    allowed, token, trust = fw.evaluate(agent, "read_file", "load config")
"""

__version__ = "0.1.1"

from .firewall import Action, Firewall, Rule
from .identity import (
    AgentIdentity,
    AgentState,
    FIRAScore,
    TRUST_DEGRADED,
    TRUST_FULL,
    TRUST_INITIAL,
    TRUST_ISOLATED,
)
from .provenance import ProvenanceChain, ProvenanceToken
from .storage import Storage

__all__ = [
    # Core
    "Firewall",
    "Rule",
    "Action",
    # Identity
    "AgentIdentity",
    "AgentState",
    "FIRAScore",
    # Trust thresholds
    "TRUST_FULL",
    "TRUST_DEGRADED",
    "TRUST_ISOLATED",
    "TRUST_INITIAL",
    # Provenance
    "ProvenanceToken",
    "ProvenanceChain",
    # Storage
    "Storage",
]
