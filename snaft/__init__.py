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

__version__ = "1.3.0"

from .blocking import BlockList
from .companions import available_companions
from .compliance import AuditCategory, AuditRecord, ComplianceEngine, RiskLevel
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
from .kernel import TrustKernel
from .normalize import normalize, normalize_confusables, strip_dangerous_chars
from .provenance import ProvenanceChain, ProvenanceToken
from .rules_injection import check_injection
from .rules_encoded_injection import check_encoded_injection
from .encoded_decoder import (
    detect_encoding,
    is_printable_text,
    magic_bytes_detect,
    recursive_decode,
)
from .mux import NullRouteMux, NullRouteDecision, IPProfile
from .storage import Storage

__all__ = [
    # Core
    "Firewall",
    "Rule",
    "Action",
    # Blocking
    "BlockList",
    # Trust Kernel
    "TrustKernel",
    # Normalization (anti-bypass)
    "normalize",
    "normalize_confusables",
    "strip_dangerous_chars",
    # Injection detection
    "check_injection",
    # Storm Discovery: encoded payload injection (SNAFT-023)
    "check_encoded_injection",
    "detect_encoding",
    "is_printable_text",
    "magic_bytes_detect",
    "recursive_decode",
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
    # Compliance (EU AI Act)
    "ComplianceEngine",
    "AuditRecord",
    "AuditCategory",
    "RiskLevel",
    # Companions
    "available_companions",
    # Null-Route MUX
    "NullRouteMux",
    "NullRouteDecision",
    "IPProfile",
    # Storage
    "Storage",
]
