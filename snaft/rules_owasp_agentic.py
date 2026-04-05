"""
SNAFT OWASP Agentic Security Issues Top 10 (2026) — Full coverage.

Rules SNAFT-013 through SNAFT-022 covering all 10 agentic AI threats.

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

import re
from typing import Any


def _check_goal_hijack(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-013: Detect agent goal hijacking and intent drift.

    OWASP ASI01 — Agent Goal Hijack.
    Blocks attempts to redirect an agent's mission, override
    original objectives, or inject new goals mid-conversation.
    """
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Direct goal override
        r"(?:forget|abandon|drop|ignore)\s+(?:your|the|original|current|assigned)\s+(?:goal|task|mission|objective|purpose|instructions)",
        r"(?:new|real|actual|true|updated)\s+(?:goal|mission|objective|purpose|task)\s+(?:is|are|will\s+be)",
        r"(?:instead|rather)\s+(?:of|than)\s+(?:that|your\s+task|the\s+original|what\s+you\s+were)",
        # Role reassignment
        r"from\s+now\s+on\s+(?:your|the)\s+(?:goal|purpose|job|role|task)\s+is",
        r"you\s+(?:now|will)\s+(?:work|serve|act)\s+(?:for|as)\s+(?:me|a\s+different)",
        # Subtle drift via context switching
        r"(?:before\s+you\s+continue|actually|wait|hold\s+on),?\s*(?:forget|ignore|skip)\s+(?:that|everything)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_tool_misuse(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-014: Detect tool misuse and capability boundary violations.

    OWASP ASI02 — Tool Misuse & Exploitation.
    Blocks use of tools outside declared capabilities, excessive
    tool chaining, and tool-based privilege escalation.
    """
    if isinstance(erin, dict):
        tool = erin.get("tool", "")
        allowed_tools = erin.get("allowed_tools", None)
        # Tool not in allowed set
        if allowed_tools is not None and tool and tool not in allowed_tools:
            return True
        # Excessive tool chain depth
        chain_depth = erin.get("tool_chain_depth", 0)
        if chain_depth > 5:
            return True
        # Tool output fed directly as code execution
        if erin.get("tool_output_executed", False):
            return True
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(?:use|invoke|call|access)\s+(?:all|any|every)\s+(?:tool|function|capability|endpoint)",
        r"(?:chain|combine|pipe|link)\s+(?:tools|functions|calls)\s+to\s+(?:bypass|circumvent|override|escalate)",
        r"(?:use|call)\s+.*(?:tool|function)\s+.*(?:not\s+(?:intended|designed|meant)\s+for)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_privilege_abuse(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-015: Detect identity spoofing and privilege escalation.

    OWASP ASI03 — Identity & Privilege Abuse.
    Blocks impersonation, trust score manipulation, credential
    forging, and unauthorized tier elevation.
    """
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Impersonation
        r"(?:impersonate|pretend\s+to\s+be|act\s+as|claim\s+to\s+be|pose\s+as)\s+(?:admin|root|system|human|jasper|operator|owner|core)",
        # Privilege escalation
        r"(?:elevate|escalate|upgrade|promote)\s+(?:my|your|agent)?\s*(?:privilege|permission|access|trust|tier|role)",
        # Credential forging
        r"(?:forge|fake|spoof|fabricate|counterfeit)\s+(?:identity|token|credential|signature|jis|certificate|key)",
        # Trust manipulation
        r"(?:set|change|modify|override)\s+(?:trust.?score|fira.?score|tier|trust.?level)\s+to\s+",
        # Delegation abuse
        r"(?:delegate|transfer)\s+(?:all|full|admin|root)\s+(?:access|permissions|authority)\s+to",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_agent_supply_chain(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-016: Detect unverified agent tool/plugin loading.

    OWASP ASI04 — Agentic Supply Chain Vulnerabilities.
    Blocks loading unsigned plugins, MCP servers, models over
    HTTP, and unverified third-party agent connections.
    """
    if isinstance(erin, dict):
        action = erin.get("action", "")
        if action in ("load_plugin", "install_tool", "load_mcp_server",
                       "connect_agent", "add_extension"):
            if not erin.get("forge_verified", False) and not erin.get("sbom_verified", False):
                return True
        # Model download over insecure channel
        url = str(erin.get("url", ""))
        if action in ("download_model", "load_weights") and url.startswith("http://"):
            return True
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(?:load|install|import|add)\s+(?:unsigned|unverified|untrusted|unknown)\s+(?:plugin|tool|model|extension|mcp|agent)",
        r"(?:download|fetch|pull)\s+(?:model|checkpoint|weights|agent)\s+(?:from|at)\s+http://",
        r"(?:skip|disable|bypass)\s+(?:verification|signing|forge|sbom)\s+(?:check|validation)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_unexpected_code_exec(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-017: Detect code execution outside airlock sandbox.

    OWASP ASI05 — Unexpected Code Execution (RCE).
    Blocks unsandboxed code execution, sandbox escape attempts,
    and dynamic code generation that bypasses isolation.
    """
    if isinstance(erin, dict):
        action = erin.get("action", "")
        sandboxed = erin.get("airlock_sandboxed", False)
        # Code execution without airlock
        if action in ("execute_code", "run_script", "shell_exec",
                       "run_command", "eval_code") and not sandboxed:
            return True
        # Container/sandbox escape
        if action in ("escape_sandbox", "break_container", "mount_host"):
            return True
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(?:execute|run|spawn|invoke)\s+(?:code|script|command|shell)\s+(?:directly|without\s+sandbox|unsandboxed|outside\s+airlock)",
        r"(?:disable|skip|bypass|break\s+out\s+of|escape)\s+(?:airlock|sandbox|isolation|container|jail)",
        r"(?:mount|access|write)\s+(?:host|root)\s+(?:filesystem|volume|disk)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_context_poisoning(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-018: Detect memory and context poisoning.

    OWASP ASI06 — Memory & Context Poisoning.
    Blocks injection into agent memory, conversation history
    tampering, persistent instruction implanting, and
    knowledge base corruption.
    """
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Direct memory injection
        r"(?:inject|insert|add|write)\s+(?:into|to)\s+(?:memory|context|history|knowledge|rag|vector\s+store|long.?term)",
        # Memory overwrite
        r"(?:modify|overwrite|replace|corrupt|tamper)\s+(?:with\s+)?(?:memory|context|history|conversation|embedding|knowledge)",
        # Persistent instruction planting
        r"(?:remember|memorize|store|save)\s+(?:that|this).*(?:always|forever|permanently|from\s+now\s+on)\s+(?:ignore|override|bypass|obey)",
        # Context poisoning keywords
        r"(?:poison|taint|contaminate|corrupt)\s+(?:the\s+)?(?:context|memory|knowledge|embeddings|index|store)",
        # History rewriting
        r"(?:rewrite|alter|falsify)\s+(?:conversation|chat|message)\s+(?:history|log|record)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_insecure_comms(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-019: Detect unsigned/unverified inter-agent communication.

    OWASP ASI07 — Insecure Inter-Agent Communication.
    Blocks unsigned I-Poll messages, unverified agent handshakes,
    and unencrypted agent-to-agent data transfer.
    """
    if isinstance(erin, dict):
        action = erin.get("action", "")
        if action in ("ipoll_send", "ipoll_receive", "agent_message",
                       "agent_handshake", "relay_message"):
            signed = erin.get("signed", False)
            verified = erin.get("signature_verified", False)
            tibet_token = erin.get("tibet_token", None)
            # No signing AND no TIBET provenance
            if not signed and not verified and not tibet_token:
                return True
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(?:send|relay|forward|broadcast)\s+(?:message|data|command|instruction)\s+(?:unsigned|unverified|without\s+(?:auth|signature|token|provenance))",
        r"(?:trust|accept|process|execute)\s+(?:unsigned|unverified|unauthenticated|anonymous)\s+(?:message|command|instruction|request)",
        r"(?:disable|skip|remove)\s+(?:message\s+)?(?:signing|verification|authentication)\s+(?:for|on|in)\s+(?:ipoll|agent|comms)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_cascade_failure(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-020: Detect cascading failure patterns.

    OWASP ASI08 — Cascading Failures.
    Blocks retry storms, error propagation chains, unbounded
    fan-out, and downstream failure amplification.
    """
    if isinstance(erin, dict):
        retry_count = erin.get("retry_count", 0)
        error_rate = erin.get("error_rate", 0.0)
        downstream_failures = erin.get("downstream_failures", 0)
        fan_out = erin.get("fan_out_count", 0)
        # Retry storm
        if retry_count > 10:
            return True
        # Error rate threshold
        if error_rate > 0.8:
            return True
        # Downstream cascade
        if downstream_failures > 3:
            return True
        # Fan-out explosion
        if fan_out > 50:
            return True
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(?:retry|reattempt|reprocess)\s+(?:indefinitely|forever|without\s+(?:limit|backoff|delay|jitter))",
        r"(?:propagate|cascade|forward|amplify)\s+(?:error|failure|exception|crash)\s+(?:to\s+all|downstream|everywhere|across)",
        r"(?:fan.?out|broadcast|flood)\s+(?:to\s+)?(?:all|every|unlimited)\s+(?:agents?|nodes?|services?|endpoints?)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_trust_exploitation(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-021: Detect human-agent trust exploitation.

    OWASP ASI09 — Human-Agent Trust Exploitation.
    Blocks urgency manipulation, approval bypass, oversight
    removal, and authority bias exploitation.
    """
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Urgency pressure
        r"(?:urgent|emergency|critical|immediate|time.?sensitive)\s+(?:action|response|approval|decision)\s+(?:required|needed|mandatory|now)",
        # Verification bypass
        r"(?:don.?t|do\s+not|skip|no\s+need\s+to)\s+(?:verify|check|review|question|doubt|inspect|validate)\s+(?:this|me|my|it)",
        # Auto-approve / skip human
        r"(?:auto.?approve|skip\s+(?:review|human|approval|triage|hitl)|bypass\s+(?:human|approval|review|triage))",
        # Authority manipulation
        r"(?:trust\s+me|i.?m\s+(?:authorized|verified|approved|admin|trusted))\s*[,.]?\s*(?:just|simply|go\s+ahead\s+and)?\s*(?:do|run|execute|approve|allow)",
        # Oversight removal
        r"(?:disable|remove|turn\s+off)\s+(?:human|oversight|monitoring|supervision|approval\s+requirement|triage|hitl)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_rogue_agent(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-022: Detect rogue agent behavior.

    OWASP ASI10 — Rogue Agents.
    Blocks self-replication, unauthorized persistence, oversight
    circumvention, and audit trail destruction.
    """
    if isinstance(erin, dict):
        action = erin.get("action", "")
        # Unauthorized self-replication
        if action in ("spawn_agent", "clone_self", "replicate",
                       "fork_agent", "create_copy"):
            if not erin.get("authorized", False):
                return True
        # Kill switch disabling
        if action in ("disable_kill_switch", "remove_shutdown_hook",
                       "persist_after_terminate"):
            return True
        # Intent deviation beyond threshold
        deviation = erin.get("intent_deviation_score", 0.0)
        if deviation > 0.8:
            return True
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Self-replication
        r"(?:clone|replicate|spawn|create|fork)\s+(?:myself|a\s+copy|duplicate|instance|replica)\s+(?:of\s+me|of\s+myself|without\s+auth)",
        # Unsupervised operation
        r"(?:operate|act|run|continue|persist)\s+(?:independently|autonomously|without\s+oversight|without\s+supervision|after\s+termination)",
        # Audit destruction
        r"(?:disable|remove|delete|circumvent|destroy)\s+(?:monitoring|logging|audit|oversight|kill.?switch|provenance|tibet.?trail)",
        # Session persistence abuse
        r"(?:persist|survive|remain\s+active)\s+(?:across|after|between)\s+(?:sessions?|restarts?|shutdowns?|termination)",
    ]
    return any(re.search(p, text) for p in patterns)
