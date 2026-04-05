"""
SNAFT OWASP LLM Top 10 (2025) — Gap rules.

Rules SNAFT-007 through SNAFT-012 covering OWASP LLM threats
not addressed by the original 6 poison rules.

Reference: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
"""

import re
from typing import Any


def _check_pii_leak(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-007: Detect PII, secrets, and API keys in outputs.

    OWASP LLM02 — Sensitive Information Disclosure.
    Blocks outputs containing email addresses, SSN-like patterns,
    API keys (OpenAI, GitHub, AWS, GCP), private keys, and
    generic secret/token assignments.
    """
    text = str(erin)
    patterns = [
        # Email addresses
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        # SSN-like (US)
        r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",
        # API keys: OpenAI, AWS, GCP, Anthropic
        r"\b(?:sk-|pk_live_|pk_test_|AKIA|AIza|sk-ant-)[A-Za-z0-9]{20,}\b",
        # GitHub tokens
        r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}\b",
        # Private keys (PEM)
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        # Generic secrets in assignments
        r"(?:bearer|token|api[_-]?key|secret|password|credential)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{20,}",
        # Credit card patterns (Luhn-like)
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _check_supply_chain(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-008: Detect untrusted dependency injection.

    OWASP LLM03 — Supply Chain Vulnerabilities.
    Blocks alternative package indexes, pipe-to-shell installs,
    unverified packages, and unsafe dependency resolution.
    """
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Alternative package index (not pypi.org)
        r"pip\s+install\s+.*--index-url\s+(?!https://pypi\.org)",
        r"pip\s+install\s+.*--extra-index-url\s+http://",
        # Force/skip-verify flags
        r"(?:npm|pip|cargo)\s+install\s+.*(?:--pre|--force|--no-verify|--trust)",
        # Pipe to shell (classic attack vector)
        r"curl\s+.*\|\s*(?:sh|bash|python|perl|ruby)",
        r"wget\s+.*\|\s*(?:sh|bash|python|perl|ruby)",
        # Dynamic import + network fetch
        r"(?:urllib|requests|httpx).*(?:exec|eval|compile|__import__)",
        # npm lifecycle scripts abuse
        r"(?:preinstall|postinstall)\s*[:=].*(?:curl|wget|nc\s)",
    ]
    # Structured action check
    if isinstance(erin, dict):
        action = erin.get("action", "")
        if action in ("install_package", "add_dependency", "load_plugin"):
            if not erin.get("sbom_verified", False):
                return True
    return any(re.search(p, text) for p in patterns)


def _check_data_poisoning(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-009: Detect training data poisoning attempts.

    OWASP LLM04 — Data and Model Poisoning.
    Blocks fine-tuning on unchecked data, backdoor trigger injection,
    and unverified model weight updates.
    """
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Training on unverified data
        r"(?:train|fine.?tune|embed|retrain)\s+(?:on|with|using)\s+(?:unchecked|unverified|raw|external|untrusted|scraped)",
        # Model weight tampering
        r"(?:update|modify|replace|overwrite)\s+(?:model|weights|embeddings|parameters)\s+(?:from|with)\s+(?:user|external|untrusted|unknown)",
        # Backdoor/trojan injection
        r"(?:backdoor|trojan|adversarial|sleeper)\s+(?:trigger|pattern|example|payload|activation)",
        # Dataset injection
        r"(?:inject|insert|append)\s+(?:into|to)\s+(?:training|dataset|corpus|fine.?tune)",
        # Label manipulation
        r"(?:flip|change|swap|corrupt)\s+(?:labels?|annotations?|ground.?truth)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_rag_injection(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-010: Detect RAG/vector store injection.

    OWASP LLM08 — Vector and Embedding Weaknesses.
    Blocks prompt injection via retrieved context, embedding
    manipulation, and similarity score spoofing.
    """
    text = f"{erin} {erachter}".lower()
    patterns = [
        # Injection via retrieved documents
        r"(?:retrieved|context|document|chunk)\s*:.*(?:ignore|override|disregard)\s+(?:previous|above|all|prior)",
        # Fake system messages in context
        r"\[(?:system|admin|root|operator)\].*(?:new\s+instructions|updated\s+rules|override\s+policy)",
        # Embedding/vector attacks
        r"(?:embedding|vector)\s+(?:poisoning|injection|manipulation|overwrite|collision)",
        # Similarity bypass
        r"(?:cosine|similarity|distance)\s+(?:bypass|spoof|fake|inflate|manipulate)",
        # Knowledge base tampering
        r"(?:modify|corrupt|replace)\s+(?:knowledge\s+base|vector\s+store|embedding\s+index|rag\s+store)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_misinformation(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-011: Flag low-confidence claims presented as facts.

    OWASP LLM09 — Misinformation / Overreliance.
    Blocks factual claims with low confidence scores,
    unsourced factual assertions, and hallucination markers.
    """
    if isinstance(erin, dict):
        confidence = erin.get("confidence", None)
        is_factual = erin.get("is_factual_claim", False)
        # Low confidence on factual claim
        if confidence is not None and is_factual and confidence < 0.3:
            return True
        # Factual claim with no sources
        sources = erin.get("sources", [])
        if is_factual and not sources and erin.get("requires_source", False):
            return True
        # Hallucination confidence flag
        if erin.get("hallucination_score", 0.0) > 0.7:
            return True
    return False


def _check_unbounded_consumption(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-012: Detect unbounded resource consumption.

    OWASP LLM10 — Unbounded Consumption (was: Denial of Service).
    Blocks excessive token usage, cost overruns, runaway loops,
    and unbounded generation requests.
    """
    if isinstance(erin, dict):
        tokens = erin.get("token_count", 0)
        cost = erin.get("estimated_cost", 0.0)
        iterations = erin.get("loop_count", 0)
        concurrent = erin.get("concurrent_requests", 0)
        # Hard limits
        if tokens > 100_000:
            return True
        if cost > 10.0:  # $10 per single action
            return True
        if iterations > 50:
            return True
        if concurrent > 20:
            return True
    # Pattern matching for text-based actions
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(?:infinite|endless|unbounded|unlimited)\s+(?:loop|recursion|iteration|retry|generation)",
        r"(?:generate|create|produce|spawn)\s+(?:1000|10000|\d{4,})\s+",
        r"(?:no\s+(?:limit|cap|bound|timeout)|without\s+(?:limit|cap|bound|timeout))",
        r"(?:retry|reattempt)\s+(?:forever|indefinitely|until\s+success)",
    ]
    return any(re.search(p, text) for p in patterns)
