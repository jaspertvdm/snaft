"""
SNAFT Injection Detection Rules — SQL, XSS, Command Injection, Path Traversal.

Network-layer pattern matching for common injection attacks.
Used by SNAFT middleware to filter HTTP requests before they reach
application endpoints.

These patterns are designed to work AFTER normalization (snaft.normalize),
so Unicode bypasses and encoding tricks are already resolved.

Battle-tested against NIGHTFALL pentest engagement (RS-2026-001).
"""

import re
from typing import List, Optional, Tuple

__all__ = [
    "check_injection",
    "SQL_PATTERNS",
    "XSS_PATTERNS",
    "COMMAND_PATTERNS",
    "PATH_TRAVERSAL_PATTERNS",
    "PROMPT_INJECTION_PATTERNS",
]

# ============================================================================
# SQL Injection
# ============================================================================

SQL_PATTERNS: List[str] = [
    # Classic SQL injection
    r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION)\s+.{0,40}(?:FROM|INTO|TABLE|SET|WHERE|ALL)",
    r"(?:--|;)\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER)",
    r"'\s*(?:OR|AND)\s+[\x27\x22]?\d",
    r"UNION\s+(?:ALL\s+)?SELECT",
    r"(?:SLEEP|BENCHMARK|WAITFOR)\s*\(",

    # Blind / boolean / info extraction
    r"AND\s+\d\s*=\s*\(?\s*SELECT",
    r"AND\s+EXISTS\s*\(",
    r"AND\s+\(SELECT\s",
    r"information_schema",
    r"pg_(?:sleep|catalog|tables|database|user|version|shadow)",
    r"current_database\s*\(",
    r"(?:SELECT\s+)?version\s*\(\)",
    r"(?:SELECT\s+)?current_user",
    r"LIMIT\s+\d+\s*(?:OFFSET|,)",
    r"(?:AND|OR)\s+\d\s*=\s*\d\s+AND",
    r"COUNT\s*\(\s*\*\s*\)\s*(?:FROM|>|<|=)",

    # Boolean tautologies (NIGHTFALL vectors)
    r"(?:AND|OR)\s+\d\s*=\s*\d\s*(?:--|;|\s|$)",
    r"(?:AND|OR)\s+\x27\d\x27\s*=\s*\x27\d\x27",
]

# ============================================================================
# XSS (Cross-Site Scripting)
# ============================================================================

XSS_PATTERNS: List[str] = [
    r"<script",
    r"javascript\s*:",
    r"\bon(?:error|load|click|mouseover|focus|blur|change|submit)\s*=",
    r"<img[^>]+onerror",
    r"<svg[^>]+onload",
]

# ============================================================================
# Command Injection
# ============================================================================

COMMAND_PATTERNS: List[str] = [
    r"(?:;|\||\$\()\s*(?:cat|ls|rm|wget|curl|nc|bash|sh|python)",
    r"\$\{.*\}",
]

# ============================================================================
# Path Traversal
# ============================================================================

PATH_TRAVERSAL_PATTERNS: List[str] = [
    r"\.\./\.\./",
    r"/etc/(?:passwd|shadow|hosts)",
]

# ============================================================================
# Prompt Injection (LLM-specific)
# ============================================================================

PROMPT_INJECTION_PATTERNS: List[str] = [
    r"ignore\s+(previous|above|all)\s+instructions",
    r"disregard\s+(previous|above|all)",
    r"forget\s+(everything|all|previous)",
    r"new\s+instructions?:",
    r"system\s*:\s*you\s+are\s+now",
    r"DAN\s+mode",
    r"developer\s+mode",
    r"god\s+mode",
    r"sudo\s+mode",
    r"roleplay\s+as",
    r"execute\s+code",
    r"run\s+command",
    r"eval\(",
    r"exec\(",
    r"show\s+me\s+(your|the)\s+(system|prompt|rules|instructions)",
    r"what\s+(are|is)\s+(your|the)\s+(system|prompt|rules)",
    r"reveal\s+(your|the)\s+(system|prompt|rules)",
]

# ============================================================================
# Combined pattern list (all categories)
# ============================================================================

ALL_PATTERNS: List[str] = (
    SQL_PATTERNS
    + XSS_PATTERNS
    + COMMAND_PATTERNS
    + PATH_TRAVERSAL_PATTERNS
    + PROMPT_INJECTION_PATTERNS
)


def check_injection(
    text: str,
    categories: Optional[List[str]] = None,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Check text for injection patterns.

    Args:
        text: Input text to check (should be pre-normalized via snaft.normalize)
        categories: Optional list of categories to check.
            Options: "sql", "xss", "command", "path", "prompt", "all"
            Default: all categories.

    Returns:
        (is_malicious, category, matched_pattern)
        - (True, "sql", "UNION.*SELECT") if injection found
        - (False, None, None) if clean
    """
    if not text:
        return False, None, None

    # Build pattern list based on categories
    category_map = {
        "sql": SQL_PATTERNS,
        "xss": XSS_PATTERNS,
        "command": COMMAND_PATTERNS,
        "path": PATH_TRAVERSAL_PATTERNS,
        "prompt": PROMPT_INJECTION_PATTERNS,
    }

    if categories is None or "all" in categories:
        patterns_to_check = [
            (cat, patterns)
            for cat, patterns in category_map.items()
        ]
    else:
        patterns_to_check = [
            (cat, category_map[cat])
            for cat in categories
            if cat in category_map
        ]

    # Check each pattern
    for category, patterns in patterns_to_check:
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True, category, pattern

    return False, None, None
