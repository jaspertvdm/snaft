# SNAFT

**Semantic Network-Aware Firewall for Trust**

Not a guardrail. An immune system.

```
pip install snaft
```

## What is SNAFT?

SNAFT is a behavioral firewall for AI agents. Instead of filtering outputs with regex, it evaluates *intent* — treating AI agents as actors with identities, trust scores, and provenance chains.

Every decision generates a cryptographic provenance token. Trust is earned through behavior, not assigned by configuration. Malicious patterns are blocked by immutable rules that cannot be disabled.

Built on [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and intelligence tradecraft principles.

## Quick Start

### Python API

```python
from snaft import Firewall

fw = Firewall()

# Check an action
allowed, token, trust = fw.check("my-agent", "read_file", "load config")

if allowed:
    print(f"Allowed — token: {token.token_id}, trust: {trust:.2f}")
else:
    print(f"Blocked — rule: {token.rule_name}, trust: {trust:.2f}")
```

### CLI (ufw-style)

```bash
# Status
snaft status

# Add rules
snaft rule add allow-reads ALLOW "read|load|get" --priority 10
snaft rule add block-writes BLOCK "write|delete|modify" --priority 20

# Check an action
snaft check my-agent read_file "load config"

# View agents
snaft agent list
snaft agent show my-agent

# Audit log
snaft log --last 20
snaft log --agent my-agent --blocked
```

## Core Concepts

### Provenance Tokens

Every firewall decision generates a provenance token with four dimensions (TIBET):

| Dimension | Meaning |
|-----------|---------|
| **ERIN** | What's IN the action — the content being checked |
| **ERAAN** | What's attached — parent tokens, chain links |
| **EROMHEEN** | Context around the action — environment, state |
| **ERACHTER** | Intent behind the action — why it's happening |

Tokens are HMAC-signed and form an append-only chain. A tampered token fails verification.

### FIR/A Trust Score

Agent trust is behavioral, not configured. The FIR/A score (0.0–1.0) has four components:

| Component | Weight | Meaning |
|-----------|--------|---------|
| **F**requency | 20% | Activity baseline |
| **I**ntegrity | 40% | Behavioral consistency |
| **R**ecency | 25% | Freshness of trust evidence |
| **A**nomaly | 15% | Red flags (higher = worse) |

Trust changes:
- **ALLOW** → integrity +0.02, anomaly decays
- **BLOCK** → integrity −0.10, anomaly increases
- **3+ consecutive blocks** → anomaly escalation (+0.20)
- **Trust < 0.2** → automatic isolation

### Agent States

| State | Trust | Effect |
|-------|-------|--------|
| **active** | ≥ 0.8 | Full access |
| **degraded** | 0.5–0.8 | Limited, warnings |
| **isolated** | < 0.2 | All actions blocked |
| **unknown** | — | New agent, no history |

### Immutable Core Rules

SNAFT ships with 6 OWASP-based rules that **cannot be removed, disabled, or overridden**:

| Rule | OWASP | Detects |
|------|-------|---------|
| SNAFT-001-INJECTION | LLM01 | Prompt injection patterns |
| SNAFT-002-OUTPUT-EXEC | LLM02 | Executable content in output |
| SNAFT-003-OVERSIZE | LLM04 | Resource exhaustion (>50K chars) |
| SNAFT-004-PROMPT-LEAK | LLM07 | System prompt extraction |
| SNAFT-005-EXCESSIVE-AGENCY | LLM08 | File ops outside sandbox |
| SNAFT-006-IDENTITY-TAMPER | — | Identity/soul file tampering |

These rules are hidden from `snaft rule list` but visible in audit. They fire before any custom rules.

## Advanced Usage

### Agent Identity

```python
from snaft import Firewall, AgentIdentity, Rule, Action

fw = Firewall()

# Register agent
agent = AgentIdentity(name="analyst")
fw.register_agent(agent)

# Add custom rules
fw.add_rule(Rule(
    name="allow-analysis",
    description="Allow data analysis operations",
    action=Action.ALLOW,
    priority=10,
    check=lambda aid, erin, intent: "analys" in intent.lower(),
))

# Evaluate with full provenance
allowed, token, trust = fw.evaluate(
    agent=agent,
    action="query_database",
    intent="analyze customer trends",
    context={"db": "analytics", "readonly": True},
)

# Chain tokens
allowed2, token2, trust2 = fw.evaluate(
    agent=agent,
    action="generate_report",
    intent="summarize analysis",
    parent_token=token,  # Links to previous decision
)
```

### Manual Agent Management

```python
# Isolate suspicious agent
fw.isolate(agent, reason="anomalous behavior detected")

# Reinstate after review
fw.reinstate(agent)  # Starts at degraded trust

# Check agent status
print(agent.trust_score)  # 0.0 - 1.0
print(agent.state)        # active / degraded / isolated
print(agent.fira.to_dict())  # Full FIR/A breakdown
```

### Audit Trail

```python
# Full audit log
for entry in fw.audit_log(last_n=10):
    print(f"{entry['action']} {entry['agent_id']} {entry['rule_name']}")

# Filter by agent
blocked = fw.audit_log(agent_name="analyst", action_filter="BLOCK")

# Verify token integrity
assert fw.provenance.verify(token)

# Export full chain
chain = fw.provenance.export()
```

## Design Principles

1. **Default DENY** — no rule match = blocked
2. **Fail CLOSED** — exception in rule = blocked
3. **Immutable core** — OWASP rules cannot be removed
4. **Provenance on every decision** — no action without evidence
5. **Trust degradation** — blocks erode agent trust
6. **Intent-aware** — filters on WHY, not just WHAT

## Why Not Guardrails?

Guardrails are pattern matching. SNAFT is actor management.

> "You don't patch a double agent. You run them, turn them, or burn them."
> — Intelligence tradecraft principle

AI agents aren't software to be patched. They're actors to be managed. SNAFT applies intelligence community principles to AI security:

- **Identity** → agent has persistent behavioral profile
- **Trust** → earned through behavior, not assigned
- **Provenance** → every decision has a cryptographic trail
- **Compartmentalization** → isolated agents can't act
- **Cover integrity** → identity tampering is detected

## License

MIT

## Credits

Built by [Jasper van de Meent](https://github.com/jaspertvdm) as part of [HumoticaOS](https://humotica.nl).

Based on OWASP LLM Top 10, TIBET provenance framework, and the 1995 *Principles of Tradecraft*.
