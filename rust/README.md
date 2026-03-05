# snaft-core

Compiled Rust trust kernel for [SNAFT](https://github.com/jaspertvdm/snaft) — the AI behavioral firewall.

## What is this?

`snaft-core` provides the performance-critical and tamper-resistant core of SNAFT, compiled from Rust:

- **FIR/A trust scoring** — weights compiled into binary, not monkey-patchable
- **Poison rule evaluation** — OWASP rules immutable in compiled binary
- **Provenance token signing** — HMAC-SHA256, key never touches Python memory
- **Runtime integrity verification** — tamper detection in compiled memory

## Installation

```bash
pip install snaft-core
```

The `snaft` package automatically uses `snaft-core` when available, falling back to pure-Python otherwise.

## Usage

```python
# Direct usage (usually not needed — snaft uses it automatically)
import snaft_core

kernel = snaft_core.TrustKernel("my-secret-key")

# Poison check
matched, rule = kernel.check_poison("some action", "some intent")

# FIR/A scoring
score = kernel.fira_score(frequency=0.5, integrity=0.8, recency=1.0, anomaly=0.1)

# Token signing
sig = kernel.sign_token("T1", 1234.0, "agent", "ALLOW", "rule", "e", "a", "o", "i")
```

## Why Rust?

Python's dynamic nature makes it trivially easy for a compromised agent to monkey-patch security rules at runtime. Rust's compiled binary cannot be modified in-process:

- No `setattr()` on compiled Rust structs
- No runtime attribute injection
- Poison rules live in read-only binary memory
- Signing keys never touch the Python heap

## License

MIT — Jasper van de Meent / Humotica
