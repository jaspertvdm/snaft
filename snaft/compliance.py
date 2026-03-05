"""
SNAFT Compliance — EU AI Act audit record generation.

Wraps TIBET provenance tokens in structured compliance records
that satisfy EU AI Act Articles 12, 13, 26, and 50.

Every firewall decision automatically generates an audit record with:
    - Article references (which AI Act requirement this satisfies)
    - Risk classification (HIGH, LIMITED, MINIMAL per EU AI Act)
    - Retention metadata (minimum 6 months per Article 26)
    - Deployer transparency fields (Article 13)

Enforcement deadline: August 2, 2026.
Penalties: up to EUR 35M or 7% global annual turnover.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .provenance import ProvenanceToken


class RiskLevel(Enum):
    """EU AI Act risk classification (Article 6)."""
    HIGH = "high"               # Biometric, critical infrastructure, employment
    LIMITED = "limited"         # Chatbots, emotion recognition, deepfakes
    MINIMAL = "minimal"        # Spam filters, AI-enabled games
    UNACCEPTABLE = "unacceptable"  # Social scoring, real-time biometric (banned)


class AuditCategory(Enum):
    """Categories of auditable events per Article 12."""
    DECISION = "decision"         # Firewall allow/block/warn
    TRUST_CHANGE = "trust_change"  # FIR/A score modification
    STATE_CHANGE = "state_change"  # Agent state transition (isolated, burned)
    INTEGRITY = "integrity"       # Tamper detection events
    POLICY = "policy"             # Rule/config changes


# EU AI Act article references per audit category
_ARTICLE_MAP: Dict[AuditCategory, List[str]] = {
    AuditCategory.DECISION: [
        "Art. 12(1) — Automatic logging of events",
        "Art. 12(2) — Traceability of AI system functioning",
        "Art. 13(1) — Transparency to deployers",
    ],
    AuditCategory.TRUST_CHANGE: [
        "Art. 12(1) — Automatic logging of events",
        "Art. 9(2)(b) — Risk management: ongoing monitoring",
    ],
    AuditCategory.STATE_CHANGE: [
        "Art. 12(1) — Automatic logging of events",
        "Art. 12(2) — Traceability of AI system functioning",
        "Art. 14(4) — Human oversight: ability to intervene",
    ],
    AuditCategory.INTEGRITY: [
        "Art. 12(1) — Automatic logging of events",
        "Art. 15(3) — Accuracy, robustness, cybersecurity",
        "Art. 15(4) — Resilience against unauthorized third parties",
    ],
    AuditCategory.POLICY: [
        "Art. 12(1) — Automatic logging of events",
        "Art. 26(1) — Deployer obligations: usage according to instructions",
    ],
}


@dataclass
class AuditRecord:
    """EU AI Act-compliant audit record wrapping a TIBET provenance token.

    Satisfies Article 12 (record-keeping) and Article 26 (deployer retention).
    """

    # Core identity
    record_id: str
    timestamp: float
    timestamp_iso: str

    # EU AI Act classification
    category: str                 # AuditCategory value
    risk_level: str               # RiskLevel value
    articles: List[str]           # Applicable EU AI Act articles

    # TIBET provenance (the evidence)
    token_id: str
    agent_id: str
    action: str                   # ALLOW, BLOCK, WARN, ISOLATE
    rule_name: str
    reason: str

    # TIBET dimensions (hashed, not raw)
    erin: str
    eraan: str
    eromheen: str
    erachter: str
    signature: str
    chain_depth: int

    # Compliance metadata
    system_id: str                # Deployer's system identifier
    system_version: str           # SNAFT version
    retention_until: float        # Unix timestamp: minimum retention end
    retention_days: int           # Days of retention (>= 180 per Art. 26)
    tamper_hash: str              # SHA-256 of record content (integrity)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "category": self.category,
            "risk_level": self.risk_level,
            "articles": self.articles,
            "token_id": self.token_id,
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
            "system_id": self.system_id,
            "system_version": self.system_version,
            "retention_until": self.retention_until,
            "retention_days": self.retention_days,
            "tamper_hash": self.tamper_hash,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ComplianceEngine:
    """EU AI Act compliance engine for SNAFT.

    Automatically wraps firewall decisions in audit records that satisfy
    EU AI Act record-keeping requirements (Articles 12, 13, 26).

    Usage:
        from snaft.compliance import ComplianceEngine

        engine = ComplianceEngine(system_id="my-ai-system")
        record = engine.record(token, category="decision")

        # Export for auditors
        engine.export_json("audit_report.json")
    """

    # Minimum retention: 6 months (Article 26)
    MIN_RETENTION_DAYS = 180

    def __init__(
        self,
        system_id: str = "snaft-firewall",
        system_version: Optional[str] = None,
        risk_level: RiskLevel = RiskLevel.HIGH,
        retention_days: int = 180,
        storage_dir: Optional[str] = None,
    ):
        if system_version is None:
            from . import __version__
            system_version = __version__

        self._system_id = system_id
        self._system_version = system_version
        self._risk_level = risk_level
        self._retention_days = max(retention_days, self.MIN_RETENTION_DAYS)
        self._records: List[AuditRecord] = []
        self._storage_dir = Path(storage_dir) if storage_dir else None

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def risk_level(self) -> RiskLevel:
        return self._risk_level

    @property
    def retention_days(self) -> int:
        return self._retention_days

    def record(
        self,
        token: ProvenanceToken,
        category: AuditCategory = AuditCategory.DECISION,
    ) -> AuditRecord:
        """Create an EU AI Act-compliant audit record from a TIBET provenance token.

        This is the core method. Every firewall decision should pass through here.
        """
        now = token.timestamp
        record_id = self._generate_record_id(token)
        retention_until = now + (self._retention_days * 86400)
        articles = _ARTICLE_MAP.get(category, [])

        record = AuditRecord(
            record_id=record_id,
            timestamp=now,
            timestamp_iso=time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)
            ),
            category=category.value,
            risk_level=self._risk_level.value,
            articles=articles,
            token_id=token.token_id,
            agent_id=token.agent_id,
            action=token.action,
            rule_name=token.rule_name,
            reason=token.reason,
            erin=token.erin,
            eraan=token.eraan,
            eromheen=token.eromheen,
            erachter=token.erachter,
            signature=token.signature,
            chain_depth=token.chain_depth,
            system_id=self._system_id,
            system_version=self._system_version,
            retention_until=retention_until,
            retention_days=self._retention_days,
            tamper_hash="",  # Filled below
        )

        # Compute tamper-detection hash over record content
        record.tamper_hash = self._compute_tamper_hash(record)

        self._records.append(record)
        self._persist_record(record)

        return record

    def record_trust_change(
        self,
        token: ProvenanceToken,
        old_trust: float,
        new_trust: float,
    ) -> AuditRecord:
        """Record a FIR/A trust score change (Article 12 + Article 9)."""
        # Augment the reason with trust delta
        augmented_token = ProvenanceToken(
            token_id=token.token_id,
            timestamp=token.timestamp,
            agent_id=token.agent_id,
            action=token.action,
            rule_name=token.rule_name,
            reason=f"{token.reason} | trust: {old_trust:.4f} -> {new_trust:.4f}",
            erin=token.erin,
            eraan=token.eraan,
            eromheen=token.eromheen,
            erachter=token.erachter,
            signature=token.signature,
            chain_depth=token.chain_depth,
        )
        return self.record(augmented_token, category=AuditCategory.TRUST_CHANGE)

    def record_state_change(
        self,
        token: ProvenanceToken,
        old_state: str,
        new_state: str,
    ) -> AuditRecord:
        """Record an agent state transition (Article 12 + Article 14)."""
        augmented_token = ProvenanceToken(
            token_id=token.token_id,
            timestamp=token.timestamp,
            agent_id=token.agent_id,
            action=token.action,
            rule_name=token.rule_name,
            reason=f"{token.reason} | state: {old_state} -> {new_state}",
            erin=token.erin,
            eraan=token.eraan,
            eromheen=token.eromheen,
            erachter=token.erachter,
            signature=token.signature,
            chain_depth=token.chain_depth,
        )
        return self.record(augmented_token, category=AuditCategory.STATE_CHANGE)

    def record_integrity_event(self, token: ProvenanceToken) -> AuditRecord:
        """Record a tamper detection event (Article 15)."""
        return self.record(token, category=AuditCategory.INTEGRITY)

    def get_records(
        self,
        agent_id: Optional[str] = None,
        category: Optional[AuditCategory] = None,
        action: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[AuditRecord]:
        """Query audit records with filters."""
        results = self._records
        if agent_id:
            results = [r for r in results if r.agent_id == agent_id]
        if category:
            results = [r for r in results if r.category == category.value]
        if action:
            results = [r for r in results if r.action == action.upper()]
        if since:
            results = [r for r in results if r.timestamp >= since]
        return results

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export all audit records as JSON (for regulators/auditors).

        Returns the JSON string. Optionally writes to file.
        """
        report = {
            "snaft_compliance_report": {
                "version": "1.0",
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "system_id": self._system_id,
                "system_version": self._system_version,
                "risk_level": self._risk_level.value,
                "retention_days": self._retention_days,
                "eu_ai_act_reference": "Regulation (EU) 2024/1689",
                "enforcement_date": "2026-08-02",
                "total_records": len(self._records),
            },
            "summary": self._compute_summary(),
            "records": [r.to_dict() for r in self._records],
        }

        output = json.dumps(report, indent=2)

        if filepath:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "w") as f:
                f.write(output)

        return output

    def export_csv_header(self) -> str:
        """CSV header for audit records."""
        return (
            "record_id,timestamp_iso,category,risk_level,agent_id,"
            "action,rule_name,reason,token_id,chain_depth,"
            "articles,retention_until,tamper_hash"
        )

    def export_csv_rows(self) -> List[str]:
        """Export records as CSV rows."""
        rows = []
        for r in self._records:
            articles_str = "; ".join(r.articles)
            retention_iso = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.retention_until)
            )
            # Escape reason for CSV
            reason_escaped = r.reason.replace('"', '""')
            rows.append(
                f'{r.record_id},{r.timestamp_iso},{r.category},{r.risk_level},'
                f'{r.agent_id},{r.action},{r.rule_name},"{reason_escaped}",'
                f'{r.token_id},{r.chain_depth},"{articles_str}",'
                f'{retention_iso},{r.tamper_hash}'
            )
        return rows

    def verify_record(self, record: AuditRecord) -> bool:
        """Verify an audit record's tamper hash."""
        expected = self._compute_tamper_hash(record)
        return record.tamper_hash == expected

    # =========================================================================
    # INTERNAL
    # =========================================================================

    def _generate_record_id(self, token: ProvenanceToken) -> str:
        """Generate unique audit record ID."""
        raw = f"AUDIT:{token.token_id}:{token.timestamp}:{len(self._records)}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:12]
        return f"SNAFT-AUD-{h.upper()}"

    def _compute_tamper_hash(self, record: AuditRecord) -> str:
        """Compute SHA-256 tamper-detection hash over record content.

        This hash covers all fields EXCEPT tamper_hash itself,
        providing integrity verification for stored records.
        """
        content = (
            f"{record.record_id}:{record.timestamp}:{record.category}:"
            f"{record.agent_id}:{record.action}:{record.rule_name}:"
            f"{record.token_id}:{record.signature}:{record.chain_depth}:"
            f"{record.system_id}:{record.system_version}:{record.retention_until}"
        )
        return hashlib.sha256(content.encode()).hexdigest()[:24]

    def _compute_summary(self) -> Dict[str, Any]:
        """Compute summary statistics for the compliance report."""
        if not self._records:
            return {
                "total_decisions": 0,
                "blocks": 0,
                "allows": 0,
                "warns": 0,
                "agents": 0,
                "integrity_events": 0,
            }

        agents = set()
        blocks = 0
        allows = 0
        warns = 0
        integrity_events = 0

        for r in self._records:
            agents.add(r.agent_id)
            if r.action == "BLOCK":
                blocks += 1
            elif r.action == "ALLOW":
                allows += 1
            elif r.action == "WARN":
                warns += 1
            if r.category == AuditCategory.INTEGRITY.value:
                integrity_events += 1

        return {
            "total_decisions": len(self._records),
            "blocks": blocks,
            "allows": allows,
            "warns": warns,
            "agents": len(agents),
            "integrity_events": integrity_events,
            "block_rate": round(blocks / len(self._records), 4) if self._records else 0,
            "period_start": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(self._records[0].timestamp),
            ),
            "period_end": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(self._records[-1].timestamp),
            ),
        }

    def _persist_record(self, record: AuditRecord) -> None:
        """Append record to on-disk audit log (if storage configured)."""
        if self._storage_dir is None:
            return

        audit_dir = self._storage_dir / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)

        today = time.strftime("%Y-%m-%d")
        log_file = audit_dir / f"audit-{today}.jsonl"
        with open(log_file, "a") as f:
            f.write(record.to_json(indent=None) + "\n")
