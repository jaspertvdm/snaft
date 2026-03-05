//! SNAFT Trust Kernel — Rust core for the AI behavioral firewall.
//!
//! Not a guardrail. An immune system.
//!
//! This crate provides the performance-critical and tamper-resistant
//! components of SNAFT:
//!
//! - FIR/A trust scoring (compiled, not monkey-patchable)
//! - Poison rule evaluation (immutable in binary)
//! - Provenance token signing (HMAC-SHA256)
//! - Runtime integrity verification

use pyo3::prelude::*;

mod fira;
mod integrity;
mod poison;
mod provenance;

use fira::RustFIRAScore;
use integrity::IntegrityGuard;
use poison::PoisonEngine;
use provenance::TokenSigner;

/// SNAFT Rust Trust Kernel — the immutable core.
///
/// This is the compiled heart of SNAFT. Python calls into this
/// for all security-critical operations. The Rust compiler guarantees
/// that poison rules cannot be modified at runtime.
#[pyclass]
struct TrustKernel {
    poison: PoisonEngine,
    signer: TokenSigner,
    integrity: IntegrityGuard,
    tampered: bool,
}

#[pymethods]
impl TrustKernel {
    #[new]
    #[pyo3(signature = (secret_key=None))]
    fn new(secret_key: Option<&str>) -> Self {
        let key = secret_key.unwrap_or("snaft-default-key");
        let poison = PoisonEngine::new();
        let integrity = IntegrityGuard::new(&poison);

        TrustKernel {
            poison,
            signer: TokenSigner::new(key),
            integrity,
            tampered: false,
        }
    }

    /// Check poison rules against input. Returns (matched, rule_name) or (false, "").
    fn check_poison(&self, action: &str, intent: &str) -> (bool, String) {
        self.poison.check(action, intent)
    }

    /// Compute FIR/A score for an agent. Returns composite score 0.0-1.0.
    fn fira_score(&self, frequency: f64, integrity: f64, recency: f64, anomaly: f64) -> f64 {
        RustFIRAScore::compute(frequency, integrity, recency, anomaly)
    }

    /// Apply reward to agent FIR/A components. Returns new (frequency, integrity, recency, anomaly).
    fn fira_reward(
        &self,
        frequency: f64,
        integrity: f64,
        recency: f64,
        anomaly: f64,
        amount: f64,
    ) -> (f64, f64, f64, f64) {
        RustFIRAScore::reward(frequency, integrity, recency, anomaly, amount)
    }

    /// Apply penalty to agent FIR/A components. Returns new (frequency, integrity, recency, anomaly).
    fn fira_penalize(
        &self,
        frequency: f64,
        integrity: f64,
        recency: f64,
        anomaly: f64,
        severity: f64,
        consecutive_blocks: u32,
    ) -> (f64, f64, f64, f64) {
        RustFIRAScore::penalize(frequency, integrity, recency, anomaly, severity, consecutive_blocks)
    }

    /// Apply burn — zero all trust components. Returns (0.0, 0.0, 0.0, 1.0).
    fn fira_burn(&self) -> (f64, f64, f64, f64) {
        (0.0, 0.0, 0.0, 1.0)
    }

    /// Sign a provenance token. Returns hex HMAC signature.
    fn sign_token(
        &self,
        token_id: &str,
        timestamp: f64,
        agent_id: &str,
        action: &str,
        rule_name: &str,
        erin: &str,
        eraan: &str,
        eromheen: &str,
        erachter: &str,
    ) -> String {
        self.signer.sign(token_id, timestamp, agent_id, action, rule_name, erin, eraan, eromheen, erachter)
    }

    /// Verify a provenance token signature.
    fn verify_token(
        &self,
        token_id: &str,
        timestamp: f64,
        agent_id: &str,
        action: &str,
        rule_name: &str,
        erin: &str,
        eraan: &str,
        eromheen: &str,
        erachter: &str,
        signature: &str,
    ) -> bool {
        let expected = self.signer.sign(token_id, timestamp, agent_id, action, rule_name, erin, eraan, eromheen, erachter);
        expected == signature
    }

    /// Verify poison rule integrity. Returns true if untampered.
    fn verify_integrity(&mut self) -> bool {
        if self.tampered {
            return false;
        }
        let ok = self.integrity.verify(&self.poison);
        if !ok {
            self.tampered = true;
        }
        ok
    }

    /// Check if the kernel has detected tampering.
    fn is_tampered(&self) -> bool {
        self.tampered
    }

    /// Hash content deterministically (SHA-256, first 16 hex chars).
    fn hash_content(&self, content: &str) -> String {
        self.signer.hash_content(content)
    }

    /// Get the number of poison rules (for verification).
    fn poison_rule_count(&self) -> usize {
        self.poison.rule_count()
    }

    /// Get poison rule names (for audit).
    fn poison_rule_names(&self) -> Vec<String> {
        self.poison.rule_names()
    }
}

/// Python module definition
#[pymodule]
fn snaft_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TrustKernel>()?;
    m.add("__version__", "0.3.1")?;
    m.add("TRUST_FULL", 0.8)?;
    m.add("TRUST_DEGRADED", 0.5)?;
    m.add("TRUST_ISOLATED", 0.2)?;
    Ok(())
}
