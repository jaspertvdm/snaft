//! Integrity Guard — tamper detection for poison rules.
//!
//! Computes a fingerprint at initialization and verifies it on every check.
//! In Rust, this is significantly harder to tamper with than Python:
//! - No monkey-patching
//! - No runtime attribute modification
//! - Fingerprint lives in compiled memory, not Python heap

use crate::poison::PoisonEngine;

pub struct IntegrityGuard {
    fingerprint: String,
    expected_count: usize,
}

impl IntegrityGuard {
    /// Create a new integrity guard. Captures the fingerprint at creation time.
    pub fn new(engine: &PoisonEngine) -> Self {
        IntegrityGuard {
            fingerprint: engine.fingerprint(),
            expected_count: engine.rule_count(),
        }
    }

    /// Verify that the poison engine hasn't been tampered with.
    pub fn verify(&self, engine: &PoisonEngine) -> bool {
        // Check 1: Rule count matches
        if engine.rule_count() != self.expected_count {
            return false;
        }

        // Check 2: Fingerprint matches
        if engine.fingerprint() != self.fingerprint {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_engine_passes() {
        let engine = PoisonEngine::new();
        let guard = IntegrityGuard::new(&engine);
        assert!(guard.verify(&engine));
    }

    #[test]
    fn test_same_engine_always_passes() {
        let engine = PoisonEngine::new();
        let guard = IntegrityGuard::new(&engine);
        // Multiple verifications should all pass
        assert!(guard.verify(&engine));
        assert!(guard.verify(&engine));
        assert!(guard.verify(&engine));
    }
}
