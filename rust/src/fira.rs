//! FIR/A Trust Scoring — compiled, immutable trust math.
//!
//! The weights and thresholds are baked into the binary.
//! No Python code can override these values.

/// Weight constants — compiled into the binary, not configurable at runtime.
const WEIGHT_INTEGRITY: f64 = 0.40;
const WEIGHT_RECENCY: f64 = 0.25;
const WEIGHT_FREQUENCY: f64 = 0.20;
const WEIGHT_ANOMALY: f64 = 0.15;

pub struct RustFIRAScore;

impl RustFIRAScore {
    /// Compute composite FIR/A score (0.0 - 1.0).
    ///
    /// Weights are compiled constants:
    ///   Integrity:  40%
    ///   Recency:    25%
    ///   Frequency:  20%
    ///   Anomaly:    15% (inverted — higher anomaly = lower score)
    #[inline]
    pub fn compute(frequency: f64, integrity: f64, recency: f64, anomaly: f64) -> f64 {
        let raw = integrity * WEIGHT_INTEGRITY
            + recency * WEIGHT_RECENCY
            + frequency * WEIGHT_FREQUENCY
            + (1.0 - anomaly) * WEIGHT_ANOMALY;
        raw.clamp(0.0, 1.0)
    }

    /// Apply reward — agent did something good.
    pub fn reward(
        frequency: f64,
        integrity: f64,
        _recency: f64,
        anomaly: f64,
        amount: f64,
    ) -> (f64, f64, f64, f64) {
        let new_integrity = (integrity + amount).min(1.0);
        let new_recency = 1.0; // Refreshed
        let new_anomaly = (anomaly - amount * 0.5).max(0.0);
        let new_frequency = (frequency + 0.01).min(1.0);
        (new_frequency, new_integrity, new_recency, new_anomaly)
    }

    /// Apply penalty — agent did something bad.
    pub fn penalize(
        frequency: f64,
        integrity: f64,
        recency: f64,
        anomaly: f64,
        severity: f64,
        consecutive_blocks: u32,
    ) -> (f64, f64, f64, f64) {
        let new_integrity = (integrity - severity).max(0.0);
        let mut new_anomaly = (anomaly + severity * 0.5).min(1.0);
        let new_frequency = (frequency - severity * 0.3).max(0.0);
        let mut new_recency = recency;

        // Consecutive blocks = escalating penalty
        if consecutive_blocks >= 3 {
            new_anomaly = (new_anomaly + 0.2).min(1.0);
            new_recency = (new_recency - 0.1).max(0.0);
        }

        (new_frequency, new_integrity, new_recency, new_anomaly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_score() {
        let score = RustFIRAScore::compute(1.0, 1.0, 1.0, 0.0);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_zero_score() {
        let score = RustFIRAScore::compute(0.0, 0.0, 0.0, 1.0);
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_initial_score() {
        // Default: freq=0.5, int=0.5, rec=1.0, anom=0.0
        let score = RustFIRAScore::compute(0.5, 0.5, 1.0, 0.0);
        // 0.5*0.40 + 1.0*0.25 + 0.5*0.20 + 1.0*0.15 = 0.20 + 0.25 + 0.10 + 0.15 = 0.70
        assert!((score - 0.70).abs() < 0.001);
    }

    #[test]
    fn test_reward_increases_integrity() {
        let (_, int, _, _) = RustFIRAScore::reward(0.5, 0.5, 1.0, 0.0, 0.02);
        assert!(int > 0.5);
    }

    #[test]
    fn test_penalty_decreases_integrity() {
        let (_, int, _, _) = RustFIRAScore::penalize(0.5, 0.5, 1.0, 0.0, 0.1, 0);
        assert!(int < 0.5);
    }

    #[test]
    fn test_consecutive_blocks_escalate() {
        let (_, _, _, anom_normal) = RustFIRAScore::penalize(0.5, 0.5, 1.0, 0.0, 0.1, 2);
        let (_, _, _, anom_escalated) = RustFIRAScore::penalize(0.5, 0.5, 1.0, 0.0, 0.1, 3);
        assert!(anom_escalated > anom_normal);
    }

    #[test]
    fn test_score_clamped() {
        let score = RustFIRAScore::compute(2.0, 2.0, 2.0, -1.0);
        assert!(score <= 1.0);
        let score2 = RustFIRAScore::compute(-1.0, -1.0, -1.0, 2.0);
        assert!(score2 >= 0.0);
    }
}
