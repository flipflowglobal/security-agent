//! Confidence-calibration tracking for the cognitive layer.
//!
//! The cognitive layers emit *probabilistic* predictions — a hypothesis is
//! "60% likely", a belief carries a probability, metacognition reports a
//! self-assessed confidence. A prediction is **calibrated** when its stated
//! confidence matches reality: across all the times the agent says "70%",
//! the predicted thing should actually happen about 70% of the time.
//!
//! This module measures that. [`CalibrationTracker`] accumulates
//! `(predicted_percent, occurred)` pairs and computes standard calibration
//! metrics — the Brier score, per-bin reliability, and expected calibration
//! error — plus a histogram recalibration that maps a raw confidence toward
//! the empirically observed hit-rate for its confidence band.
//!
//! Nothing here affects authorization; calibration is advisory feedback the
//! agent keeps about the quality of its own predictions.

/// One prediction and the outcome that later realized it: the agent stated
/// `predicted_percent` confidence, and the predicted event either
/// `occurred` or did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationRecord {
    pub predicted_percent: u8,
    pub occurred: bool,
}

/// One confidence band `[lower_percent, upper_percent)` (the top band is
/// closed at 100), summarizing the predictions that fell in it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReliabilityBin {
    pub lower_percent: u8,
    pub upper_percent: u8,
    pub count: usize,
    /// Mean stated confidence of the predictions in this band, as a
    /// probability in `[0.0, 1.0]`.
    pub mean_predicted: f32,
    /// Fraction of those predictions whose event actually occurred, in
    /// `[0.0, 1.0]`.
    pub empirical_rate: f32,
}

/// Whether the agent's confidence tends to run ahead of, behind, or in line
/// with reality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationTendency {
    /// Stated confidence exceeds the realized rate — the agent is too sure.
    Overconfident,
    /// Realized rate exceeds stated confidence — the agent is too cautious.
    Underconfident,
    /// Stated confidence and realized rate agree within tolerance.
    WellCalibrated,
}

impl std::fmt::Display for CalibrationTendency {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Overconfident => "overconfident",
            Self::Underconfident => "underconfident",
            Self::WellCalibrated => "well-calibrated",
        };
        formatter.write_str(name)
    }
}

/// Accumulates prediction/outcome pairs and derives calibration metrics.
#[derive(Debug, Clone, Default)]
pub struct CalibrationTracker {
    records: Vec<CalibrationRecord>,
}

impl CalibrationTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one prediction outcome. `predicted_percent` is clamped to
    /// `[0, 100]`.
    pub fn record(&mut self, predicted_percent: u8, occurred: bool) {
        self.records.push(CalibrationRecord {
            predicted_percent: predicted_percent.min(100),
            occurred,
        });
    }

    #[must_use]
    pub fn records(&self) -> &[CalibrationRecord] {
        &self.records
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Mean stated confidence across all records, as a probability in
    /// `[0.0, 1.0]`. `None` when empty.
    #[must_use]
    pub fn mean_predicted(&self) -> Option<f32> {
        if self.records.is_empty() {
            return None;
        }
        let sum: f32 = self
            .records
            .iter()
            .map(|record| f32::from(record.predicted_percent) / 100.0)
            .sum();
        Some(sum / self.count_as_f32())
    }

    /// Fraction of records whose event actually occurred, in `[0.0, 1.0]`.
    /// `None` when empty.
    #[must_use]
    pub fn empirical_rate(&self) -> Option<f32> {
        if self.records.is_empty() {
            return None;
        }
        let hits = self.records.iter().filter(|record| record.occurred).count();
        // hits <= len, both small enough to represent exactly in f32 here.
        #[allow(clippy::cast_precision_loss)]
        let rate = hits as f32 / self.count_as_f32();
        Some(rate)
    }

    /// The Brier score: mean squared error between stated probability and
    /// realized outcome (0 or 1). Ranges `[0.0, 1.0]`; lower is better.
    /// `None` when empty.
    #[must_use]
    pub fn brier_score(&self) -> Option<f32> {
        if self.records.is_empty() {
            return None;
        }
        let sum: f32 = self
            .records
            .iter()
            .map(|record| {
                let predicted = f32::from(record.predicted_percent) / 100.0;
                let outcome = if record.occurred { 1.0 } else { 0.0 };
                let error = predicted - outcome;
                error * error
            })
            .sum();
        Some(sum / self.count_as_f32())
    }

    /// The overall calibration gap: the absolute difference between mean
    /// stated confidence and the overall realized rate. `None` when empty.
    #[must_use]
    pub fn mean_calibration_error(&self) -> Option<f32> {
        Some((self.mean_predicted()? - self.empirical_rate()?).abs())
    }

    /// Groups records into `bin_count` equal-width confidence bands over
    /// `[0, 100]` and summarizes each **non-empty** band. `bin_count` is
    /// treated as at least 1.
    #[must_use]
    pub fn reliability_bins(&self, bin_count: usize) -> Vec<ReliabilityBin> {
        let bins = bin_count.max(1);
        let mut buckets: Vec<(usize, u32, u32)> = vec![(0, 0, 0); bins];

        for record in &self.records {
            let index = bin_index(record.predicted_percent, bins);
            let bucket = &mut buckets[index];
            bucket.0 += 1;
            bucket.1 += u32::from(record.predicted_percent);
            bucket.2 += u32::from(record.occurred);
        }

        buckets
            .into_iter()
            .enumerate()
            .filter(|(_, (count, _, _))| *count > 0)
            .map(|(index, (count, predicted_sum, hit_count))| {
                let width = 100.0 / precise(bins);
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let lower_percent = (width * precise(index)) as u8;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let upper_percent = (width * precise(index + 1)).min(100.0) as u8;
                let count_f = precise(count);
                ReliabilityBin {
                    lower_percent,
                    upper_percent,
                    count,
                    mean_predicted: precise_u32(predicted_sum) / count_f / 100.0,
                    empirical_rate: precise_u32(hit_count) / count_f,
                }
            })
            .collect()
    }

    /// The expected calibration error (ECE): the sample-weighted average,
    /// over confidence bands, of the gap between mean stated confidence and
    /// realized rate. Ranges `[0.0, 1.0]`; lower is better. `None` when
    /// empty.
    #[must_use]
    pub fn expected_calibration_error(&self, bin_count: usize) -> Option<f32> {
        if self.records.is_empty() {
            return None;
        }
        let total = self.count_as_f32();
        let ece = self
            .reliability_bins(bin_count)
            .into_iter()
            .map(|bin| {
                let weight = precise(bin.count) / total;
                weight * (bin.mean_predicted - bin.empirical_rate).abs()
            })
            .sum();
        Some(ece)
    }

    /// Which way the agent's confidence is biased, judged by the overall
    /// calibration gap against `tolerance` (a probability, e.g. `0.05`).
    /// `None` when empty.
    #[must_use]
    pub fn tendency(&self, tolerance: f32) -> Option<CalibrationTendency> {
        let predicted = self.mean_predicted()?;
        let empirical = self.empirical_rate()?;
        let gap = predicted - empirical;
        Some(if gap > tolerance {
            CalibrationTendency::Overconfident
        } else if gap < -tolerance {
            CalibrationTendency::Underconfident
        } else {
            CalibrationTendency::WellCalibrated
        })
    }

    /// Recalibrates a raw confidence via histogram binning: if the band
    /// `raw_percent` falls into holds at least `min_samples` observations,
    /// returns that band's empirical hit-rate (as a percent); otherwise
    /// returns `raw_percent` unchanged, so sparse evidence never overrides
    /// the prior. With no history the input is always returned as-is.
    #[must_use]
    pub fn calibrated_percent(&self, raw_percent: u8, bin_count: usize, min_samples: usize) -> u8 {
        let raw = raw_percent.min(100);
        let bins = bin_count.max(1);
        let target_index = bin_index(raw, bins);
        for bin in self.reliability_bins(bins) {
            if bin_index(bin.lower_percent, bins) == target_index && bin.count >= min_samples.max(1)
            {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let calibrated = (bin.empirical_rate * 100.0).round() as u8;
                return calibrated.min(100);
            }
        }
        raw
    }

    fn count_as_f32(&self) -> f32 {
        precise(self.records.len())
    }
}

/// Which equal-width bin (of `bins` over `[0, 100]`) a percent falls into.
/// The top value (100) maps to the last bin.
fn bin_index(percent: u8, bins: usize) -> usize {
    (usize::from(percent) * bins / 100).min(bins - 1)
}

/// `usize` → `f32` for small magnitudes used in averaging. Counts here are
/// bounded by the number of records, well within f32's exact-integer range.
#[allow(clippy::cast_precision_loss)]
const fn precise(value: usize) -> f32 {
    value as f32
}

#[allow(clippy::cast_precision_loss)]
const fn precise_u32(value: u32) -> f32 {
    value as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tracker_yields_no_metrics() {
        let tracker = CalibrationTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.brier_score(), None);
        assert_eq!(tracker.empirical_rate(), None);
        assert_eq!(tracker.mean_calibration_error(), None);
        assert_eq!(tracker.expected_calibration_error(10), None);
        assert_eq!(tracker.tendency(0.05), None);
        // With no history, recalibration returns the input untouched.
        assert_eq!(tracker.calibrated_percent(60, 10, 1), 60);
    }

    #[test]
    fn brier_score_matches_hand_computed_value() {
        let mut tracker = CalibrationTracker::new();
        // Predicted 100% and it occurred → error 0.
        tracker.record(100, true);
        // Predicted 0% and it did not occur → error 0.
        tracker.record(0, false);
        assert_eq!(tracker.brier_score(), Some(0.0));

        // Predicted 50%, outcome true → (0.5-1)^2 = 0.25.
        let mut half = CalibrationTracker::new();
        half.record(50, true);
        assert!((half.brier_score().unwrap() - 0.25).abs() < 1e-6);
    }

    #[test]
    fn perfectly_confident_and_correct_is_well_calibrated() {
        let mut tracker = CalibrationTracker::new();
        for _ in 0..10 {
            tracker.record(100, true);
        }
        assert!((tracker.empirical_rate().unwrap() - 1.0).abs() < 1e-6);
        assert!((tracker.mean_predicted().unwrap() - 1.0).abs() < 1e-6);
        assert_eq!(tracker.mean_calibration_error(), Some(0.0));
        assert_eq!(
            tracker.tendency(0.05),
            Some(CalibrationTendency::WellCalibrated)
        );
    }

    #[test]
    fn detects_overconfidence() {
        let mut tracker = CalibrationTracker::new();
        // Says 90% ten times, only 3 occur → overconfident.
        for i in 0..10 {
            tracker.record(90, i < 3);
        }
        assert_eq!(
            tracker.tendency(0.05),
            Some(CalibrationTendency::Overconfident)
        );
        // gap = 0.9 - 0.3 = 0.6
        assert!((tracker.mean_calibration_error().unwrap() - 0.6).abs() < 1e-6);
    }

    #[test]
    fn detects_underconfidence() {
        let mut tracker = CalibrationTracker::new();
        // Says 20% ten times, but 8 occur → underconfident.
        for i in 0..10 {
            tracker.record(20, i < 8);
        }
        assert_eq!(
            tracker.tendency(0.05),
            Some(CalibrationTendency::Underconfident)
        );
    }

    #[test]
    fn reliability_bins_group_by_confidence_band() {
        let mut tracker = CalibrationTracker::new();
        tracker.record(15, false); // low band
        tracker.record(15, false);
        tracker.record(95, true); // high band
        tracker.record(95, true);

        let bins = tracker.reliability_bins(10);
        assert_eq!(bins.len(), 2, "two distinct non-empty bands");
        let low = bins.iter().find(|b| b.lower_percent == 10).unwrap();
        assert_eq!(low.count, 2);
        assert!((low.empirical_rate - 0.0).abs() < 1e-6);
        let high = bins.iter().find(|b| b.lower_percent == 90).unwrap();
        assert_eq!(high.count, 2);
        assert!((high.empirical_rate - 1.0).abs() < 1e-6);
    }

    #[test]
    fn ece_is_zero_for_perfect_calibration() {
        let mut tracker = CalibrationTracker::new();
        // A 0% band that never occurs and a 100% band that always does.
        for _ in 0..5 {
            tracker.record(0, false);
            tracker.record(100, true);
        }
        assert!(tracker.expected_calibration_error(10).unwrap() < 1e-6);
    }

    #[test]
    fn ece_is_high_for_miscalibration() {
        let mut tracker = CalibrationTracker::new();
        // A single band that says 100% but never occurs → ECE ≈ 1.
        for _ in 0..8 {
            tracker.record(100, false);
        }
        assert!((tracker.expected_calibration_error(10).unwrap() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn recalibration_uses_empirical_rate_when_enough_samples() {
        let mut tracker = CalibrationTracker::new();
        // The 90% band actually occurs only 40% of the time, with plenty of
        // samples → a raw 92% recalibrates toward ~40%.
        for i in 0..10 {
            tracker.record(92, i < 4);
        }
        let calibrated = tracker.calibrated_percent(92, 10, 5);
        assert_eq!(calibrated, 40);
    }

    #[test]
    fn recalibration_keeps_raw_value_when_samples_are_sparse() {
        let mut tracker = CalibrationTracker::new();
        tracker.record(92, false); // only one sample in the band
        // min_samples not met → return the raw input unchanged.
        assert_eq!(tracker.calibrated_percent(92, 10, 5), 92);
    }
}
