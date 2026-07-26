//! Write-only, on-disk archive of the agent's deliberations: each run's
//! full [`ReasoningChain`] and [`Metacognition`] verdict, backed by the
//! `.sadb` engine ([`crate::sadb`]).
//!
//! Unlike [`crate::calibration_db`], nothing here ever feeds back into
//! reasoning -- [`AdversaryMove`](crate::cognitive_engine::AdversaryMove),
//! attention, and belief-propagation output are deliberately *not*
//! archived here, because they're pure functions of `targets` and
//! `memory`, both already persisted elsewhere; storing them again would
//! just be duplicating derivable state. What's stored is exactly what
//! can't be recomputed later: what the agent actually concluded, and why,
//! at the time -- an immutable record even if the reasoning code itself
//! changes afterward.
//!
//! Two tables, following the chain's own shape: one row per run in
//! `reasoning_runs`, and one row per [`Thought`] in `reasoning_thoughts`,
//! each pointing back at its run via the [`RecordId`] `reasoning_runs`
//! returned when that run was inserted.

use crate::cognitive_engine::{Metacognition, ReasoningChain, Thought, ThoughtKind};
use crate::sadb::codec::{Reader, write_bool, write_f32, write_string, write_u8, write_u64};
use crate::sadb::{Database, DbError, RecordId};
use std::collections::HashMap;
use std::path::Path;

const RUNS_TABLE: &str = "reasoning_runs";
const THOUGHTS_TABLE: &str = "reasoning_thoughts";

/// One archived deliberation: everything [`append_run`] wrote for a
/// single [`crate::cognitive_engine::CognitiveEngine::deliberate`] call.
#[derive(Debug, Clone)]
pub struct RecordedRun {
    pub timestamp_epoch_seconds: u64,
    pub reasoning_chain: ReasoningChain,
    pub metacognition: Metacognition,
}

fn encode_run(
    timestamp_epoch_seconds: u64,
    chain: &ReasoningChain,
    meta: &Metacognition,
) -> Vec<u8> {
    let mut buffer = Vec::new();
    write_u64(&mut buffer, timestamp_epoch_seconds);
    write_u8(&mut buffer, chain.overall_confidence());
    write_u8(&mut buffer, meta.self_assessed_confidence);
    write_f32(&mut buffer, meta.uncertainty);
    write_bool(&mut buffer, meta.should_escalate);
    write_string(&mut buffer, &meta.reasoning);
    #[allow(clippy::cast_possible_truncation)]
    write_u32_len(&mut buffer, meta.knowledge_gaps.len());
    for gap in &meta.knowledge_gaps {
        write_string(&mut buffer, gap);
    }
    buffer
}

fn write_u32_len(buffer: &mut Vec<u8>, len: usize) {
    #[allow(clippy::cast_possible_truncation)]
    crate::sadb::codec::write_u32(buffer, len as u32);
}

struct RunSummary {
    timestamp_epoch_seconds: u64,
    self_assessed_confidence: u8,
    uncertainty: f32,
    should_escalate: bool,
    reasoning: String,
    knowledge_gaps: Vec<String>,
}

fn decode_run(bytes: &[u8]) -> Option<RunSummary> {
    let mut reader = Reader::new(bytes);
    let timestamp_epoch_seconds = reader.read_u64().ok()?;
    let _overall_confidence = reader.read_u8().ok()?;
    let self_assessed_confidence = reader.read_u8().ok()?;
    let uncertainty = reader.read_f32().ok()?;
    let should_escalate = reader.read_bool().ok()?;
    let reasoning = reader.read_string().ok()?;
    let gap_count = reader.read_u32().ok()?;
    let mut knowledge_gaps = Vec::new();
    for _ in 0..gap_count {
        knowledge_gaps.push(reader.read_string().ok()?);
    }
    Some(RunSummary {
        timestamp_epoch_seconds,
        self_assessed_confidence,
        uncertainty,
        should_escalate,
        reasoning,
        knowledge_gaps,
    })
}

const fn kind_to_u8(kind: ThoughtKind) -> u8 {
    match kind {
        ThoughtKind::Observation => 0,
        ThoughtKind::Inference => 1,
        ThoughtKind::Hypothesis => 2,
        ThoughtKind::Counterfactual => 3,
        ThoughtKind::Decision => 4,
        ThoughtKind::Reflection => 5,
    }
}

const fn kind_from_u8(value: u8) -> Option<ThoughtKind> {
    match value {
        0 => Some(ThoughtKind::Observation),
        1 => Some(ThoughtKind::Inference),
        2 => Some(ThoughtKind::Hypothesis),
        3 => Some(ThoughtKind::Counterfactual),
        4 => Some(ThoughtKind::Decision),
        5 => Some(ThoughtKind::Reflection),
        _ => None,
    }
}

fn encode_thought(run_id: RecordId, thought: &Thought) -> Vec<u8> {
    let mut buffer = Vec::new();
    crate::sadb::codec::write_u32(&mut buffer, run_id.page);
    crate::sadb::codec::write_u16(&mut buffer, run_id.slot);
    write_u8(&mut buffer, kind_to_u8(thought.kind));
    write_string(&mut buffer, &thought.statement);
    write_u8(&mut buffer, thought.confidence_percent);
    write_u32_len(&mut buffer, thought.derived_from.len());
    for index in &thought.derived_from {
        #[allow(clippy::cast_possible_truncation)]
        crate::sadb::codec::write_u32(&mut buffer, *index as u32);
    }
    buffer
}

struct DecodedThought {
    run_id: RecordId,
    kind: ThoughtKind,
    statement: String,
    confidence_percent: u8,
    derived_from: Vec<usize>,
}

fn decode_thought(bytes: &[u8]) -> Option<DecodedThought> {
    let mut reader = Reader::new(bytes);
    let run_id = RecordId {
        page: reader.read_u32().ok()?,
        slot: reader.read_u16().ok()?,
    };
    let kind = kind_from_u8(reader.read_u8().ok()?)?;
    let statement = reader.read_string().ok()?;
    let confidence_percent = reader.read_u8().ok()?;
    let derived_from_count = reader.read_u32().ok()?;
    let mut derived_from = Vec::new();
    for _ in 0..derived_from_count {
        derived_from.push(reader.read_u32().ok()? as usize);
    }
    Some(DecodedThought {
        run_id,
        kind,
        statement,
        confidence_percent,
        derived_from,
    })
}

/// Appends one deliberation -- its full [`ReasoningChain`] and the
/// [`Metacognition`] verdict reached over it -- to the `.sadb` database
/// at `path`, in a single transaction.
///
/// # Errors
///
/// Returns [`DbError`] if the database can't be opened, a row can't be
/// inserted, or the transaction can't be committed.
pub fn append_run(
    path: &Path,
    timestamp_epoch_seconds: u64,
    chain: &ReasoningChain,
    metacognition: &Metacognition,
) -> Result<(), DbError> {
    let mut db = Database::open(path)?;
    let mut txn = db.begin();
    let run_id = txn.insert(
        RUNS_TABLE,
        &encode_run(timestamp_epoch_seconds, chain, metacognition),
    )?;
    for thought in chain.thoughts() {
        txn.insert(THOUGHTS_TABLE, &encode_thought(run_id, thought))?;
    }
    txn.commit()
}

/// Reads back every deliberation previously written by [`append_run`],
/// oldest first, reconstructing each run's [`ReasoningChain`] from its
/// thoughts.
///
/// # Errors
///
/// Returns [`DbError`] if the database can't be opened or scanned.
pub fn load_runs(path: &Path) -> Result<Vec<RecordedRun>, DbError> {
    let mut db = Database::open(path)?;
    let run_rows = db.scan_with_ids(RUNS_TABLE)?;
    let thought_rows: Vec<DecodedThought> = db
        .scan(THOUGHTS_TABLE)?
        .iter()
        .filter_map(|bytes| decode_thought(bytes))
        .collect();

    // Grouped once up front, rather than re-scanning every thought for
    // every run, so this stays O(runs + thoughts) as the archive grows.
    let mut thoughts_by_run: HashMap<RecordId, Vec<&DecodedThought>> = HashMap::new();
    for thought in &thought_rows {
        thoughts_by_run
            .entry(thought.run_id)
            .or_default()
            .push(thought);
    }

    let mut runs = Vec::new();
    for (run_id, run_bytes) in &run_rows {
        let Some(summary) = decode_run(run_bytes) else {
            continue;
        };
        let mut chain = ReasoningChain::new();
        for thought in thoughts_by_run.get(run_id).into_iter().flatten() {
            chain.push(
                thought.kind,
                thought.statement.clone(),
                thought.confidence_percent,
                thought.derived_from.clone(),
            );
        }
        runs.push(RecordedRun {
            timestamp_epoch_seconds: summary.timestamp_epoch_seconds,
            reasoning_chain: chain,
            metacognition: Metacognition {
                self_assessed_confidence: summary.self_assessed_confidence,
                uncertainty: summary.uncertainty,
                knowledge_gaps: summary.knowledge_gaps,
                should_escalate: summary.should_escalate,
                reasoning: summary.reasoning,
            },
        });
    }
    Ok(runs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_chain() -> ReasoningChain {
        let mut chain = ReasoningChain::new();
        let observation = chain.push(
            ThoughtKind::Observation,
            "target has no history",
            100,
            vec![],
        );
        chain.push(
            ThoughtKind::Inference,
            "therefore assume type-based prior",
            60,
            vec![observation],
        );
        chain
    }

    fn sample_metacognition() -> Metacognition {
        Metacognition {
            self_assessed_confidence: 55,
            uncertainty: 0.42,
            knowledge_gaps: vec!["no prior engagements".to_string()],
            should_escalate: true,
            reasoning: "high uncertainty warrants human review".to_string(),
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-reasoning-log-db-{name}-{}.sadb",
            std::process::id()
        ))
    }

    #[test]
    fn a_run_round_trips_with_its_thoughts_and_metacognition_intact() {
        let path = temp_path("round-trip");
        let _ = fs::remove_file(&path);

        append_run(
            &path,
            1_700_000_000,
            &sample_chain(),
            &sample_metacognition(),
        )
        .expect("append should succeed");
        let runs = load_runs(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        assert_eq!(run.timestamp_epoch_seconds, 1_700_000_000);
        assert_eq!(
            run.metacognition.self_assessed_confidence,
            sample_metacognition().self_assessed_confidence
        );
        assert!(
            (run.metacognition.uncertainty - sample_metacognition().uncertainty).abs()
                < f32::EPSILON
        );
        assert_eq!(
            run.metacognition.knowledge_gaps,
            sample_metacognition().knowledge_gaps
        );
        assert_eq!(
            run.metacognition.should_escalate,
            sample_metacognition().should_escalate
        );
        assert_eq!(
            run.metacognition.reasoning,
            sample_metacognition().reasoning
        );

        let thoughts = run.reasoning_chain.thoughts();
        assert_eq!(thoughts.len(), 2);
        assert_eq!(thoughts[0].kind, ThoughtKind::Observation);
        assert_eq!(thoughts[0].statement, "target has no history");
        assert_eq!(thoughts[1].derived_from, vec![0]);
    }

    #[test]
    fn multiple_runs_keep_their_thoughts_correctly_separated() {
        let path = temp_path("multiple-runs");
        let _ = fs::remove_file(&path);

        let mut first_chain = ReasoningChain::new();
        first_chain.push(ThoughtKind::Decision, "first run's decision", 80, vec![]);
        let mut second_chain = ReasoningChain::new();
        second_chain.push(ThoughtKind::Decision, "second run's decision", 90, vec![]);

        append_run(&path, 1, &first_chain, &sample_metacognition()).expect("first append");
        append_run(&path, 2, &second_chain, &sample_metacognition()).expect("second append");

        let runs = load_runs(&path).expect("load should succeed");
        fs::remove_file(&path).expect("remove temp file");

        assert_eq!(runs.len(), 2);
        assert_eq!(
            runs[0].reasoning_chain.thoughts()[0].statement,
            "first run's decision"
        );
        assert_eq!(
            runs[1].reasoning_chain.thoughts()[0].statement,
            "second run's decision"
        );
    }

    #[test]
    fn a_run_with_an_empty_chain_still_round_trips() {
        let path = temp_path("empty-chain");
        let _ = fs::remove_file(&path);

        append_run(&path, 5, &ReasoningChain::new(), &sample_metacognition())
            .expect("append should succeed");
        let runs = load_runs(&path).expect("load should succeed");

        fs::remove_file(&path).expect("remove temp file");
        assert_eq!(runs.len(), 1);
        assert!(runs[0].reasoning_chain.is_empty());
    }
}
