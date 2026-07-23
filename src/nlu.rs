//! A grounded natural-language intent router.
//!
//! This lets the agent take a plain-English instruction and map it to one of
//! its own capabilities — list tools/skills, explain a skill, report status,
//! plan a scan, generate text, or score a string for anomaly — and reply in
//! English, all offline. It is deliberately *grounded*: it routes to real,
//! in-scope actions rather than free-forming, so it never claims to do
//! things the agent cannot.
//!
//! Routing combines two fully-local signals:
//!
//! - **Lexical anchoring** — matches against each capability's trigger words
//!   and phrases (the reliable primary signal), plus recognition of the
//!   agent's own tool/skill names as a strong "explain this" cue.
//! - **Semantic similarity** — cosine similarity between the instruction and
//!   each capability's example phrasings in the built-in language model's
//!   learned embedding space ([`crate::language_model::NeuralLanguageModel::embed_text`]),
//!   which generalizes to paraphrases the keywords miss.
//!
//! Scope is authorized defensive and offensive security work: an instruction
//! that matches nothing routes to [`Intent::OutOfScope`] with a polite
//! decline. Nothing here executes or authorizes anything — it only
//! *interprets*; the caller decides what to run.

use crate::language_model::NeuralLanguageModel;
use crate::local_assets::LocalAgentAssets;

/// A capability the router can recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    OfflineStatus,
    About,
    Help,
    ListTools,
    ListSkills,
    ShowSkill,
    PlanScan,
    ScheduleRetest,
    ViewAudit,
    ViewAuditDb,
    ViewFindingsDb,
    ViewCalibrationDb,
    ViewReasoningLogDb,
    Generate,
    AnomalyCheck,
    OutOfScope,
}

impl Intent {
    /// A short human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OfflineStatus => "offline-status",
            Self::About => "about",
            Self::Help => "help",
            Self::ListTools => "list-tools",
            Self::ListSkills => "list-skills",
            Self::ShowSkill => "show-skill",
            Self::PlanScan => "plan-scan",
            Self::ScheduleRetest => "schedule-retest",
            Self::ViewAudit => "view-audit",
            Self::ViewAuditDb => "view-audit-db",
            Self::ViewFindingsDb => "view-findings-db",
            Self::ViewCalibrationDb => "view-calibration-db",
            Self::ViewReasoningLogDb => "view-reasoning-log-db",
            Self::Generate => "generate",
            Self::AnomalyCheck => "anomaly-check",
            Self::OutOfScope => "out-of-scope",
        }
    }
}

/// The router's understanding of an instruction.
#[derive(Debug, Clone)]
pub struct Interpretation {
    pub intent: Intent,
    /// Softmax confidence over the candidate intents, 0–100.
    pub confidence: u8,
    /// An extracted argument (a skill/tool name, a path, or free text),
    /// when the intent takes one.
    pub slot: Option<String>,
    /// A plain-English reply describing what was understood and the next
    /// step.
    pub reply: String,
}

/// One capability's routing signals.
struct IntentSpec {
    intent: Intent,
    /// Trigger words/phrases; a phrase (with a space) must appear verbatim.
    triggers: &'static [&'static str],
    /// Example phrasings, embedded to form the semantic centroid.
    examples: &'static [&'static str],
}

const SPECS: &[IntentSpec] = &[
    IntentSpec {
        intent: Intent::OfflineStatus,
        triggers: &["status", "health", "offline", "ready", "state"],
        examples: &[
            "what is your status",
            "report local status",
            "are you healthy",
        ],
    },
    IntentSpec {
        intent: Intent::About,
        triggers: &["about", "version", "mission", "who are you", "purpose"],
        examples: &[
            "who are you",
            "what is your mission",
            "tell me about yourself",
        ],
    },
    IntentSpec {
        intent: Intent::Help,
        triggers: &["help", "commands", "usage", "what can you do"],
        examples: &["help", "what can you do", "list your commands"],
    },
    IntentSpec {
        intent: Intent::ListTools,
        triggers: &["list tools", "tools", "tool catalog", "capabilities"],
        examples: &[
            "list your tools",
            "what tools do you have",
            "enumerate tools",
        ],
    },
    IntentSpec {
        intent: Intent::ListSkills,
        triggers: &["list skills", "skills"],
        examples: &["list skills", "what skills do you have", "show skills"],
    },
    IntentSpec {
        intent: Intent::ShowSkill,
        triggers: &["show", "explain", "describe", "how do i use", "skill for"],
        examples: &[
            "show me the nmap skill",
            "explain the semgrep tool",
            "how do i use jadx",
        ],
    },
    IntentSpec {
        intent: Intent::PlanScan,
        triggers: &["plan", "scan", "assess", "assessment", "engagement"],
        examples: &["plan a scan", "run an assessment", "scan the target"],
    },
    IntentSpec {
        intent: Intent::ScheduleRetest,
        triggers: &["retest", "reschedule"],
        examples: &[
            "schedule a retest",
            "when should i retest",
            "retest schedule",
        ],
    },
    IntentSpec {
        intent: Intent::ViewAudit,
        triggers: &["audit", "ledger"],
        examples: &["show the audit log", "view audit records", "audit history"],
    },
    // The four `*Db` intents below share the word "database"/"db" with
    // each other, so each also carries a distinguishing phrase trigger
    // ("audit database", "findings database", ...) worth 1.5 lexical
    // points -- enough to outrank a same-topic single-word intent like
    // `ViewAudit` (worth 1.0) whenever the instruction actually names the
    // database, while a bare "show the audit log" still routes to
    // `ViewAudit` since no `*Db` phrase trigger matches it at all.
    IntentSpec {
        intent: Intent::ViewAuditDb,
        triggers: &["audit database", "audit db"],
        examples: &[
            "show the audit database",
            "view the audit database",
            "open the audit db",
        ],
    },
    IntentSpec {
        intent: Intent::ViewFindingsDb,
        triggers: &["findings database", "findings db"],
        examples: &[
            "show the findings database",
            "view the findings database",
            "open the findings db",
        ],
    },
    IntentSpec {
        intent: Intent::ViewCalibrationDb,
        triggers: &["calibration database", "calibration db", "calibration"],
        examples: &[
            "show the calibration database",
            "how calibrated are you",
            "view calibration history",
        ],
    },
    IntentSpec {
        intent: Intent::ViewReasoningLogDb,
        triggers: &["reasoning log", "reasoning database", "reasoning history"],
        examples: &[
            "show the reasoning log",
            "view past reasoning",
            "show archived reasoning",
        ],
    },
    IntentSpec {
        intent: Intent::Generate,
        triggers: &["generate", "write", "continue", "compose", "draft"],
        examples: &[
            "generate text about scanning",
            "write about findings",
            "continue this",
        ],
    },
    IntentSpec {
        intent: Intent::AnomalyCheck,
        triggers: &[
            "anomaly",
            "suspicious",
            "surprising",
            "perplexity",
            "weird",
            "malicious",
        ],
        examples: &[
            "is this string suspicious",
            "check this for anomalies",
            "how surprising is this",
        ],
    },
];

/// Relative weight of the semantic signal against the lexical one when
/// *ranking* candidate intents. Semantic similarity disambiguates among
/// intents the instruction already anchors to lexically; it is deliberately
/// **not** trusted to decide scope on its own, because the bundled model is
/// tiny enough that its similarity to short example phrases is near-noise
/// for unrelated text (an off-topic string can sit as close to an intent's
/// examples as a real paraphrase does). Scope is therefore grounded in the
/// agent's own vocabulary — see [`interpret`].
const SEMANTIC_WEIGHT: f32 = 1.5;

/// Interprets a plain-English `instruction` against the agent's
/// capabilities, using `assets` to recognize its own tool/skill names and
/// `model` for semantic similarity.
#[must_use]
pub fn interpret(
    instruction: &str,
    assets: &LocalAgentAssets,
    model: &NeuralLanguageModel,
) -> Interpretation {
    let lowered = instruction.to_ascii_lowercase();
    let instruction_vec = model.embed_text(instruction);
    let asset_name = known_asset_name(&lowered, assets);

    // Per-spec signals, keeping the lexical anchor alongside the combined
    // score so the scope gate can inspect it separately from the ranking.
    let mut scored: Vec<(Intent, f32, f32)> = SPECS
        .iter()
        .map(|spec| {
            let lexical = lexical_score(&lowered, spec.triggers);
            let semantic = semantic_score(&instruction_vec, spec.examples, model);
            let mut combined = SEMANTIC_WEIGHT.mul_add(semantic, lexical);
            // Naming one of the agent's own tools/skills strongly implies
            // "explain this to me".
            if spec.intent == Intent::ShowSkill && asset_name.is_some() {
                combined += 1.5;
            }
            (spec.intent, combined, lexical)
        })
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let (best_intent, _, best_lexical) = scored[0];

    let ranked: Vec<(Intent, f32)> = scored.iter().map(|&(i, c, _)| (i, c)).collect();
    let confidence = softmax_confidence(&ranked);

    // Grounded scope decision: an instruction is in scope only if it anchors
    // to a real capability's trigger vocabulary or names one of the agent's
    // own tools/skills. Semantic similarity ranks the matched intents but is
    // too weak here to admit scope on its own, so an off-topic request with
    // no keyword overlap declines cleanly to `OutOfScope`.
    let intent = if best_lexical > 0.0 || asset_name.is_some() {
        best_intent
    } else {
        Intent::OutOfScope
    };

    let slot = extract_slot(intent, instruction, &lowered, asset_name);
    let reply = build_reply(intent, slot.as_deref(), assets);
    Interpretation {
        intent,
        confidence,
        slot,
        reply,
    }
}

/// Lexical score: 1.0 per matched single word, 1.5 per matched multi-word
/// phrase (phrases are stronger evidence).
fn lexical_score(lowered: &str, triggers: &[&str]) -> f32 {
    let mut score = 0.0;
    for trigger in triggers {
        if trigger.contains(' ') {
            if lowered.contains(trigger) {
                score += 1.5;
            }
        } else if lowered
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| word == *trigger)
        {
            score += 1.0;
        }
    }
    score
}

/// Cosine similarity (mapped to `[0, 1]`) between the instruction vector and
/// the mean example embedding for a capability.
fn semantic_score(instruction_vec: &[f32], examples: &[&str], model: &NeuralLanguageModel) -> f32 {
    let mut centroid = vec![0.0_f32; instruction_vec.len()];
    for example in examples {
        for (acc, value) in centroid.iter_mut().zip(model.embed_text(example)) {
            *acc += value;
        }
    }
    (cosine(instruction_vec, &centroid) + 1.0) * 0.5
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm_a = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a > 0.0 && norm_b > 0.0 {
        dot / (norm_a * norm_b)
    } else {
        0.0
    }
}

/// Confidence as the softmax probability of the top-scoring intent.
fn softmax_confidence(scores: &[(Intent, f32)]) -> u8 {
    let max = scores
        .iter()
        .map(|&(_, s)| s)
        .fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = scores.iter().map(|&(_, s)| (s - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum <= 0.0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let top = ((exps[0] / sum) * 100.0).round() as u8;
    top.min(100)
}

/// The first token that names one of the agent's tools or skills, if any.
fn known_asset_name(lowered: &str, assets: &LocalAgentAssets) -> Option<String> {
    lowered
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find(|word| {
            !word.is_empty() && (assets.tool(word).is_some() || assets.skill(word).is_some())
        })
        .map(ToString::to_string)
}

/// Extracts the intent's argument: a tool/skill name, or free text after the
/// trigger word for generation/anomaly intents.
fn extract_slot(
    intent: Intent,
    instruction: &str,
    lowered: &str,
    asset_name: Option<String>,
) -> Option<String> {
    match intent {
        Intent::ShowSkill => asset_name,
        Intent::Generate => Some(strip_leading(
            instruction,
            &[
                "generate", "write", "continue", "compose", "draft", "about", "text", "a", "the",
            ],
        )),
        Intent::AnomalyCheck => Some(after_marker(instruction, lowered)),
        Intent::PlanScan
        | Intent::ViewAudit
        | Intent::ViewAuditDb
        | Intent::ViewFindingsDb
        | Intent::ViewCalibrationDb
        | Intent::ViewReasoningLogDb
        | Intent::ScheduleRetest => instruction
            .split_whitespace()
            .find(|token| token.contains('/') || token.contains('.'))
            .map(ToString::to_string),
        _ => None,
    }
}

/// Drops leading words that are pure command noise, keeping the substantive
/// remainder as a generation prompt.
fn strip_leading(instruction: &str, noise: &[&str]) -> String {
    let mut words: Vec<&str> = instruction.split_whitespace().collect();
    while let Some(first) = words.first() {
        let clean = first
            .trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if noise.contains(&clean.as_str()) {
            words.remove(0);
        } else {
            break;
        }
    }
    if words.is_empty() {
        instruction.trim().to_string()
    } else {
        words.join(" ")
    }
}

/// Returns quoted text if present, else the text after a colon, else the
/// whole instruction — the string to score for anomaly.
fn after_marker(instruction: &str, lowered: &str) -> String {
    if let (Some(start), Some(end)) = (instruction.find('"'), instruction.rfind('"')) {
        if end > start + 1 {
            return instruction[start + 1..end].to_string();
        }
    }
    if let Some(colon) = lowered.find(':') {
        let rest = instruction[colon + 1..].trim();
        if !rest.is_empty() {
            return rest.to_string();
        }
    }
    instruction.trim().to_string()
}

/// Builds the plain-English reply for an interpreted intent.
fn build_reply(intent: Intent, slot: Option<&str>, assets: &LocalAgentAssets) -> String {
    match intent {
        Intent::OfflineStatus => "Reporting local runtime status.".to_string(),
        Intent::About => "Here is who I am and my roadmap.".to_string(),
        Intent::Help => {
            "I can list tools/skills, explain a skill, report status, plan an authorized scan, \
             generate text, and score text for anomalies. Ask me in plain English."
                .to_string()
        }
        Intent::ListTools => format!(
            "I have {} cataloged tools; listing them.",
            assets.tools().len()
        ),
        Intent::ListSkills => {
            format!(
                "I have {} embedded skills; listing them.",
                assets.skills().len()
            )
        }
        Intent::ShowSkill => match slot {
            Some(name) if assets.skill(name).is_some() => {
                format!("Showing the '{name}' skill.")
            }
            Some(name) => format!(
                "I don't have a skill named '{name}'. Try 'list skills' to see what's available."
            ),
            None => {
                "Which skill or tool should I explain? Name one, e.g. 'explain nmap'.".to_string()
            }
        },
        Intent::PlanScan => slot.map_or_else(
            || {
                "Planning a scan needs an engagement config file. Run: --plan-scan <config> \
                 (add --cognitive-review for analysis)."
                    .to_string()
            },
            |path| format!("Planning an authorized scan from the engagement config '{path}'."),
        ),
        Intent::ScheduleRetest => slot.map_or_else(
            || "Point me at a findings log: --schedule-retest <findings-log>.jsonl.".to_string(),
            |path| format!("Deriving a retest schedule from the findings log '{path}'."),
        ),
        Intent::ViewAudit => slot.map_or_else(
            || "Point me at an audit log: --view-audit <log>.jsonl.".to_string(),
            |path| format!("Viewing the audit log '{path}'."),
        ),
        Intent::ViewAuditDb => slot.map_or_else(
            || "Point me at an audit database: --view-audit-db <db>.sadb.".to_string(),
            |path| format!("Viewing the audit database '{path}'."),
        ),
        Intent::ViewFindingsDb => slot.map_or_else(
            || "Point me at a findings database: --view-findings-db <db>.sadb.".to_string(),
            |path| format!("Viewing the findings database '{path}'."),
        ),
        Intent::ViewCalibrationDb => slot.map_or_else(
            || "Point me at a calibration database: --view-calibration-db <db>.sadb.".to_string(),
            |path| format!("Viewing the calibration database '{path}'."),
        ),
        Intent::ViewReasoningLogDb => slot.map_or_else(
            || {
                "Point me at a reasoning log database: --view-reasoning-log-db <db>.sadb."
                    .to_string()
            },
            |path| format!("Viewing the reasoning log database '{path}'."),
        ),
        Intent::Generate => {
            "Generating a continuation with the built-in language model.".to_string()
        }
        Intent::AnomalyCheck => {
            "Scoring that text for language-model surprise (higher = more out-of-domain)."
                .to_string()
        }
        Intent::OutOfScope => {
            "That's outside my scope. I'm a defensive and offensive security orchestration agent \
             — I can plan authorized scans and penetration tests, run local analysis tools, \
             explain skills, report status, and score text. I'm offline by default; live/active \
             tools need the --allow-network opt-in. Try 'list tools' or 'help'."
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> NeuralLanguageModel {
        NeuralLanguageModel::bundled()
    }

    fn route(instruction: &str) -> Interpretation {
        interpret(instruction, &LocalAgentAssets::bundled(), &model())
    }

    #[test]
    fn routes_common_instructions() {
        assert_eq!(route("list your tools").intent, Intent::ListTools);
        assert_eq!(route("what skills do you have").intent, Intent::ListSkills);
        assert_eq!(route("what is your status").intent, Intent::OfflineStatus);
        assert_eq!(route("who are you").intent, Intent::About);
        assert_eq!(route("plan a scan of the target").intent, Intent::PlanScan);
    }

    #[test]
    fn recognizes_a_skill_name_and_extracts_it() {
        let interp = route("show me the nmap skill");
        assert_eq!(interp.intent, Intent::ShowSkill);
        assert_eq!(interp.slot.as_deref(), Some("nmap"));
    }

    #[test]
    fn extracts_generation_prompt() {
        let interp = route("generate text about scanning targets");
        assert_eq!(interp.intent, Intent::Generate);
        assert_eq!(interp.slot.as_deref(), Some("scanning targets"));
    }

    #[test]
    fn extracts_anomaly_text_from_quotes() {
        let interp = route("is this suspicious: \"zzq xqv payload\"");
        assert_eq!(interp.intent, Intent::AnomalyCheck);
        assert_eq!(interp.slot.as_deref(), Some("zzq xqv payload"));
    }

    #[test]
    fn routes_the_new_db_view_intents_and_distinguishes_them_from_view_audit() {
        assert_eq!(route("show the audit database").intent, Intent::ViewAuditDb);
        assert_eq!(route("show the audit log").intent, Intent::ViewAudit);
        assert_eq!(
            route("show the findings database").intent,
            Intent::ViewFindingsDb
        );
        assert_eq!(
            route("show the calibration database").intent,
            Intent::ViewCalibrationDb
        );
        assert_eq!(
            route("show the reasoning log").intent,
            Intent::ViewReasoningLogDb
        );
    }

    #[test]
    fn extracts_a_path_for_the_new_db_view_intents() {
        let interp = route("show the audit database at audit.sadb");
        assert_eq!(interp.intent, Intent::ViewAuditDb);
        assert_eq!(interp.slot.as_deref(), Some("audit.sadb"));
    }

    #[test]
    fn declines_out_of_scope_requests() {
        let interp = route("book me a flight to paris");
        assert_eq!(interp.intent, Intent::OutOfScope);
        assert!(interp.reply.contains("outside my scope"));
    }

    #[test]
    fn confidence_is_bounded() {
        for instruction in ["list tools", "who are you", "book a flight"] {
            assert!(route(instruction).confidence <= 100);
        }
    }
}
