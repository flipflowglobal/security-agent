//! Deterministic training-corpus generator mined from the tool catalog.
//!
//! The neural language model learns from a small hand-written security corpus
//! (`SECURITY_CORPUS` in [`crate::language_model`]). That corpus is broad on
//! concepts but thin on the agent's own **tool vocabulary** — the 89 cataloged
//! tool names and the execution-class language that surrounds them. This
//! module synthesizes one grammatical, in-domain sentence per cataloged tool
//! from the authoritative catalog ([`crate::registry::cataloged_tool_names`])
//! and each tool's execution class ([`crate::registry::classify_execution`]),
//! so the model sees every tool name and reinforces the least-invasive-first
//! class distinctions the orchestrator relies on.
//!
//! The output is **committed** to `src/corpus_catalog.txt` and compiled into
//! the binary with `include_str!`, so the runtime stays a single pure-Rust,
//! offline, deterministic artifact — the generator is a build-time dev tool
//! (`cargo run --example corpus_build`), never a runtime dependency. A test
//! asserts the committed file matches this generator, so the artifact can
//! never silently drift from its source.

use crate::registry::{ExecutionClass, cataloged_tool_names, classify_execution};

/// The committed catalog corpus, compiled into the binary and appended to the
/// hand-written security corpus during training (see
/// [`crate::language_model::NeuralLanguageModel::bundled`]).
pub const CATALOG_CORPUS: &str = include_str!("corpus_catalog.txt");

/// Renders the catalog corpus: one sentence per cataloged tool.
///
/// Sentences are emitted in the catalog's canonical (sorted, deduplicated)
/// order, each terminated with a period and newline. Pure and deterministic —
/// the same catalog always yields byte-identical output.
///
/// The sentence for a tool states its execution surface in the same
/// least-invasive-first vocabulary the orchestrator uses, which both
/// introduces the tool name into the model's vocabulary and ties it to its
/// class.
#[must_use]
pub fn generate_catalog_corpus() -> String {
    let mut out = String::new();
    for name in cataloged_tool_names() {
        out.push_str(&sentence_for(&name, classify_execution(&name)));
        out.push('\n');
    }
    out
}

/// The training sentence for one tool, without the trailing newline.
fn sentence_for(name: &str, class: ExecutionClass) -> String {
    let predicate = match class {
        ExecutionClass::StaticLocalAnalysis => {
            "runs static local analysis on authorized evidence within scope"
        }
        ExecutionClass::ActiveNetwork => "actively scans an authorized network target within scope",
        ExecutionClass::ActiveExploitation => {
            "attempts exploitation of an authorized target after explicit approval"
        }
    };
    format!("{name} {predicate}.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_corpus_matches_the_generator() {
        assert_eq!(
            generate_catalog_corpus(),
            CATALOG_CORPUS,
            "src/corpus_catalog.txt is stale — regenerate it with \
             `cargo run --example corpus_build > src/corpus_catalog.txt`",
        );
    }

    #[test]
    fn every_cataloged_tool_appears_once() {
        let corpus = generate_catalog_corpus();
        for name in cataloged_tool_names() {
            let hits = corpus
                .lines()
                .filter(|line| line.starts_with(&format!("{name} ")))
                .count();
            assert_eq!(hits, 1, "tool '{name}' should have exactly one sentence");
        }
        assert_eq!(
            corpus.lines().count(),
            cataloged_tool_names().len(),
            "one sentence per cataloged tool",
        );
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(generate_catalog_corpus(), generate_catalog_corpus());
    }

    #[test]
    fn every_sentence_is_a_terminated_clause() {
        for line in generate_catalog_corpus().lines() {
            assert!(
                line.ends_with('.'),
                "sentence must end with a period: {line}"
            );
            assert!(
                line.split_whitespace().count() >= 5,
                "sentence should be a full clause: {line}",
            );
        }
    }
}
