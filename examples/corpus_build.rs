//! Regenerates the committed catalog training corpus.
//!
//! Build-time dev tool only — never part of the shipped binary. Run:
//!
//! ```text
//! cargo run --example corpus_build > src/corpus_catalog.txt
//! ```
//!
//! The generated file (`src/corpus_catalog.txt`) is compiled into the binary
//! with `include_str!` and appended to the model's training corpus. A test
//! (`corpus_gen::committed_corpus_matches_the_generator`) fails if the
//! committed file drifts from this generator, so regeneration stays honest.

fn main() {
    print!("{}", security_agent::corpus_gen::generate_catalog_corpus());
}
