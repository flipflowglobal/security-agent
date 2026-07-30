//! Regenerates the committed trained-weights blob.
//!
//! Build-time dev tool only — never part of the shipped binary. Run:
//!
//! ```text
//! cargo run --release --example train_weights > src/model_weights.bin
//! ```
//!
//! The generated file (`src/model_weights.bin`) is compiled into the binary
//! with `include_bytes!` and loaded by `NeuralLanguageModel::bundled()` in
//! place of retraining. A Linux-gated test
//! (`committed_weights_match_a_freshly_trained_model`) fails if the committed
//! blob drifts from the training code, so regeneration stays honest.

use std::io::Write as _;

fn main() {
    let blob = security_agent::NeuralLanguageModel::bundled_weight_blob();
    std::io::stdout()
        .write_all(&blob)
        .expect("write weights blob to stdout");
}
