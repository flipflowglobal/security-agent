//! Optional candle-backed language-model backend (`--features inference`).
//!
//! The bundled [`crate::language_model::NeuralLanguageModel`] is a tiny,
//! zero-dependency model compiled into the binary. This module is the seam for
//! a *stronger* brain: a real transformer run on [candle], selectable at
//! runtime, without changing the default zero-dependency build (everything
//! here is behind the `inference` feature).
//!
//! The model is a small **byte-level GPT** built directly from candle-nn
//! primitives (token + positional embeddings, causal multi-head self-attention
//! blocks, a final norm, and a tied-width LM head). Tokenization is byte-level
//! and built in, so a model is fully described by its weights plus a small
//! [`ModelConfig`] — no external tokenizer file. Weights come either from an
//! operator-supplied safetensors file ([`CandleTextModel::load`]) or, for
//! tests, from in-process random initialization
//! ([`CandleTextModel::random`]) — the same forward path either way, so the
//! inference plumbing is exercised end-to-end offline.
//!
//! It implements [`crate::language_model::LanguageModel`], so it is a drop-in
//! alternative anywhere the trait is used. Decoding is greedy, hence
//! deterministic for a fixed model.

use crate::language_model::LanguageModel;
use candle_core::{DType, Device, Tensor};
use candle_nn::{
    Embedding, LayerNorm, Linear, Module, VarBuilder, VarMap, embedding, layer_norm,
    linear_no_bias, ops::softmax,
};
use std::fmt;
use std::path::Path;

/// The size of the byte-level vocabulary (one token per byte value).
pub const VOCAB_SIZE: usize = 256;

/// Upper bound on embedding width (keeps `4 * n_embd` and
/// `VOCAB_SIZE * n_embd` well within `usize`).
const MAX_N_EMBD: usize = 8_192;
/// Upper bound on the number of transformer blocks.
const MAX_N_LAYER: usize = 128;
/// Upper bound on context length (keeps position indices within `u32`).
const MAX_BLOCK_SIZE: usize = 8_192;

/// The architectural shape of a [`CandleTextModel`]. Must match the weights it
/// is loaded with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelConfig {
    /// Embedding width.
    pub n_embd: usize,
    /// Number of attention heads (`n_embd` must divide by this).
    pub n_head: usize,
    /// Number of transformer blocks.
    pub n_layer: usize,
    /// Maximum context length (positions the model has embeddings for).
    pub block_size: usize,
}

impl ModelConfig {
    /// The per-head dimension.
    #[must_use]
    pub const fn head_dim(&self) -> usize {
        self.n_embd / self.n_head
    }

    /// Whether the config is self-consistent and within safe bounds.
    ///
    /// Beyond "heads divide the width, nothing is zero", the fields are capped
    /// so that internal size calculations for operator-supplied configs cannot
    /// overflow or produce out-of-range indices (`4 * n_embd` in the MLP,
    /// `VOCAB_SIZE * n_embd` embedding matrices, `block_size` position indices).
    /// The caps are generous relative to any model this CPU backend would run.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.n_embd != 0
            && self.n_head != 0
            && self.n_layer != 0
            && self.block_size != 0
            && self.n_embd % self.n_head == 0
            && self.n_embd <= MAX_N_EMBD
            && self.n_layer <= MAX_N_LAYER
            && self.block_size <= MAX_BLOCK_SIZE
    }

    /// Parses a config from JSON with integer `n_embd`, `n_head`, `n_layer`,
    /// and `block_size` fields (a model directory's `config.json`).
    ///
    /// # Errors
    ///
    /// Returns [`InferenceError::Load`] if the JSON is malformed or a field is
    /// missing, or [`InferenceError::InvalidConfig`] if the values are not
    /// self-consistent.
    pub fn from_json(text: &str) -> Result<Self, InferenceError> {
        let value = crate::json::parse(text)
            .ok_or_else(|| InferenceError::Load("config.json is not valid JSON".to_string()))?;
        let field = |name: &str| -> Result<usize, InferenceError> {
            value
                .get(name)
                .and_then(crate::json::JsonValue::as_u64)
                .and_then(|number| usize::try_from(number).ok())
                .ok_or_else(|| {
                    InferenceError::Load(format!("config.json missing integer field '{name}'"))
                })
        };
        let config = Self {
            n_embd: field("n_embd")?,
            n_head: field("n_head")?,
            n_layer: field("n_layer")?,
            block_size: field("block_size")?,
        };
        if config.is_valid() {
            Ok(config)
        } else {
            Err(InferenceError::InvalidConfig(format!("{config:?}")))
        }
    }
}

/// Errors from building or running a [`CandleTextModel`].
#[derive(Debug)]
pub enum InferenceError {
    /// The [`ModelConfig`] is not self-consistent.
    InvalidConfig(String),
    /// A weights file could not be read or did not match the config.
    Load(String),
    /// A tensor operation failed during the forward pass.
    Compute(String),
}

impl fmt::Display for InferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid model config: {message}"),
            Self::Load(message) => write!(formatter, "failed to load model: {message}"),
            Self::Compute(message) => write!(formatter, "inference failed: {message}"),
        }
    }
}

impl std::error::Error for InferenceError {}

/// Maps a candle error into an [`InferenceError::Compute`].
fn compute(error: &candle_core::Error) -> InferenceError {
    InferenceError::Compute(error.to_string())
}

/// One causal multi-head self-attention + MLP transformer block.
struct Block {
    ln1: LayerNorm,
    query: Linear,
    key: Linear,
    value: Linear,
    proj: Linear,
    ln2: LayerNorm,
    fc: Linear,
    fc_proj: Linear,
    n_head: usize,
    head_dim: usize,
}

impl Block {
    fn new(vb: &VarBuilder, config: ModelConfig) -> Result<Self, candle_core::Error> {
        let c = config.n_embd;
        Ok(Self {
            ln1: layer_norm(c, 1e-5, vb.pp("ln1"))?,
            query: linear_no_bias(c, c, vb.pp("q"))?,
            key: linear_no_bias(c, c, vb.pp("k"))?,
            value: linear_no_bias(c, c, vb.pp("v"))?,
            proj: linear_no_bias(c, c, vb.pp("proj"))?,
            ln2: layer_norm(c, 1e-5, vb.pp("ln2"))?,
            fc: linear_no_bias(c, 4 * c, vb.pp("fc"))?,
            fc_proj: linear_no_bias(4 * c, c, vb.pp("fc_proj"))?,
            n_head: config.n_head,
            head_dim: config.head_dim(),
        })
    }

    /// `input`: `[T, C]` -> `[T, C]`. `mask`: additive causal mask `[T, T]`.
    fn forward(&self, input: &Tensor, mask: &Tensor) -> Result<Tensor, candle_core::Error> {
        let (seq_len, _channels) = input.dims2()?;
        let normed = self.ln1.forward(input)?;
        // Project to query/key/value and split into heads: [T, C] -> [H, T, hd].
        let split = |linear: &Linear| -> Result<Tensor, candle_core::Error> {
            linear
                .forward(&normed)?
                .reshape((seq_len, self.n_head, self.head_dim))?
                .transpose(0, 1)?
                .contiguous()
        };
        let queries = split(&self.query)?;
        let keys = split(&self.key)?;
        let values = split(&self.value)?;

        // Scaled dot-product attention with the causal mask, per head.
        #[allow(clippy::cast_precision_loss)] // head_dim is small; exact as f64.
        let scale = 1.0 / (self.head_dim as f64).sqrt();
        let scores = (queries.matmul(&keys.transpose(1, 2)?)? * scale)?;
        let scores = scores.broadcast_add(mask)?;
        let weights = softmax(&scores, 2)?;
        let attended = weights
            .matmul(&values)? // [H, T, head_dim]
            .transpose(0, 1)?
            .contiguous()?
            .reshape((seq_len, self.n_head * self.head_dim))?;
        let residual = (input + self.proj.forward(&attended)?)?;

        // Position-wise MLP with a GELU nonlinearity.
        let hidden = self.fc.forward(&self.ln2.forward(&residual)?)?.gelu()?;
        residual + self.fc_proj.forward(&hidden)?
    }
}

/// A small byte-level GPT and its runtime state.
pub struct CandleTextModel {
    token_embedding: Embedding,
    position_embedding: Embedding,
    blocks: Vec<Block>,
    ln_final: LayerNorm,
    lm_head: Linear,
    config: ModelConfig,
    device: Device,
}

impl CandleTextModel {
    /// Builds the model from a [`VarBuilder`] over already-loaded weights.
    fn from_var_builder(vb: &VarBuilder, config: ModelConfig) -> Result<Self, InferenceError> {
        if !config.is_valid() {
            return Err(InferenceError::InvalidConfig(format!(
                "{config:?} (n_embd must be a non-zero multiple of n_head)"
            )));
        }
        let build = || -> Result<Self, candle_core::Error> {
            let token_embedding = embedding(VOCAB_SIZE, config.n_embd, vb.pp("wte"))?;
            let position_embedding = embedding(config.block_size, config.n_embd, vb.pp("wpe"))?;
            let mut blocks = Vec::with_capacity(config.n_layer);
            for layer in 0..config.n_layer {
                blocks.push(Block::new(&vb.pp(format!("block{layer}")), config)?);
            }
            let ln_final = layer_norm(config.n_embd, 1e-5, vb.pp("ln_f"))?;
            let lm_head = linear_no_bias(config.n_embd, VOCAB_SIZE, vb.pp("lm_head"))?;
            Ok(Self {
                token_embedding,
                position_embedding,
                blocks,
                ln_final,
                lm_head,
                config,
                device: vb.device().clone(),
            })
        };
        build().map_err(|error| compute(&error))
    }

    /// Loads a model from an operator-supplied safetensors file.
    ///
    /// The file must hold the named parameters this architecture expects for
    /// `config` (as produced by a matching trainer). Tokenization is byte-level
    /// and built in, so no tokenizer file is needed.
    ///
    /// # Errors
    ///
    /// Returns [`InferenceError::Load`] if the file is missing or its tensors
    /// don't match `config`, or [`InferenceError::InvalidConfig`] if `config`
    /// is not self-consistent.
    pub fn load(weights: &Path, config: ModelConfig) -> Result<Self, InferenceError> {
        if !config.is_valid() {
            return Err(InferenceError::InvalidConfig(format!("{config:?}")));
        }
        let device = Device::Cpu;
        // Safety: from_mmaped_safetensors maps the file read-only; the mapping
        // lives for the duration of the load and the tensors are copied into
        // the model, so no external mutation can invalidate them here.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights], DType::F32, &device)
                .map_err(|error| InferenceError::Load(error.to_string()))?
        };
        Self::from_var_builder(&vb, config)
    }

    /// Builds a model with in-process random weights — for tests and for
    /// exercising the inference plumbing without any weights file. Weights are
    /// candle's default initialization; a given instance is fixed, so greedy
    /// decoding on it is deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`InferenceError::InvalidConfig`] if `config` is not
    /// self-consistent, or [`InferenceError::Compute`] if initialization fails.
    pub fn random(config: ModelConfig) -> Result<Self, InferenceError> {
        let device = Device::Cpu;
        let var_map = VarMap::new();
        let vb = VarBuilder::from_varmap(&var_map, DType::F32, &device);
        Self::from_var_builder(&vb, config)
    }

    /// The model's configuration.
    #[must_use]
    pub const fn config(&self) -> ModelConfig {
        self.config
    }

    /// Runs the forward pass over a byte-id context, returning per-position
    /// logits as `[T, VOCAB_SIZE]`.
    fn logits(&self, context: &[u32]) -> Result<Vec<Vec<f32>>, InferenceError> {
        let forward = || -> Result<Vec<Vec<f32>>, candle_core::Error> {
            let seq_len = context.len();
            let idx = Tensor::from_vec(context.to_vec(), (seq_len,), &self.device)?;
            // A checked conversion: fail loudly rather than inject a sentinel
            // index if the context somehow exceeds u32 (block_size is bounded
            // by MAX_BLOCK_SIZE, so this is unreachable in practice).
            let positions: Vec<u32> = (0..seq_len)
                .map(u32::try_from)
                .collect::<Result<_, _>>()
                .map_err(|_| candle_core::Error::Msg("context length exceeds u32".to_string()))?;
            let pos = Tensor::from_vec(positions, (seq_len,), &self.device)?;

            let mut hidden =
                (self.token_embedding.forward(&idx)? + self.position_embedding.forward(&pos)?)?;
            let mask = causal_mask(seq_len, &self.device)?;
            for block in &self.blocks {
                hidden = block.forward(&hidden, &mask)?;
            }
            let normed = self.ln_final.forward(&hidden)?;
            self.lm_head.forward(&normed)?.to_vec2::<f32>()
        };
        forward().map_err(|error| compute(&error))
    }

    /// Encodes text as byte ids, truncated to the model's context window from
    /// the right (the most recent `block_size` bytes).
    fn context_ids(&self, text: &str) -> Vec<u32> {
        let bytes = text.as_bytes();
        let start = bytes.len().saturating_sub(self.config.block_size);
        bytes[start..].iter().map(|&b| u32::from(b)).collect()
    }
}

impl LanguageModel for CandleTextModel {
    fn generate(&self, prompt: &str, max_tokens: usize) -> String {
        let mut ids = self.context_ids(prompt);
        if ids.is_empty() {
            ids.push(u32::from(b' '));
        }
        let mut produced: Vec<u8> = Vec::with_capacity(max_tokens);
        for _ in 0..max_tokens {
            let window_start = ids.len().saturating_sub(self.config.block_size);
            let context = &ids[window_start..];
            let Ok(logits) = self.logits(context) else {
                break;
            };
            let Some(last) = logits.last() else { break };
            // The logits row is vocab-sized (256), so the argmax index is a byte.
            let byte = u8::try_from(argmax(last)).unwrap_or(0);
            produced.push(byte);
            ids.push(u32::from(byte));
        }
        String::from_utf8_lossy(&produced).into_owned()
    }

    fn perplexity(&self, text: &str) -> f32 {
        let ids = self.context_ids(text);
        if ids.len() < 2 {
            return f32::INFINITY;
        }
        let Ok(logits) = self.logits(&ids) else {
            return f32::INFINITY;
        };
        let mut total = 0.0_f64;
        let mut counted = 0u32;
        for position in 0..ids.len() - 1 {
            let target = ids[position + 1] as usize;
            let row = &logits[position];
            total += -f64::from(log_softmax_at(row, target));
            counted += 1;
        }
        if counted == 0 {
            return f32::INFINITY;
        }
        #[allow(clippy::cast_possible_truncation)]
        let mean = (total / f64::from(counted)) as f32;
        mean.exp()
    }
}

/// An additive causal mask `[T, T]`: `0` where a query may attend to a key
/// (`key <= query`), `-inf` above the diagonal.
fn causal_mask(t: usize, device: &Device) -> Result<Tensor, candle_core::Error> {
    let mut data = vec![0.0_f32; t * t];
    for (query, row) in data.chunks_mut(t).enumerate() {
        for (key, cell) in row.iter_mut().enumerate() {
            if key > query {
                *cell = f32::NEG_INFINITY;
            }
        }
    }
    Tensor::from_vec(data, (t, t), device)
}

/// The index of the maximum value in `row` (the greedy next token).
fn argmax(row: &[f32]) -> usize {
    let mut best = 0;
    let mut best_value = f32::NEG_INFINITY;
    for (index, &value) in row.iter().enumerate() {
        if value > best_value {
            best_value = value;
            best = index;
        }
    }
    best
}

/// The log-softmax of `logits` evaluated at `target`, computed stably.
fn log_softmax_at(logits: &[f32], target: usize) -> f32 {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let sum_exp: f64 = logits.iter().map(|&v| f64::from(v - max).exp()).sum();
    #[allow(clippy::cast_possible_truncation)]
    let result = (f64::from(logits[target] - max) - sum_exp.ln()) as f32;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> ModelConfig {
        ModelConfig {
            n_embd: 16,
            n_head: 2,
            n_layer: 2,
            block_size: 32,
        }
    }

    #[test]
    fn config_validity_is_checked() {
        assert!(tiny().is_valid());
        // n_head does not divide n_embd.
        assert!(
            !ModelConfig {
                n_embd: 10,
                n_head: 3,
                n_layer: 1,
                block_size: 8,
            }
            .is_valid()
        );
        assert!(
            !ModelConfig {
                n_embd: 0,
                n_head: 1,
                n_layer: 1,
                block_size: 8,
            }
            .is_valid()
        );
    }

    #[test]
    fn random_model_builds_and_reports_its_config() {
        let model = CandleTextModel::random(tiny()).expect("build");
        assert_eq!(model.config(), tiny());
    }

    #[test]
    fn invalid_config_is_rejected() {
        let bad = ModelConfig {
            n_embd: 10,
            n_head: 4,
            n_layer: 1,
            block_size: 8,
        };
        assert!(matches!(
            CandleTextModel::random(bad),
            Err(InferenceError::InvalidConfig(_))
        ));
    }

    #[test]
    fn oversized_configs_are_rejected() {
        // Beyond-bounds fields are refused so internal size math can't overflow
        // (Copilot review, PR #63).
        for bad in [
            ModelConfig {
                n_embd: MAX_N_EMBD + 8,
                n_head: 1,
                n_layer: 1,
                block_size: 8,
            },
            ModelConfig {
                n_embd: 16,
                n_head: 2,
                n_layer: MAX_N_LAYER + 1,
                block_size: 8,
            },
            ModelConfig {
                n_embd: 16,
                n_head: 2,
                n_layer: 1,
                block_size: MAX_BLOCK_SIZE + 1,
            },
        ] {
            assert!(!bad.is_valid(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn generate_produces_output_and_is_deterministic() {
        let model = CandleTextModel::random(tiny()).expect("build");
        let a = model.generate("hello world", 12);
        let b = model.generate("hello world", 12);
        // The forward path ran end-to-end and produced a continuation, and
        // greedy decoding is deterministic for a fixed model. (Byte length is
        // not asserted: high bytes become multi-byte replacement chars under
        // lossy UTF-8, so the string length can exceed the token count.)
        assert!(!a.is_empty(), "expected a non-empty continuation");
        assert_eq!(a, b, "greedy decoding must be deterministic");
    }

    #[test]
    fn perplexity_is_finite_and_positive() {
        let model = CandleTextModel::random(tiny()).expect("build");
        let ppl = model.perplexity("a security engagement report");
        assert!(ppl.is_finite() && ppl > 0.0, "perplexity was {ppl}");
    }

    #[test]
    fn perplexity_of_too_short_text_is_infinite() {
        let model = CandleTextModel::random(tiny()).expect("build");
        assert!(model.perplexity("a").is_infinite());
    }

    #[test]
    fn load_reports_a_clean_error_for_a_missing_file() {
        let missing = std::env::temp_dir().join("security-agent-no-such-model.safetensors");
        let _ = std::fs::remove_file(&missing);
        let result = CandleTextModel::load(&missing, tiny());
        assert!(matches!(result, Err(InferenceError::Load(_))));
    }

    #[test]
    fn config_parses_from_json() {
        let parsed =
            ModelConfig::from_json(r#"{"n_embd":16,"n_head":2,"n_layer":2,"block_size":32}"#)
                .expect("valid config");
        assert_eq!(parsed, tiny());
    }

    #[test]
    fn config_json_rejects_missing_and_invalid() {
        assert!(matches!(
            ModelConfig::from_json(r#"{"n_embd":16,"n_head":2}"#),
            Err(InferenceError::Load(_))
        ));
        assert!(matches!(
            ModelConfig::from_json("not json"),
            Err(InferenceError::Load(_))
        ));
        // n_head does not divide n_embd -> invalid.
        assert!(matches!(
            ModelConfig::from_json(r#"{"n_embd":10,"n_head":3,"n_layer":1,"block_size":8}"#),
            Err(InferenceError::InvalidConfig(_))
        ));
    }

    #[test]
    fn generate_handles_an_empty_prompt() {
        let model = CandleTextModel::random(tiny()).expect("build");
        // Must not panic on an empty prompt (a space seed is used) and still
        // produce a continuation.
        let out = model.generate("", 4);
        assert!(!out.is_empty());
    }
}
