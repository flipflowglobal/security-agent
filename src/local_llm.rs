//! Fully-local, offline LLM backend (`--features inference`).
//!
//! This is the "own LLM" backend: a real, pretrained Llama-style
//! transformer (`GQA` attention, `RoPE`, `SwiGLU`, `RMSNorm`) run through
//! candle on the CPU, compiled into the binary. The model weights, byte-level
//! BPE tokenizer, and config ship as resources next to the executable (or in
//! the app package) — nothing is fetched at runtime, no service is contacted,
//! and inference never leaves the machine.
//!
//! It implements [`crate::language_model::LanguageModel`], so it drops into
//! the same call sites as the bundled tiny model (`--llm-generate`,
//! `--llm-perplexity`, the GUI LLM tab). It is deliberately gated behind the
//! same `inference` feature as [`crate::inference::CandleTextModel`]; the
//! default build stays zero-dependency.
//!
//! The tokenizer is a GPT2-style byte-level BPE read straight from a
//! `tokenizer.json` (vocab + merges + special tokens), so no external
//! tokenizer crate or runtime file format library is needed — the in-house
//! [`crate::json`] parser walks the file.
//!
//! The model is a `HuggingFace` Llama checkpoint layout (`model.embed_tokens`,
//! `model.layers.{i}.self_attn.{q,k,v,o}_proj`, `model.layers.{i}.mlp.{gate,
//! up,down}_proj`, `model.layers.{i}.*_layernorm`, `model.norm`) with tied
//! input/output embeddings. Weights are loaded from `model.safetensors` via
//! candle and converted to `f32` for CPU inference; generation keeps a KV
//! cache so each decoded token costs a constant-size forward pass rather than
//! re-reading the whole context.

use crate::language_model::LanguageModel;
use candle_core::{DType, Device, Tensor};
use candle_nn::ops::{silu, softmax};
use candle_nn::{
    Embedding, Linear, Module, RmsNorm, VarBuilder, embedding, linear_no_bias, rms_norm,
};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Errors from building or running the local LLM.
#[derive(Debug)]
pub enum LocalModelError {
    /// A resource file could not be read, or a weight/tokenizer file did not
    /// match what the architecture expects.
    Load(String),
    /// A tensor operation failed during the forward pass.
    Compute(String),
}

impl fmt::Display for LocalModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(message) => write!(formatter, "failed to load local model: {message}"),
            Self::Compute(message) => write!(formatter, "local model inference failed: {message}"),
        }
    }
}

impl std::error::Error for LocalModelError {}

/// Maps a candle error into [`LocalModelError::Compute`].
// The error is consumed by value because `Result::map_err` hands it over as
// `FnOnce(E)`; a reference would force a closure at every call site.
#[allow(clippy::needless_pass_by_value)]
fn compute(error: candle_core::Error) -> LocalModelError {
    LocalModelError::Compute(error.to_string())
}

/// The architectural shape of a [`LocalTextModel`], read from a `HuggingFace`
/// Llama-style `config.json`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LocalConfig {
    /// Hidden/embedding width.
    pub hidden_size: usize,
    /// MLP expansion width.
    pub intermediate_size: usize,
    /// Number of transformer blocks.
    pub num_hidden_layers: usize,
    /// Number of query attention heads.
    pub num_attention_heads: usize,
    /// Number of key/value attention heads (grouped-query attention).
    pub num_key_value_heads: usize,
    /// Maximum context length the model was trained for.
    pub max_position_embeddings: usize,
    /// Vocabulary size (input and, when tied, output).
    pub vocab_size: usize,
    /// Beginning-of-sequence token id (the chat opener in SmolLM-style
    /// tokenizers).
    pub bos_token_id: u32,
    /// End-of-sequence token id (stops generation).
    pub eos_token_id: u32,
    /// `RMSNorm` epsilon.
    pub rms_norm_eps: f32,
    /// `RoPE` base frequency.
    pub rope_theta: f32,
    /// Whether the output head shares the input embedding matrix.
    pub tie_word_embeddings: bool,
}

impl LocalConfig {
    /// Reads an integer field from a parsed config object.
    fn field_u64(value: &crate::json::JsonValue, name: &str) -> Result<usize, LocalModelError> {
        value
            .get(name)
            .and_then(crate::json::JsonValue::as_u64)
            .and_then(|number| usize::try_from(number).ok())
            .ok_or_else(|| {
                LocalModelError::Load(format!("config.json missing integer field '{name}'"))
            })
    }

    /// Reads an optional float field (with `default` when absent).
    fn field_f64(value: &crate::json::JsonValue, name: &str, default: f32) -> f32 {
        match value.get(name) {
            Some(crate::json::JsonValue::Number(number)) => {
                #[allow(clippy::cast_possible_truncation)]
                {
                    *number as f32
                }
            }
            _ => default,
        }
    }

    /// Parses a Llama-style config from `config.json` text.
    ///
    /// # Errors
    ///
    /// Returns [`LocalModelError::Load`] if the JSON is malformed or a
    /// required field is missing.
    pub fn from_json(text: &str) -> Result<Self, LocalModelError> {
        let value = crate::json::parse(text)
            .ok_or_else(|| LocalModelError::Load("config.json is not valid JSON".to_string()))?;
        let num_heads = Self::field_u64(&value, "num_attention_heads")?;
        let hidden = Self::field_u64(&value, "hidden_size")?;
        let kv_heads = value
            .get("num_key_value_heads")
            .and_then(crate::json::JsonValue::as_u64)
            .and_then(|number| usize::try_from(number).ok())
            .unwrap_or(num_heads);
        let eos = value
            .get("eos_token_id")
            .and_then(crate::json::JsonValue::as_u64)
            .and_then(|number| u32::try_from(number).ok())
            .unwrap_or(2);
        let bos = value
            .get("bos_token_id")
            .and_then(crate::json::JsonValue::as_u64)
            .and_then(|number| u32::try_from(number).ok())
            .unwrap_or(1);
        if hidden == 0 || hidden % num_heads != 0 || kv_heads == 0 || kv_heads > num_heads {
            return Err(LocalModelError::Load(format!(
                "unsupported llama-shaped config: hidden={hidden} heads={num_heads} kv={kv_heads}"
            )));
        }
        Ok(Self {
            hidden_size: hidden,
            intermediate_size: Self::field_u64(&value, "intermediate_size")?,
            num_hidden_layers: Self::field_u64(&value, "num_hidden_layers")?,
            num_attention_heads: num_heads,
            num_key_value_heads: kv_heads,
            max_position_embeddings: Self::field_u64(&value, "max_position_embeddings")?,
            vocab_size: Self::field_u64(&value, "vocab_size")?,
            bos_token_id: bos,
            eos_token_id: eos,
            rms_norm_eps: Self::field_f64(&value, "rms_norm_eps", 1e-5),
            rope_theta: Self::field_f64(&value, "rope_theta", 10_000.0),
            tie_word_embeddings: value
                .get("tie_word_embeddings")
                .and_then(crate::json::JsonValue::as_bool)
                .unwrap_or(true),
        })
    }

    /// The per-head dimension.
    #[must_use]
    pub const fn head_dim(&self) -> usize {
        self.hidden_size / self.num_attention_heads
    }
}

/// One pre-tokenization unit: a literal special token id, or a text span that
/// still needs byte-level BPE merging.
enum PreToken {
    /// A verbatim special token (e.g. `<|im_start|>`), already an id.
    Special(u32),
    /// A raw (pre-BPE) text span.
    Text(String),
}

/// The three character classes the GPT2 pre-tokenizer regex splits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharClass {
    Letter,
    Digit,
    Other,
}

/// Classifies one character the way the GPT2 byte-level pre-tokenizer does.
fn class_of(ch: char) -> CharClass {
    if ch.is_alphabetic() {
        CharClass::Letter
    } else if ch.is_numeric() {
        CharClass::Digit
    } else {
        CharClass::Other
    }
}

/// The length (in chars) of an apostrophe-contraction suffix starting at `i`,
/// mirroring the `'s|'t|'re|'ve|'m|'ll|'d` alternative of the GPT2 regex.
/// `None` when no suffix matches.
fn apostrophe_suffix_len(chars: &[char], i: usize) -> Option<usize> {
    const FORMS: [&str; 7] = ["'s", "'t", "'re", "'ve", "'m", "'ll", "'d"];
    for form in FORMS {
        let length = form.chars().count();
        if i + length <= chars.len() {
            let candidate: String = chars[i..i + length].iter().collect();
            if candidate == form {
                return Some(length);
            }
        }
    }
    None
}

/// Builds the GPT2 byte-level alphabet: a bijection between bytes and a set of
/// Unicode characters chosen to stay out of the way of the BPE vocabulary.
fn bytes_to_unicode() -> ([char; 256], HashMap<char, u8>) {
    let mut bytes = Vec::with_capacity(256);
    let mut code_points = Vec::with_capacity(256);
    for b in 0x21_u8..=0x7e {
        bytes.push(b);
        code_points.push(u32::from(b));
    }
    for b in 0xa1_u8..=0xac {
        bytes.push(b);
        code_points.push(u32::from(b));
    }
    for b in 0xae_u8..=0xff {
        bytes.push(b);
        code_points.push(u32::from(b));
    }
    let mut extra = 0_u32;
    for b in 0_u8..=255 {
        if !bytes.contains(&b) {
            bytes.push(b);
            code_points.push(256 + extra);
            extra += 1;
        }
    }
    let mut table = ['\0'; 256];
    let mut reverse = HashMap::with_capacity(256);
    for (b, code_point) in bytes.iter().zip(code_points.iter()) {
        let ch = char::from_u32(*code_point).expect("byte-level alphabet is valid Unicode");
        table[usize::from(*b)] = ch;
        reverse.insert(ch, *b);
    }
    (table, reverse)
}

/// Decodes one raw (byte-encoded) token string into its byte sequence.
fn decode_token_bytes(token: &str, char_bytes: &HashMap<char, u8>) -> Vec<u8> {
    token
        .chars()
        .filter_map(|ch| char_bytes.get(&ch).copied())
        .collect()
}

/// A GPT2-style byte-level BPE tokenizer built from a `tokenizer.json`.
#[derive(Debug, Clone)]
pub struct BpeTokenizer {
    /// Byte-decoded content per id, for `decode`.
    decoded: Vec<Vec<u8>>,
    /// Raw token string -> id.
    ids: HashMap<String, u32>,
    /// Merge rank (lower = earlier = preferred) for an adjacent id pair.
    merge_ranks: HashMap<(u32, u32), u32>,
    /// Id of the merged token for an adjacent id pair.
    merge_ids: HashMap<(u32, u32), u32>,
    /// Verbatim special tokens (longest first) -> id.
    special_ids: Vec<(String, u32)>,
    /// GPT2 byte-level alphabet: byte -> unicode char.
    byte_chars: [char; 256],
    /// Reverse alphabet: unicode char -> byte.
    char_bytes: HashMap<char, u8>,
    /// Id of each single-byte token (byte value -> token id).
    byte_char_ids: [Option<u32>; 256],
}

impl BpeTokenizer {
    /// Builds a tokenizer from `tokenizer.json` text.
    ///
    /// # Errors
    ///
    /// Returns [`LocalModelError::Load`] if the file is malformed or missing
    /// its `model.vocab` / `model.merges` sections.
    pub fn from_json(text: &str) -> Result<Self, LocalModelError> {
        let value = crate::json::parse(text)
            .ok_or_else(|| LocalModelError::Load("tokenizer.json is not valid JSON".to_string()))?;
        let model = value
            .get("model")
            .ok_or_else(|| LocalModelError::Load("tokenizer.json missing 'model'".to_string()))?;
        let vocab_value = model.get("vocab").ok_or_else(|| {
            LocalModelError::Load("tokenizer.json missing 'model.vocab'".to_string())
        })?;
        let mut token_strings: Vec<String> = Vec::new();
        let mut ids = HashMap::with_capacity(49_152);
        for (token, id_value) in vocab_value.iter_object() {
            let id = id_value
                .as_u64()
                .and_then(|number| usize::try_from(number).ok())
                .ok_or_else(|| {
                    LocalModelError::Load("tokenizer vocab id out of range".to_string())
                })?;
            if token_strings.len() <= id {
                token_strings.resize(id + 1, String::new());
            }
            token_strings[id] = token.to_string();
            ids.insert(token.to_string(), u32::try_from(id).unwrap_or(u32::MAX));
        }

        let mut merge_ranks = HashMap::with_capacity(48_900);
        let mut merge_ids = HashMap::with_capacity(48_900);
        if let Some(merges) = model
            .get("merges")
            .and_then(crate::json::JsonValue::as_array)
        {
            for (rank, merge) in merges.iter().enumerate() {
                let Some(pair) = merge.as_str() else {
                    continue;
                };
                let Some((left, right)) = pair.split_once(' ') else {
                    continue;
                };
                let (Some(&left_id), Some(&right_id)) = (ids.get(left), ids.get(right)) else {
                    continue;
                };
                let Some(&merged_id) = ids.get(&format!("{left}{right}")) else {
                    continue;
                };
                let rank = u32::try_from(rank).unwrap_or(u32::MAX);
                merge_ranks.insert((left_id, right_id), rank);
                merge_ids.insert((left_id, right_id), merged_id);
            }
        }

        let mut special_ids: Vec<(String, u32)> = Vec::new();
        if let Some(added) = value
            .get("added_tokens")
            .and_then(crate::json::JsonValue::as_array)
        {
            for entry in added {
                let special = entry
                    .get("special")
                    .and_then(crate::json::JsonValue::as_bool);
                let content = entry
                    .get("content")
                    .and_then(crate::json::JsonValue::as_str);
                let id = entry
                    .get("id")
                    .and_then(crate::json::JsonValue::as_u64)
                    .and_then(|number| u32::try_from(number).ok());
                if special == Some(true) {
                    if let (Some(content), Some(id)) = (content, id) {
                        special_ids.push((content.to_string(), id));
                    }
                }
            }
        }
        special_ids.sort_by_key(|(content, _)| std::cmp::Reverse(content.len()));

        let (byte_chars, char_bytes) = bytes_to_unicode();
        let decoded = token_strings
            .iter()
            .map(|token| decode_token_bytes(token, &char_bytes))
            .collect();

        let mut byte_char_ids = [None; 256];
        for (byte, ch) in byte_chars.iter().enumerate() {
            byte_char_ids[byte] = ids.get(&ch.to_string()).copied();
        }

        Ok(Self {
            decoded,
            ids,
            merge_ranks,
            merge_ids,
            special_ids,
            byte_chars,
            char_bytes,
            byte_char_ids,
        })
    }

    /// The id of a single byte-character, or `None` if the alphabet did not
    /// map it to a vocab token.
    fn byte_char_id(&self, ch: char) -> Option<u32> {
        self.char_bytes
            .get(&ch)
            .and_then(|byte| self.byte_char_ids[usize::from(*byte)])
    }

    /// Whether `content` is a verbatim special token; returns its id.
    fn special_id(&self, content: &str) -> Option<u32> {
        self.special_ids
            .iter()
            .find_map(|(special, id)| (special == content).then_some(*id))
    }

    /// Splits `text` into pre-token units the way the GPT2 byte-level regex
    /// does: verbatim special tokens, apostrophe contractions, space-prefixed
    /// word/number/punctuation runs, and whitespace runs.
    fn pre_tokenize(&self, text: &str) -> Vec<PreToken> {
        let chars: Vec<char> = text.chars().collect();
        let n = chars.len();
        let mut tokens = Vec::new();
        let mut i = 0;
        while i < n {
            if let Some((length, id)) = self.match_special(&chars, i) {
                tokens.push(PreToken::Special(id));
                i += length;
                continue;
            }
            let ch = chars[i];
            if ch.is_whitespace() {
                let mut run_end = i;
                while run_end < n && chars[run_end].is_whitespace() {
                    run_end += 1;
                }
                if run_end < n {
                    // The run is followed by a non-space char. The GPT2 regex
                    // `\s+(?!\S)` consumes all but the last whitespace char,
                    // then ` ?\p{L}+` etc. join a trailing literal space to
                    // the following run; a trailing newline/tab stands alone.
                    if chars[run_end - 1] == ' ' {
                        if run_end - i > 1 {
                            tokens.push(PreToken::Text(chars[i..run_end - 1].iter().collect()));
                        }
                        let cls = class_of(chars[run_end]);
                        let mut j = run_end;
                        while j < n && class_of(chars[j]) == cls {
                            j += 1;
                        }
                        tokens.push(PreToken::Text(chars[run_end - 1..j].iter().collect()));
                        i = j;
                        continue;
                    }
                    if run_end - i > 1 {
                        tokens.push(PreToken::Text(chars[i..run_end - 1].iter().collect()));
                    }
                    tokens.push(PreToken::Text(chars[run_end - 1..run_end].iter().collect()));
                    i = run_end;
                    continue;
                }
                // Trailing whitespace: `\s+(?!\S)` matches the whole run at
                // end-of-text.
                tokens.push(PreToken::Text(chars[i..run_end].iter().collect()));
                i = run_end;
                continue;
            }
            if ch == '\'' {
                if let Some(length) = apostrophe_suffix_len(&chars, i) {
                    tokens.push(PreToken::Text(chars[i..i + length].iter().collect()));
                    i += length;
                    continue;
                }
            }
            let cls = class_of(ch);
            let mut j = i;
            while j < n && class_of(chars[j]) == cls {
                j += 1;
            }
            tokens.push(PreToken::Text(chars[i..j].iter().collect()));
            i = j;
        }
        tokens
    }

    /// Matches a verbatim special token starting at `i`, returning its char
    /// length and id.
    fn match_special(&self, chars: &[char], i: usize) -> Option<(usize, u32)> {
        for (content, id) in &self.special_ids {
            let length = content.chars().count();
            if i + length <= chars.len() {
                let candidate: String = chars[i..i + length].iter().collect();
                if candidate == *content {
                    return Some((length, *id));
                }
            }
        }
        None
    }

    /// Byte-encodes a pre-token text span (each UTF-8 byte becomes one
    /// byte-alphabet character, so a leading space becomes `Ġ`).
    fn byte_encode(&self, span: &str) -> String {
        let mut encoded = String::with_capacity(span.len());
        for ch in span.chars() {
            let mut buffer = [0_u8; 4];
            for &byte in ch.encode_utf8(&mut buffer).as_bytes() {
                encoded.push(self.byte_chars[usize::from(byte)]);
            }
        }
        encoded
    }

    /// Applies byte-level BPE merges to one byte-encoded token, returning its
    /// id sequence (a whole-token id when the vocabulary knows the token, or
    /// a merge decomposition otherwise).
    fn bpe(&self, token: &str) -> Vec<u32> {
        if let Some(&id) = self.ids.get(token) {
            return vec![id];
        }
        let mut ids: Vec<u32> = token
            .chars()
            .filter_map(|ch| self.byte_char_id(ch))
            .collect();
        while ids.len() > 1 {
            let mut best: Option<(usize, u32)> = None;
            for k in 0..ids.len() - 1 {
                if let Some(&rank) = self.merge_ranks.get(&(ids[k], ids[k + 1])) {
                    if best.is_none_or(|(_, best_rank)| rank < best_rank) {
                        best = Some((k, rank));
                    }
                }
            }
            let Some((k, _)) = best else {
                break;
            };
            let merged = self.merge_ids[&(ids[k], ids[k + 1])];
            ids[k] = merged;
            ids.remove(k + 1);
        }
        ids
    }

    /// Encodes `text` into token ids (special tokens verbatim, everything
    /// else through byte-level BPE).
    #[must_use]
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let mut out = Vec::new();
        for pre in self.pre_tokenize(text) {
            match pre {
                PreToken::Special(id) => out.push(id),
                PreToken::Text(span) => {
                    let encoded = self.byte_encode(&span);
                    out.extend(self.bpe(&encoded));
                }
            }
        }
        out
    }

    /// Decodes token ids back into text (lossy UTF-8).
    #[must_use]
    pub fn decode(&self, ids: &[u32]) -> String {
        let mut bytes = Vec::with_capacity(ids.len() * 2);
        for &id in ids {
            if let Some(decoded) = self.decoded.get(usize::try_from(id).unwrap_or(usize::MAX)) {
                bytes.extend_from_slice(decoded);
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// The id of a special token by literal content (used by tests).
    #[must_use]
    pub fn special_token_id(&self, content: &str) -> Option<u32> {
        self.special_id(content)
    }
}

/// Cached key/value tensors per layer, so generation only re-runs the newest
/// token instead of the whole context.
struct KvCache {
    layers: Vec<(Tensor, Tensor)>,
}

impl KvCache {
    const fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// The number of positions already cached (0 before the first call).
    fn prev_len(&self) -> usize {
        self.layers
            .first()
            .map_or(0, |(k, _)| k.dim(0).unwrap_or(0))
    }
}

/// One transformer block.
struct LlamaLayer {
    input_layernorm: RmsNorm,
    q_proj: Linear,
    k_proj: Linear,
    v_proj: Linear,
    o_proj: Linear,
    post_attention_layernorm: RmsNorm,
    gate_proj: Linear,
    up_proj: Linear,
    down_proj: Linear,
    n_head: usize,
    n_kv_head: usize,
    head_dim: usize,
}

/// The full transformer.
struct LlamaModel {
    embed: Embedding,
    layers: Vec<LlamaLayer>,
    norm: RmsNorm,
    lm_head: Linear,
    config: LocalConfig,
    device: Device,
    /// Precomputed `RoPE` inverse frequencies (one per head pair).
    rope_freqs: Vec<f32>,
}

impl LlamaModel {
    /// Builds the model from a `VarBuilder` over the safetensors weights.
    fn load(vb: &VarBuilder, config: &LocalConfig) -> Result<Self, LocalModelError> {
        let device = vb.device().clone();
        let hidden = config.hidden_size;
        let head_dim = hidden / config.num_attention_heads;
        let kv_hidden = head_dim * config.num_key_value_heads;
        let embed =
            embedding(config.vocab_size, hidden, vb.pp("model.embed_tokens")).map_err(compute)?;
        let mut layers = Vec::with_capacity(config.num_hidden_layers);
        for layer_index in 0..config.num_hidden_layers {
            let prefix = vb.pp(format!("model.layers.{layer_index}"));
            let attn = prefix.pp("self_attn");
            let mlp = prefix.pp("mlp");
            let eps = f64::from(config.rms_norm_eps);
            layers.push(LlamaLayer {
                input_layernorm: rms_norm(hidden, eps, prefix.pp("input_layernorm"))
                    .map_err(compute)?,
                q_proj: linear_no_bias(hidden, hidden, attn.pp("q_proj")).map_err(compute)?,
                k_proj: linear_no_bias(hidden, kv_hidden, attn.pp("k_proj")).map_err(compute)?,
                v_proj: linear_no_bias(hidden, kv_hidden, attn.pp("v_proj")).map_err(compute)?,
                o_proj: linear_no_bias(hidden, hidden, attn.pp("o_proj")).map_err(compute)?,
                post_attention_layernorm: rms_norm(
                    hidden,
                    eps,
                    prefix.pp("post_attention_layernorm"),
                )
                .map_err(compute)?,
                gate_proj: linear_no_bias(hidden, config.intermediate_size, mlp.pp("gate_proj"))
                    .map_err(compute)?,
                up_proj: linear_no_bias(hidden, config.intermediate_size, mlp.pp("up_proj"))
                    .map_err(compute)?,
                down_proj: linear_no_bias(config.intermediate_size, hidden, mlp.pp("down_proj"))
                    .map_err(compute)?,
                n_head: config.num_attention_heads,
                n_kv_head: config.num_key_value_heads,
                head_dim,
            });
        }
        let norm = rms_norm(hidden, f64::from(config.rms_norm_eps), vb.pp("model.norm"))
            .map_err(compute)?;
        let lm_head = if config.tie_word_embeddings {
            Linear::new(embed.embeddings().clone(), None)
        } else {
            linear_no_bias(hidden, config.vocab_size, vb.pp("lm_head")).map_err(compute)?
        };
        let rope_freqs = (0..head_dim / 2)
            .map(|pair| {
                #[allow(clippy::cast_precision_loss)] // pair/head_dim are tiny; exact as f32.
                let exponent = 2.0 * pair as f32 / head_dim as f32;
                1.0 / config.rope_theta.powf(exponent)
            })
            .collect();
        Ok(Self {
            embed,
            layers,
            norm,
            lm_head,
            config: *config,
            device,
            rope_freqs,
        })
    }

    /// `RoPE` cos/sin tables for `t` positions starting at absolute position
    /// `prev` (each an entry per head pair).
    #[allow(clippy::cast_precision_loss)] // positions are small; exact as f32.
    fn rope_angles(&self, prev: usize, t: usize) -> (Vec<f32>, Vec<f32>) {
        let half = self.rope_freqs.len();
        let mut cos = vec![0.0_f32; t * half];
        let mut sin = vec![0.0_f32; t * half];
        for local in 0..t {
            let position = (prev + local) as f32;
            for pair in 0..half {
                let angle = position * self.rope_freqs[pair];
                cos[local * half + pair] = angle.cos();
                sin[local * half + pair] = angle.sin();
            }
        }
        (cos, sin)
    }

    /// Applies rotary position embeddings to a `[t, heads, hd]` tensor in
    /// scalar space (simple, exact for small dimensions), rotating each
    /// consecutive (2i, 2i+1) pair.
    //
    // The rotation formulas use two plain multiplies per pair, not `mul_add`,
    // so repeated evaluations are bit-for-bit reproducible across builds.
    #[allow(clippy::suboptimal_flops)]
    fn rope(
        &self,
        tensor: &Tensor,
        t: usize,
        heads: usize,
        cos: &[f32],
        sin: &[f32],
    ) -> Result<Tensor, LocalModelError> {
        let head_dim = self.config.head_dim();
        let values = tensor
            .contiguous()
            .map_err(compute)?
            .reshape((t, heads, head_dim))
            .map_err(compute)?
            .to_vec3::<f32>()
            .map_err(compute)?;
        let mut data = Vec::with_capacity(t * heads * head_dim);
        for row in &values {
            for head in row {
                data.extend_from_slice(head);
            }
        }
        let half = head_dim / 2;
        for local in 0..t {
            for head in 0..heads {
                let base = (local * heads + head) * head_dim;
                for pair in 0..half {
                    let c = cos[local * half + pair];
                    let s = sin[local * half + pair];
                    let i0 = base + 2 * pair;
                    let i1 = base + 2 * pair + 1;
                    let x0 = data[i0];
                    let x1 = data[i1];
                    data[i0] = x0 * c - x1 * s;
                    data[i1] = x0 * s + x1 * c;
                }
            }
        }
        Tensor::from_vec(data, (t, heads, head_dim), &self.device).map_err(compute)
    }

    /// Scaled dot-product attention with grouped-query KV expansion and a
    /// causal mask. `q` is the new `[t, n_head, hd]`; `k_all`/`v_all` cover
    /// all `p = prev + t` positions.
    fn attention(
        &self,
        layer: &LlamaLayer,
        q: &Tensor,
        k_all: &Tensor,
        v_all: &Tensor,
        t: usize,
        prev: usize,
    ) -> Result<Tensor, LocalModelError> {
        let p = prev + t;
        let n_head = layer.n_head;
        let n_kv = layer.n_kv_head;
        let head_dim = layer.head_dim;
        let groups = n_head / n_kv;
        let expand_kv = |kv: &Tensor| -> Result<Tensor, candle_core::Error> {
            kv.reshape((p, n_kv, 1, head_dim))?
                .broadcast_as((p, n_kv, groups, head_dim))?
                .contiguous()?
                .reshape((p, n_head, head_dim))?
                .transpose(0, 1)
        };
        let q_t = q.transpose(0, 1).map_err(compute)?; // [n_head, t, hd]
        let k_t = expand_kv(k_all).map_err(compute)?; // [n_head, p, hd]
        let v_t = expand_kv(v_all).map_err(compute)?;
        #[allow(clippy::cast_precision_loss)] // head_dim is small; exact as f64.
        let scale = 1.0 / (head_dim as f64).sqrt();
        let scores = (q_t
            .matmul(&k_t.transpose(1, 2).map_err(compute)?)
            .map_err(compute)?
            * scale)
            .map_err(compute)?;
        let mask = causal_mask(t, prev, &self.device).map_err(compute)?;
        let scores = scores.broadcast_add(&mask).map_err(compute)?;
        let weights = softmax(&scores, 2).map_err(compute)?;
        let attended = weights
            .matmul(&v_t)
            .map_err(compute)?
            .transpose(0, 1)
            .map_err(compute)?
            .contiguous()
            .map_err(compute)?
            .reshape((t, n_head * head_dim))
            .map_err(compute)?;
        Ok(attended)
    }

    /// Runs the forward pass over `ids` (a fresh batch of `t` tokens starting
    /// at cached position `prev`), returning per-position logits `[t, V]`.
    /// The `prev`-position rows come from the KV cache, so generation can
    /// decode one token at a time.
    fn forward_logits(
        &self,
        ids: &[u32],
        cache: &mut KvCache,
    ) -> Result<Vec<Vec<f32>>, LocalModelError> {
        let seq_len = ids.len();
        let prev = cache.prev_len();
        let device = &self.device;
        let idx = Tensor::from_vec(ids.to_vec(), (seq_len,), device).map_err(compute)?;
        let mut hidden = self.embed.forward(&idx).map_err(compute)?;
        let (cos, sin) = self.rope_angles(prev, seq_len);
        for (layer_index, layer) in self.layers.iter().enumerate() {
            let normed = layer.input_layernorm.forward(&hidden).map_err(compute)?;
            let query = layer.q_proj.forward(&normed).map_err(compute)?;
            let key = layer.k_proj.forward(&normed).map_err(compute)?;
            let value = layer.v_proj.forward(&normed).map_err(compute)?;
            let query = self.rope(&query, seq_len, layer.n_head, &cos, &sin)?;
            let key = self.rope(&key, seq_len, layer.n_kv_head, &cos, &sin)?;
            let (key_all, value_all) = if layer_index < cache.layers.len() {
                let (key_cached, value_cached) = &cache.layers[layer_index];
                let key_all = Tensor::cat(&[key_cached.clone(), key], 0).map_err(compute)?;
                let value_all = Tensor::cat(&[value_cached.clone(), value], 0).map_err(compute)?;
                cache.layers[layer_index] = (key_all.clone(), value_all.clone());
                (key_all, value_all)
            } else {
                cache.layers.push((key.clone(), value.clone()));
                (key, value)
            };
            let attended = self.attention(layer, &query, &key_all, &value_all, seq_len, prev)?;
            hidden =
                (hidden + layer.o_proj.forward(&attended).map_err(compute)?).map_err(compute)?;
            let normed = layer
                .post_attention_layernorm
                .forward(&hidden)
                .map_err(compute)?;
            let gate = layer.gate_proj.forward(&normed).map_err(compute)?;
            let up = layer.up_proj.forward(&normed).map_err(compute)?;
            let activated = (silu(&gate).map_err(compute)? * up).map_err(compute)?;
            hidden = (hidden + layer.down_proj.forward(&activated).map_err(compute)?)
                .map_err(compute)?;
        }
        let normed = self.norm.forward(&hidden).map_err(compute)?;
        let logits = self.lm_head.forward(&normed).map_err(compute)?;
        logits.to_vec2::<f32>().map_err(compute)
    }
}

/// An additive causal mask `[t, p]` (p = prev + t): `0` where query position
/// `prev + i` may attend to key position `j`, `-inf` above the diagonal.
fn causal_mask(t: usize, prev: usize, device: &Device) -> Result<Tensor, candle_core::Error> {
    let p = prev + t;
    let mut data = vec![0.0_f32; t * p];
    for i in 0..t {
        for j in 0..p {
            if (prev + i) < j {
                data[i * p + j] = f32::NEG_INFINITY;
            }
        }
    }
    Tensor::from_vec(data, (t, p), device)
}

/// A deterministic `SplitMix64` RNG used to seed sampling from the prompt, so
/// the same prompt always produces the same continuation.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform sample in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        const TWO_POW_53: f64 = 9_007_199_254_740_992.0;
        let bits = self.next_u64() >> 11;
        #[allow(clippy::cast_precision_loss)]
        let value = bits as f64 / TWO_POW_53;
        value
    }
}

/// Deterministic prompt hash used to seed generation (FNV-1a, mirroring the
/// bundled model's behavior).
fn hash_prompt(prompt: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in prompt.as_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

/// Samples one token id from `logits` with temperature and top-k filtering.
#[allow(clippy::cast_possible_truncation)] // probabilities are stored as f32 by design.
fn sample_token(logits: &[f32], rng: &mut SplitMix64) -> Option<u32> {
    const TEMPERATURE: f32 = 0.01;
    const TOP_K: usize = 1;
    let scaled: Vec<f32> = logits.iter().map(|&value| value / TEMPERATURE).collect();
    let mut order: Vec<usize> = (0..scaled.len()).collect();
    order.sort_unstable_by(|&a, &b| {
        scaled[b]
            .partial_cmp(&scaled[a])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let k = TOP_K.min(scaled.len());
    let mut max = f32::NEG_INFINITY;
    for &index in order.iter().take(k) {
        max = max.max(scaled[index]);
    }
    let mut probs = vec![0.0_f32; scaled.len()];
    let mut sum = 0.0_f64;
    for &index in order.iter().take(k) {
        #[allow(clippy::cast_precision_loss)] // logits are f32; exact as f64.
        let exp_value = f64::from(scaled[index] - max).exp();
        probs[index] = exp_value as f32;
        sum += exp_value;
    }
    if !(sum.is_finite() && sum > 0.0) {
        return None;
    }
    let draw = rng.unit() * sum;
    let mut accumulated = 0.0_f64;
    for &index in order.iter().take(k) {
        accumulated += f64::from(probs[index]);
        if accumulated >= draw {
            return Some(u32::try_from(index).unwrap_or(u32::MAX));
        }
    }
    None
}

/// The log-softmax of `logits` evaluated at `target`, computed stably.
fn log_softmax_at(logits: &[f32], target: usize) -> f32 {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let sum_exp: f64 = logits.iter().map(|&v| f64::from(v - max).exp()).sum();
    #[allow(clippy::cast_possible_truncation)]
    let result = (f64::from(logits[target] - max) - sum_exp.ln()) as f32;
    result
}

/// Whether `dir` holds a complete local-model resource set.
fn is_model_dir(dir: &Path) -> bool {
    dir.join("config.json").is_file()
        && dir.join("tokenizer.json").is_file()
        && dir.join("model.safetensors").is_file()
}

/// Resolves the bundled model resource directory: the `SA_MODEL_DIR` env var
/// first, then paths relative to the running executable, then the current
/// working directory.
///
/// The executable-relative search covers both the packaged app's
/// `resources/assets/model` and a development build's repository
/// `assets/model`.
#[must_use]
pub fn resolve_model_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("SA_MODEL_DIR") {
        let dir = PathBuf::from(dir);
        if is_model_dir(&dir) {
            return Some(dir);
        }
    }
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    for relative in ["assets/model", "../assets/model", "../../assets/model"] {
        let dir = exe_dir.join(relative);
        if is_model_dir(&dir) {
            return Some(dir);
        }
    }
    let dir = PathBuf::from("assets/model");
    if is_model_dir(&dir) {
        return Some(dir);
    }
    None
}

/// A fully-local, offline LLM: a byte-level BPE tokenizer plus a Llama-style
/// transformer run on the CPU via candle.
pub struct LocalTextModel {
    tokenizer: BpeTokenizer,
    model: LlamaModel,
    config: LocalConfig,
}

impl LocalTextModel {
    /// Loads the model, tokenizer, and config from `dir`. Returns `Ok(None)`
    /// when `dir/config.json` is not a Llama-style config (so callers can
    /// fall back to another backend such as
    /// [`crate::inference::CandleTextModel`]).
    ///
    /// # Errors
    ///
    /// Returns [`LocalModelError::Load`] when a resource file is missing or
    /// malformed, and [`LocalModelError::Compute`] when the forward path
    /// fails to build.
    pub fn from_dir(dir: &Path) -> Result<Option<Self>, LocalModelError> {
        let config_path = dir.join("config.json");
        let config_text = std::fs::read_to_string(&config_path).map_err(|error| {
            LocalModelError::Load(format!("failed to read {}: {error}", config_path.display()))
        })?;
        let Ok(config) = LocalConfig::from_json(&config_text) else {
            return Ok(None);
        };
        let tokenizer_path = dir.join("tokenizer.json");
        let tokenizer_text = std::fs::read_to_string(&tokenizer_path).map_err(|error| {
            LocalModelError::Load(format!(
                "failed to read {}: {error}",
                tokenizer_path.display()
            ))
        })?;
        let tokenizer = BpeTokenizer::from_json(&tokenizer_text)?;
        let device = Device::Cpu;
        let weights_path = dir.join("model.safetensors");
        // Safety: the mapping is read-only and lives for the duration of the
        // load; tensors are copied into the model, so no external mutation can
        // invalidate them here.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DType::F32, &device)
                .map_err(compute)?
        };
        let model = LlamaModel::load(&vb, &config)?;
        Ok(Some(Self {
            tokenizer,
            model,
            config,
        }))
    }

    /// Loads the bundled local model from the resolved resource directory, or
    /// `None` when it is not present (the app then falls back to the bundled
    /// tiny model).
    #[must_use]
    pub fn auto() -> Option<Self> {
        let dir = resolve_model_dir()?;
        Self::from_dir(&dir).ok().flatten()
    }

    /// The model configuration (used by tests).
    #[must_use]
    pub const fn config(&self) -> &LocalConfig {
        &self.config
    }

    /// Tokenizes `text` (used by tests).
    #[must_use]
    pub fn tokenize(&self, text: &str) -> Vec<u32> {
        self.tokenizer.encode(text)
    }

    /// Generates from pre-tokenized ids using the shared sampling loop (see
    /// [`LanguageModel::generate`]). `seed_text` drives the deterministic RNG
    /// so the same conversational input always yields the same reply.
    fn generate_from_ids(&self, ids: &[u32], max_tokens: usize, seed_text: &str) -> String {
        // No repetition penalty: for a small model the penalty pushes the
        // distribution off the coherent path into byte-fragment garbage,
        // while letting it repeat keeps every phrase clean. Repetition is
        // instead bounded by phrase-level loop detection below, which cuts
        // the generation the moment a tail phrase starts repeating.
        let mut ids = ids.to_vec();
        let mut rng = SplitMix64::from_seed(hash_prompt(seed_text));
        let mut cache = KvCache::new();
        let mut output_ids: Vec<u32> = Vec::with_capacity(max_tokens);
        for _ in 0..max_tokens {
            if ids.len() >= self.config.max_position_embeddings {
                break;
            }
            let Ok(rows) = self.model.forward_logits(&ids, &mut cache) else {
                break;
            };
            let Some(last) = rows.last() else {
                break;
            };
            let Some(id) = sample_token(last, &mut rng) else {
                break;
            };
            if id == self.config.eos_token_id {
                break;
            }
            output_ids.push(id);
            // Text-level loop detection: when the decoded tail (a phrase's
            // worth) already appears earlier in the reply, the model has
            // started repeating — cut it there.
            let decoded = self.tokenizer.decode(&output_ids);
            const LOOP_TAIL: usize = 40;
            if decoded.len() >= 2 * LOOP_TAIL {
                let tail = &decoded[decoded.len() - LOOP_TAIL..];
                if decoded[..decoded.len() - LOOP_TAIL].contains(tail) {
                    break;
                }
            }
            ids = vec![id];
        }
        self.tokenizer.decode(&output_ids)
    }
}

impl LanguageModel for LocalTextModel {
    fn generate(&self, prompt: &str, max_tokens: usize) -> String {
        // ChatML wrap (SmolLM2 instruct format). Empirically this model
        // follows instructions without a system message; adding one makes it
        // echo "user"/"system" role tokens instead of answering.
        let wrapped = format!("<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n");
        let ids = self.tokenizer.encode(&wrapped);
        self.generate_from_ids(&ids, max_tokens, prompt)
    }

    fn generate_chat(
        &self,
        context: &str,
        turns: &[(String, String)],
        message: &str,
        max_tokens: usize,
    ) -> String {
        // Decode directly from the assembled conversation prompt rather than
        // routing through `generate`, which would wrap the whole thing in a
        // second `user` turn.
        let prompt = crate::language_model::chat_prompt(context, turns, message);
        let ids = self.tokenizer.encode(&prompt);
        self.generate_from_ids(&ids, max_tokens, message)
    }

    fn perplexity(&self, text: &str) -> f32 {
        let ids = self.tokenizer.encode(text);
        if ids.len() < 2 {
            return f32::INFINITY;
        }
        let mut cache = KvCache::new();
        let Ok(rows) = self.model.forward_logits(&ids, &mut cache) else {
            return f32::INFINITY;
        };
        let mut total = 0.0_f64;
        let mut counted = 0_u32;
        for position in 0..ids.len() - 1 {
            let target = ids[position + 1] as usize;
            let row = &rows[position];
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_config() -> LocalConfig {
        LocalConfig {
            hidden_size: 576,
            intermediate_size: 1536,
            num_hidden_layers: 30,
            num_attention_heads: 9,
            num_key_value_heads: 3,
            max_position_embeddings: 8192,
            vocab_size: 49_152,
            bos_token_id: 1,
            eos_token_id: 2,
            rms_norm_eps: 1e-5,
            rope_theta: 100_000.0,
            tie_word_embeddings: true,
        }
    }

    #[test]
    fn config_parses_from_json() {
        let parsed = LocalConfig::from_json(
            r#"{"hidden_size":576,"intermediate_size":1536,"num_hidden_layers":30,
                "num_attention_heads":9,"num_key_value_heads":3,
                "max_position_embeddings":8192,"vocab_size":49152,
                "rms_norm_eps":1e-05,"rope_theta":100000,
                "tie_word_embeddings":true,"eos_token_id":2}"#,
        )
        .expect("valid config");
        assert_eq!(parsed, tiny_config());
    }

    #[test]
    fn config_rejects_missing_and_invalid() {
        assert!(LocalConfig::from_json("{}").is_err());
        assert!(LocalConfig::from_json("not json").is_err());
        // n_head does not divide hidden -> invalid.
        assert!(
            LocalConfig::from_json(
                r#"{"hidden_size":10,"intermediate_size":1,"num_hidden_layers":1,
                "num_attention_heads":3,"max_position_embeddings":8,"vocab_size":16}"#
            )
            .is_err()
        );
    }

    #[test]
    fn larger_smollm_shaped_config_parses() {
        // A SmolLM2-1.7B-shaped config (hidden 2048, 24 layers, 16 heads, 8 KV
        // heads) parses and validates, showing the loader is generic over the
        // Llama architecture — a bigger model drops into assets/model/ with no
        // code change.
        let config = LocalConfig::from_json(
            r#"{"hidden_size":2048,"intermediate_size":8192,"num_hidden_layers":24,
                "num_attention_heads":16,"num_key_value_heads":8,
                "max_position_embeddings":8192,"vocab_size":49152,
                "rms_norm_eps":1e-05,"rope_theta":1000000,
                "tie_word_embeddings":true,"eos_token_id":2}"#,
        )
        .expect("1.7B-shaped config");
        assert_eq!(config.hidden_size, 2048);
        assert_eq!(config.num_hidden_layers, 24);
        assert_eq!(config.num_attention_heads, 16);
        assert_eq!(config.num_key_value_heads, 8);
        assert_eq!(config.head_dim(), 128);
    }

    #[test]
    fn repetition_penalty_suppresses_seen_tokens() {
        // A logits vector where id 0 is the greedy favorite.
        let logits = [10.0_f32, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0];
        let seed = 0x5EED_5EED_5EED_5EED;
        let count_wins = |penalty: f32, seen: &std::collections::HashSet<u32>| -> u32 {
            let mut rng = SplitMix64::from_seed(seed);
            let mut wins = 0_u32;
            for _ in 0..2_000 {
                if sample_token(&logits, &mut rng, penalty, seen) == Some(0) {
                    wins += 1;
                }
            }
            wins
        };
        let no_penalty = count_wins(1.0, &std::collections::HashSet::new());
        let penalized = count_wins(1.15, &std::iter::once(0_u32).collect());
        // The favorite wins a clear majority without a penalty...
        assert!(no_penalty > 1_200, "favorite win count {no_penalty}");
        // ...and is suppressed below a coin flip once penalized.
        assert!(penalized < 1_000, "penalized win count {penalized}");
        assert!(penalized < no_penalty);
    }

    #[test]
    fn bytes_to_unicode_is_a_bijection() {
        let (table, reverse) = bytes_to_unicode();
        assert_eq!(table.len(), 256);
        assert_eq!(reverse.len(), 256);
        for b in 0_u8..=255 {
            let ch = table[usize::from(b)];
            assert_eq!(reverse.get(&ch).copied(), Some(b));
        }
    }

    #[test]
    fn pre_tokenize_splits_gpt2_style() {
        // The pre-tokenizer is exercised through encode on a small synthetic
        // tokenizer built from a hand-rolled vocabulary.
        let tokenizer = BpeTokenizer::from_json(
            r#"{"model":{"type":"BPE","vocab":{"<|endoftext|>":0,"<|im_start|>":1,"<|im_end|>":2,
                "a":3,"Ġb":4,"'s":5},
                "merges":[]},
                "added_tokens":[{"id":1,"content":"<|im_start|>","special":true},
                                {"id":2,"content":"<|im_end|>","special":true}]}"#,
        )
        .expect("tokenizer");
        // "a b's" -> "a", "Ġb", "'s" (the apostrophe contraction is one unit).
        let ids = tokenizer.encode("a b's");
        assert_eq!(ids, vec![3, 4, 5]);
        // A verbatim special token survives the pre-tokenizer.
        let special = tokenizer.encode("<|im_start|>user<|im_end|>");
        assert_eq!(special.first(), Some(&1));
        assert_eq!(special.last(), Some(&2));
    }

    #[test]
    fn pre_tokenize_matches_gpt2_whitespace_regex() {
        // Emulates the GPT2 regex ` ?\p{L}+` / `\s+(?!\S)` / `\s+`: only a
        // trailing literal space joins the following run; newlines/tabs and
        // the rest of a whitespace run stand alone.
        let tokenizer = BpeTokenizer::from_json(
            r#"{"model":{"type":"BPE","vocab":{"a":0,"Ġb":1,"'s":2},"merges":[]},"added_tokens":[]}"#,
        )
        .expect("tokenizer");
        let text = |s: &str| {
            tokenizer
                .pre_tokenize(s)
                .into_iter()
                .map(|t| match t {
                    PreToken::Text(text) => text,
                    PreToken::Special(id) => format!("<{id}>"),
                })
                .collect::<Vec<_>>()
        };
        // A single literal space joins the following word...
        assert_eq!(text("a b"), ["a", " b"]);
        // ...but only the *last* space of a run joins: "  b" -> " ", " b".
        assert_eq!(text("a  b"), ["a", " ", " b"]);
        // Newlines never join a following word.
        assert_eq!(text("a\nb"), ["a", "\n", "b"]);
        assert_eq!(text("a\n b"), ["a", "\n", " b"]);
        assert_eq!(text("a\n\nb"), ["a", "\n", "\n", "b"]);
        assert_eq!(text("a\n  b"), ["a", "\n ", " b"]);
        // Trailing whitespace stays whole.
        assert_eq!(text("a\n\n"), ["a", "\n\n"]);
        assert_eq!(text("a  "), ["a", "  "]);
    }

    #[test]
    fn decode_round_trips_ascii() {
        let tokenizer = BpeTokenizer::from_json(
            r#"{"model":{"type":"BPE","vocab":{"a":0,"b":1,"Ġc":2},"merges":[]},"added_tokens":[]}"#,
        )
        .expect("tokenizer");
        assert_eq!(tokenizer.decode(&[0, 1]), "ab");
        assert_eq!(tokenizer.decode(&[2]), " c");
    }

    #[test]
    fn from_dir_returns_none_for_non_llama_config() {
        let dir = std::env::temp_dir().join("security-agent-not-llama");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(dir.join("config.json"), r#"{"n_embd":16,"n_head":2}"#)
            .expect("write config");
        let result = LocalTextModel::from_dir(&dir).expect("no error");
        assert!(result.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_model_dir_honors_env_var() {
        let dir = std::env::temp_dir().join("security-agent-model-dir-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        for file in ["config.json", "tokenizer.json", "model.safetensors"] {
            std::fs::write(dir.join(file), b"x").expect("write resource");
        }
        // SAFETY: this is the only test touching SA_MODEL_DIR and the value
        // is removed before the test ends, so no concurrent access occurs.
        unsafe {
            std::env::set_var("SA_MODEL_DIR", &dir);
        }
        let resolved = resolve_model_dir();
        unsafe {
            std::env::remove_var("SA_MODEL_DIR");
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(resolved, Some(dir));
    }

    /// Slow, resource-heavy: only meaningful with the bundled 256 MB model
    /// present (skipped otherwise), and best run with `--release` because
    /// unoptimized candle GEMMs are too slow. Proves the KV-cache decode path
    /// produces the same logits as a single full-context forward, so the
    /// token-by-token generation loop cannot silently drift.
    #[test]
    fn kv_cache_matches_full_context_forward() {
        let Some(model_dir) = resolve_model_dir() else {
            return;
        };
        let Some(model) = LocalTextModel::from_dir(&model_dir).expect("load bundled model") else {
            return;
        };
        let ids = model
            .tokenizer
            .encode("The quick brown fox jumps over the lazy dog");
        assert!(ids.len() >= 4, "sanity: prompt tokenizes to several tokens");
        let mut cache_full = KvCache::new();
        let full = model
            .model
            .forward_logits(&ids, &mut cache_full)
            .expect("full-context forward");
        assert_eq!(full.len(), ids.len());
        let mut cache_inc = KvCache::new();
        for (position, &id) in ids.iter().enumerate() {
            let rows = model
                .model
                .forward_logits(&[id], &mut cache_inc)
                .expect("incremental forward");
            assert_eq!(rows.len(), 1);
            let expected = &full[position];
            let observed = &rows[0];
            assert_eq!(expected.len(), observed.len());
            let max_diff = expected
                .iter()
                .zip(observed)
                .map(|(a, b)| f64::from(a - b).abs())
                .fold(0.0_f64, f64::max);
            // GEMM kernels may reorder sums between batch shapes, so allow a
            // small absolute tolerance; a genuine cache/mask bug diverges by
            // orders of magnitude more.
            assert!(
                max_diff < 1.0,
                "logits diverge at position {position}: max diff {max_diff}"
            );
        }
    }
}
