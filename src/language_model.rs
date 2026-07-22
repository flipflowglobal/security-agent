//! A small, self-contained neural language model.
//!
//! This is a genuine (if tiny) neural language model, not a wrapper around a
//! large pretrained transformer: it learns word embeddings and a hidden
//! layer by gradient descent, then predicts the next token from a softmax
//! over the vocabulary. It is deliberately small so it stays true to the
//! rest of the crate — **no external crates, no network, no model weights on
//! disk**. The model trains itself, deterministically, from a compact
//! security-domain corpus compiled into the binary
//! ([`SECURITY_CORPUS`]), so the whole thing ships inside the offline
//! binary like every other capability here.
//!
//! Architecture: a word-level neural bigram/trigram model
//! (context of [`CONTEXT`] previous tokens) —
//! `embedding -> concat -> tanh hidden layer -> linear -> softmax`, trained
//! with online SGD and cross-entropy loss. It exposes text generation and
//! perplexity scoring through the [`LanguageModel`] trait, which is also the
//! seam where a larger, feature-gated backend could plug in later.
//!
//! Being tiny, its text is modest — it captures the domain's vocabulary and
//! local phrasing, not long-range coherence. Like the cognitive layer, it is
//! advisory: nothing here affects authorization.

/// Anything that can continue a prompt and score how surprising text is.
/// Implemented by [`NeuralLanguageModel`]; kept as a trait so a larger
/// backend can be substituted without touching callers.
pub trait LanguageModel {
    /// Continues `prompt` for up to `max_tokens` tokens (deterministic,
    /// greedy decoding).
    fn generate(&self, prompt: &str, max_tokens: usize) -> String;

    /// The model's perplexity on `text` — its average per-token surprise.
    /// Lower means the text looks more like what the model was trained on.
    fn perplexity(&self, text: &str) -> f32;
}

/// Number of previous tokens the model conditions on.
const CONTEXT: usize = 2;
/// Embedding width per token.
const EMBED: usize = 8;
/// Hidden-layer width.
const HIDDEN: usize = 24;
/// Concatenated input width feeding the hidden layer.
const INPUT: usize = CONTEXT * EMBED;
/// Training passes over the corpus.
const EPOCHS: usize = 160;
/// SGD learning rate.
const LEARNING_RATE: f32 = 0.1;
/// Deterministic seed for weight initialization.
const SEED: u64 = 0x5EC0_0DED_1234_5678;

/// Sentence-boundary token (also used as left padding for the first tokens).
const BOS: &str = "<s>";
/// End-of-sentence token; generation stops when it is produced.
const EOS: &str = "</s>";

/// Compact, in-domain training text. Small on purpose — enough to teach the
/// model the security vocabulary and local phrasing while keeping training
/// fast and fully deterministic.
const SECURITY_CORPUS: &str = "\
the coordinator plans an authorized scan across in scope targets.
every finding is scored by severity and confidence.
broken object level authorization is a common api vulnerability.
misconfigured headers and weak tls are frequent web findings.
the policy engine denies out of scope and deny listed targets.
static analysis surfaces injection and unsafe deserialization bugs.
hardcoded secrets in mobile binaries are a frequent finding.
overly permissive cloud iam grants excessive privilege.
the attacker pivots from a compromised asset to reachable assets.
lateral movement raises the risk of neighboring targets.
remediation reduces the residual risk of a critical finding.
the audit ledger records every authorized action.
passive recon precedes active testing on authorized engagements.
rate limiting mitigates brute force against the api.
the retest schedule is derived from the finding risk score.
a high impact target requires explicit approval before testing.
the agent reasons over an already authorized plan.
calibration measures whether stated confidence matches reality.
belief propagation spreads compromise risk across the attack graph.
the specialist maps techniques to approved tools within scope.";

/// A fast, fully-deterministic pseudo-random generator (`SplitMix64`), used
/// for reproducible weight initialization — no external RNG crate.
struct Rng {
    state: u64,
}

impl Rng {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform sample in `[-scale, scale)`.
    fn symmetric(&mut self, scale: f32) -> f32 {
        // Top 24 bits are an integer in [0, 2^24), exactly representable in
        // f32; dividing by 2^24 gives a unit value in [0, 1).
        const TWO_POW_24: f32 = 16_777_216.0;
        #[allow(clippy::cast_precision_loss)]
        let unit = (self.next_u64() >> 40) as f32 / TWO_POW_24;
        (unit * 2.0 - 1.0) * scale
    }
}

/// `usize` -> `f32` for counts small enough to be exact here.
#[allow(clippy::cast_precision_loss)]
const fn count(value: usize) -> f32 {
    value as f32
}

/// Token vocabulary with stable id assignment.
#[derive(Debug, Clone)]
struct Vocabulary {
    tokens: Vec<String>,
    ids: std::collections::HashMap<String, usize>,
}

impl Vocabulary {
    fn from_corpus(corpus: &str) -> Self {
        let mut tokens = vec![BOS.to_string(), EOS.to_string()];
        let mut ids = std::collections::HashMap::new();
        ids.insert(BOS.to_string(), 0);
        ids.insert(EOS.to_string(), 1);
        for token in corpus.split_whitespace().filter_map(normalize) {
            if !ids.contains_key(&token) {
                ids.insert(token.clone(), tokens.len());
                tokens.push(token);
            }
        }
        Self { tokens, ids }
    }

    fn len(&self) -> usize {
        self.tokens.len()
    }

    fn id(&self, token: &str) -> Option<usize> {
        self.ids.get(token).copied()
    }

    fn token(&self, id: usize) -> &str {
        &self.tokens[id]
    }
}

/// Lowercases a raw whitespace-delimited word and strips surrounding
/// punctuation, yielding zero or one clean tokens.
fn normalize(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Splits `text` into sentences (on `.`), each a token-id sequence padded
/// with `CONTEXT` leading [`BOS`] ids and a trailing [`EOS`] id. Unknown
/// words are dropped.
fn encode_sentences(vocab: &Vocabulary, text: &str) -> Vec<Vec<usize>> {
    let bos = vocab.id(BOS).unwrap_or(0);
    let eos = vocab.id(EOS).unwrap_or(1);
    text.split('.')
        .filter_map(|sentence| {
            let mut ids: Vec<usize> = vec![bos; CONTEXT];
            ids.extend(
                sentence
                    .split_whitespace()
                    .filter_map(normalize)
                    .filter_map(|token| vocab.id(&token)),
            );
            if ids.len() == CONTEXT {
                return None; // empty sentence
            }
            ids.push(eos);
            Some(ids)
        })
        .collect()
}

/// A word-level neural language model with learned embeddings and one tanh
/// hidden layer.
#[derive(Debug, Clone)]
pub struct NeuralLanguageModel {
    vocab: Vocabulary,
    embed: Vec<f32>, // vocab_len * EMBED
    w1: Vec<f32>,    // HIDDEN * INPUT
    b1: Vec<f32>,    // HIDDEN
    w2: Vec<f32>,    // vocab_len * HIDDEN
    b2: Vec<f32>,    // vocab_len
}

impl Default for NeuralLanguageModel {
    fn default() -> Self {
        Self::bundled()
    }
}

impl NeuralLanguageModel {
    /// Builds and trains the default model on the bundled security corpus.
    /// Deterministic: the same binary always yields the same model.
    #[must_use]
    pub fn bundled() -> Self {
        Self::trained_on(SECURITY_CORPUS, EPOCHS)
    }

    /// Builds a vocabulary from `corpus` and trains for `epochs` passes.
    #[must_use]
    pub fn trained_on(corpus: &str, epochs: usize) -> Self {
        let vocab = Vocabulary::from_corpus(corpus);
        let vocab_len = vocab.len();
        let mut rng = Rng::new(SEED);

        let mut model = Self {
            embed: init(vocab_len * EMBED, 0.3, &mut rng),
            w1: init(HIDDEN * INPUT, 0.3, &mut rng),
            b1: vec![0.0; HIDDEN],
            w2: init(vocab_len * HIDDEN, 0.3, &mut rng),
            b2: vec![0.0; vocab_len],
            vocab,
        };

        let sentences = encode_sentences(&model.vocab, corpus);
        for _ in 0..epochs {
            for sentence in &sentences {
                for window in sentence.windows(CONTEXT + 1) {
                    let context = [window[0], window[1]];
                    let target = window[2];
                    model.train_step(context, target);
                }
            }
        }
        model
    }

    /// Forward pass: returns the concatenated input, hidden activations, and
    /// softmax probabilities over the vocabulary for `context`.
    // Flat-indexed matrix math reads more clearly as range loops than as
    // zipped iterators, since each step indexes weights by a computed offset.
    #[allow(clippy::needless_range_loop)]
    fn forward(&self, context: [usize; CONTEXT]) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
        let mut input = vec![0.0_f32; INPUT];
        for (slot, &token) in context.iter().enumerate() {
            let base = token * EMBED;
            input[slot * EMBED..(slot + 1) * EMBED]
                .copy_from_slice(&self.embed[base..base + EMBED]);
        }

        let mut hidden = vec![0.0_f32; HIDDEN];
        for (h, hidden_value) in hidden.iter_mut().enumerate() {
            let mut sum = self.b1[h];
            for i in 0..INPUT {
                sum += self.w1[h * INPUT + i] * input[i];
            }
            *hidden_value = sum.tanh();
        }

        let vocab_len = self.vocab.len();
        let mut logits = vec![0.0_f32; vocab_len];
        for (v, logit) in logits.iter_mut().enumerate() {
            let mut sum = self.b2[v];
            for h in 0..HIDDEN {
                sum += self.w2[v * HIDDEN + h] * hidden[h];
            }
            *logit = sum;
        }

        softmax(&mut logits);
        (input, hidden, logits)
    }

    /// One SGD step of cross-entropy loss for `context -> target`.
    #[allow(clippy::needless_range_loop)]
    fn train_step(&mut self, context: [usize; CONTEXT], target: usize) {
        let (input, hidden, probs) = self.forward(context);
        let vocab_len = self.vocab.len();

        // dL/dlogits for softmax + cross-entropy.
        let mut dlogits = probs;
        dlogits[target] -= 1.0;

        // Gradients into the hidden layer (using current w2, before update).
        let mut dhidden = [0.0_f32; HIDDEN];
        for (h, dh) in dhidden.iter_mut().enumerate() {
            let mut sum = 0.0;
            for v in 0..vocab_len {
                sum += self.w2[v * HIDDEN + h] * dlogits[v];
            }
            // tanh'(z) = 1 - tanh(z)^2, and hidden already holds tanh(z).
            *dh = sum * hidden[h].mul_add(-hidden[h], 1.0);
        }

        // Gradients into the input (using current w1, before update).
        let mut dinput = [0.0_f32; INPUT];
        for (i, di) in dinput.iter_mut().enumerate() {
            let mut sum = 0.0;
            for h in 0..HIDDEN {
                sum += self.w1[h * INPUT + i] * dhidden[h];
            }
            *di = sum;
        }

        // Apply updates.
        for v in 0..vocab_len {
            for h in 0..HIDDEN {
                self.w2[v * HIDDEN + h] -= LEARNING_RATE * dlogits[v] * hidden[h];
            }
            self.b2[v] -= LEARNING_RATE * dlogits[v];
        }
        for h in 0..HIDDEN {
            for i in 0..INPUT {
                self.w1[h * INPUT + i] -= LEARNING_RATE * dhidden[h] * input[i];
            }
            self.b1[h] -= LEARNING_RATE * dhidden[h];
        }
        for (slot, &token) in context.iter().enumerate() {
            let base = token * EMBED;
            for j in 0..EMBED {
                self.embed[base + j] -= LEARNING_RATE * dinput[slot * EMBED + j];
            }
        }
    }

    /// Mean cross-entropy loss over the bundled corpus — used by tests to
    /// confirm the model actually learns.
    #[cfg(test)]
    #[must_use]
    fn mean_loss(&self, corpus: &str) -> f32 {
        let sentences = encode_sentences(&self.vocab, corpus);
        let mut total = 0.0;
        let mut steps = 0usize;
        for sentence in &sentences {
            for window in sentence.windows(CONTEXT + 1) {
                let (_, _, probs) = self.forward([window[0], window[1]]);
                total += -(probs[window[2]].max(f32::MIN_POSITIVE)).ln();
                steps += 1;
            }
        }
        if steps == 0 {
            0.0
        } else {
            total / count(steps)
        }
    }

    /// The most probable next token id for `context`.
    fn argmax_next(&self, context: [usize; CONTEXT]) -> usize {
        let (_, _, probs) = self.forward(context);
        probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(0, |(index, _)| index)
    }

    /// Encodes `prompt` into an initial context of the last [`CONTEXT`]
    /// known token ids, padding with [`BOS`] when the prompt is short or its
    /// words are out of vocabulary.
    fn seed_context(&self, prompt: &str) -> [usize; CONTEXT] {
        let bos = self.vocab.id(BOS).unwrap_or(0);
        let known: Vec<usize> = prompt
            .split_whitespace()
            .filter_map(normalize)
            .filter_map(|token| self.vocab.id(&token))
            .collect();
        let mut context = [bos; CONTEXT];
        for (slot, &id) in context
            .iter_mut()
            .zip(known.iter().rev().take(CONTEXT).rev())
        {
            *slot = id;
        }
        context
    }
}

impl LanguageModel for NeuralLanguageModel {
    fn generate(&self, prompt: &str, max_tokens: usize) -> String {
        let bos = self.vocab.id(BOS).unwrap_or(0);
        let eos = self.vocab.id(EOS).unwrap_or(1);
        let mut context = self.seed_context(prompt);
        let mut produced = Vec::new();

        for _ in 0..max_tokens {
            let next = self.argmax_next(context);
            if next == eos {
                break;
            }
            if next != bos {
                produced.push(self.vocab.token(next).to_string());
            }
            context = [context[1], next];
        }
        produced.join(" ")
    }

    fn perplexity(&self, text: &str) -> f32 {
        let sentences = encode_sentences(&self.vocab, text);
        let mut total = 0.0;
        let mut steps = 0usize;
        for sentence in &sentences {
            for window in sentence.windows(CONTEXT + 1) {
                let (_, _, probs) = self.forward([window[0], window[1]]);
                total += -(probs[window[2]].max(f32::MIN_POSITIVE)).ln();
                steps += 1;
            }
        }
        if steps == 0 {
            return f32::INFINITY;
        }
        (total / count(steps)).exp()
    }
}

/// Initializes `len` weights uniformly in `[-scale, scale)`.
fn init(len: usize, scale: f32, rng: &mut Rng) -> Vec<f32> {
    (0..len).map(|_| rng.symmetric(scale)).collect()
}

/// In-place numerically-stable softmax.
fn softmax(values: &mut [f32]) {
    let max = values.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0;
    for value in values.iter_mut() {
        *value = (*value - max).exp();
        sum += *value;
    }
    if sum > 0.0 {
        for value in values.iter_mut() {
            *value /= sum;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary_covers_the_corpus_and_specials() {
        let vocab = Vocabulary::from_corpus(SECURITY_CORPUS);
        assert_eq!(vocab.id(BOS), Some(0));
        assert_eq!(vocab.id(EOS), Some(1));
        assert!(vocab.id("authorized").is_some());
        assert!(vocab.id("calibration").is_some());
        assert!(vocab.id("nonexistentword").is_none());
        assert!(vocab.len() > 20);
    }

    #[test]
    fn normalize_strips_punctuation_and_lowercases() {
        assert_eq!(normalize("Scan."), Some("scan".to_string()));
        assert_eq!(normalize("API,"), Some("api".to_string()));
        assert_eq!(normalize("!!!"), None);
    }

    #[test]
    fn training_reduces_loss() {
        let untrained = NeuralLanguageModel::trained_on(SECURITY_CORPUS, 0);
        let trained = NeuralLanguageModel::trained_on(SECURITY_CORPUS, EPOCHS);
        let before = untrained.mean_loss(SECURITY_CORPUS);
        let after = trained.mean_loss(SECURITY_CORPUS);
        assert!(
            after < before,
            "training should reduce loss: before={before:.3} after={after:.3}"
        );
    }

    #[test]
    fn generation_is_deterministic_and_in_vocabulary() {
        let model = NeuralLanguageModel::bundled();
        let first = model.generate("the coordinator", 8);
        let second = model.generate("the coordinator", 8);
        assert_eq!(first, second, "greedy decoding must be deterministic");

        let vocab = Vocabulary::from_corpus(SECURITY_CORPUS);
        for token in first.split_whitespace() {
            assert!(
                vocab.id(token).is_some(),
                "generated token '{token}' must be in the vocabulary"
            );
        }
    }

    #[test]
    fn generation_handles_unknown_and_empty_prompts() {
        let model = NeuralLanguageModel::bundled();
        // Out-of-vocabulary prompt: falls back to BOS padding, still emits
        // only in-vocabulary tokens without panicking.
        let out = model.generate("qqqq zzzz", 6);
        let vocab = Vocabulary::from_corpus(SECURITY_CORPUS);
        for token in out.split_whitespace() {
            assert!(vocab.id(token).is_some());
        }
        // Empty prompt is fine too.
        let _ = model.generate("", 4);
    }

    #[test]
    fn in_domain_text_has_lower_perplexity_than_gibberish() {
        let model = NeuralLanguageModel::bundled();
        let in_domain = model.perplexity("the policy engine denies out of scope targets");
        let gibberish = model.perplexity("calibration attacker remediation the the api scope");
        assert!(
            in_domain < gibberish,
            "in-domain text should be less surprising: in_domain={in_domain:.2} gibberish={gibberish:.2}"
        );
        assert!(in_domain.is_finite());
    }

    #[test]
    fn softmax_normalizes_to_one() {
        let mut values = vec![1.0, 2.0, 3.0];
        softmax(&mut values);
        let sum: f32 = values.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5);
        assert!(values.iter().all(|&p| (0.0..=1.0).contains(&p)));
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(SEED);
        let mut b = Rng::new(SEED);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        // Samples stay within the requested symmetric range.
        let mut rng = Rng::new(SEED);
        for _ in 0..1000 {
            let value = rng.symmetric(0.3);
            assert!((-0.3..0.3).contains(&value));
        }
    }
}
