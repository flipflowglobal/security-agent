//! A small, fully-local vector-quantized temporal-frequency neural language
//! model.
//!
//! This is a genuine (if tiny) neural language model with a deliberately
//! unusual architecture, and it stays true to the rest of the crate — **no
//! external crates, no network, no model weights on disk**. It trains
//! itself, deterministically, from a compact security-domain corpus
//! compiled into the binary ([`SECURITY_CORPUS`]).
//!
//! The prediction path is *temporal-frequency + vector-quantized*:
//!
//! 1. **Embed** the recent window of [`CONTEXT`] tokens into learned
//!    vectors, giving a short multi-channel *time signal*
//!    (`CONTEXT` steps × [`EMBED`] channels).
//! 2. **Temporal → frequency**: apply a Discrete Cosine Transform (DCT-II)
//!    along the time axis of each channel, so the model reasons about *how*
//!    the context changes across the window (its spectral content) rather
//!    than the raw sequence.
//! 3. **Vector-quantize** the flattened spectral features against a learned
//!    codebook (VQ-VAE style, with a straight-through estimator and a
//!    commitment penalty), collapsing them to the nearest discrete code.
//! 4. **Predict** the next token from that quantized code through a tanh
//!    hidden layer and a softmax over the vocabulary.
//!
//! Everything — the DCT, the codebook nearest-neighbor search, the forward
//! and backward passes, and a deterministic `SplitMix64` RNG — is
//! hand-rolled, so the whole model ships inside the offline binary like
//! every other capability here. Being tiny, its text is modest; like the
//! cognitive layer, it is advisory and never affects authorization.

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

/// Number of previous tokens in the temporal window the model transforms.
const CONTEXT: usize = 4;
/// Embedding channels per token (the temporal signal's channel count).
const EMBED: usize = 8;
/// Flattened spectral-feature width (`CONTEXT` frequencies × `EMBED`
/// channels).
const FEAT: usize = CONTEXT * EMBED;
/// Number of entries in each vector-quantization codebook.
const CODES: usize = 48;
/// Number of residual quantization stages. Each stage quantizes the
/// residual the previous stage left behind (`q = q1 + q2 + ...`), a
/// residual path *through* the quantizer that shrinks quantization error and
/// recovers detail the discrete bottleneck would otherwise lose.
const VQ_STAGES: usize = 2;
/// Hidden-layer width of the prediction head.
const HIDDEN: usize = 24;
/// Training passes over the corpus.
const EPOCHS: usize = 150;
/// SGD learning rate.
const LEARNING_RATE: f32 = 0.05;
/// Weight of the VQ commitment/codebook penalties.
const COMMITMENT: f32 = 0.25;
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

/// The DCT-II basis matrix (`CONTEXT` × `CONTEXT`), row-major:
/// `dct[k*CONTEXT + n] = cos(pi/CONTEXT * (n + 0.5) * k)`. This turns a
/// length-`CONTEXT` temporal signal into `CONTEXT` frequency coefficients.
fn dct_matrix() -> Vec<f32> {
    let mut matrix = vec![0.0_f32; CONTEXT * CONTEXT];
    for k in 0..CONTEXT {
        for n in 0..CONTEXT {
            let angle = std::f32::consts::PI / count(CONTEXT) * (count(n) + 0.5) * count(k);
            matrix[k * CONTEXT + n] = angle.cos();
        }
    }
    matrix
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

/// Intermediates from a forward pass, retained so the backward pass can
/// reuse them.
struct Forward {
    /// Flattened DCT spectral features, length `FEAT`.
    spectral: Vec<f32>,
    /// Chosen codebook index at each residual stage.
    codes: Vec<usize>,
    /// Summed quantized code (`q1 + q2 + ...`), length `FEAT` — the residual
    /// approximation of `spectral` fed to the prediction head.
    quant: Vec<f32>,
    /// Hidden activations, length `HIDDEN`.
    hidden: Vec<f32>,
    /// Softmax distribution over the vocabulary.
    probs: Vec<f32>,
}

/// A vector-quantized, temporal-frequency neural language model with
/// residual (multi-stage) quantization.
#[derive(Debug, Clone)]
pub struct NeuralLanguageModel {
    vocab: Vocabulary,
    dct: Vec<f32>,            // CONTEXT * CONTEXT
    embed: Vec<f32>,          // vocab_len * EMBED
    codebooks: Vec<Vec<f32>>, // stages × (CODES * FEAT)
    w1: Vec<f32>,             // HIDDEN * FEAT
    b1: Vec<f32>,             // HIDDEN
    w2: Vec<f32>,             // vocab_len * HIDDEN
    b2: Vec<f32>,             // vocab_len
}

impl Default for NeuralLanguageModel {
    fn default() -> Self {
        Self::bundled()
    }
}

impl NeuralLanguageModel {
    /// Builds and trains the default model on the bundled security corpus.
    /// Deterministic: the same binary always yields the same model.
    ///
    /// Training is memoized in a process-wide [`std::sync::OnceLock`] and
    /// subsequent calls return a clone, so repeated use (tests, multiple CLI
    /// paths, `Default`) trains only once.
    #[must_use]
    pub fn bundled() -> Self {
        static CACHED: std::sync::OnceLock<NeuralLanguageModel> = std::sync::OnceLock::new();
        CACHED
            .get_or_init(|| Self::trained_on(SECURITY_CORPUS, EPOCHS))
            .clone()
    }

    /// Builds a vocabulary from `corpus` and trains for `epochs` passes using
    /// the default number of residual quantization stages.
    #[must_use]
    pub fn trained_on(corpus: &str, epochs: usize) -> Self {
        Self::trained_staged(corpus, epochs, VQ_STAGES)
    }

    /// Like [`Self::trained_on`], but with an explicit number of residual
    /// quantization `stages` (used to compare quantization depth).
    #[must_use]
    pub fn trained_staged(corpus: &str, epochs: usize, stages: usize) -> Self {
        let vocab = Vocabulary::from_corpus(corpus);
        let vocab_len = vocab.len();
        let mut rng = Rng::new(SEED);

        let stages = stages.max(1);
        let codebooks = (0..stages)
            .map(|_| init(CODES * FEAT, 0.3, &mut rng))
            .collect();
        let mut model = Self {
            dct: dct_matrix(),
            embed: init(vocab_len * EMBED, 0.3, &mut rng),
            codebooks,
            w1: init(HIDDEN * FEAT, 0.3, &mut rng),
            b1: vec![0.0; HIDDEN],
            w2: init(vocab_len * HIDDEN, 0.3, &mut rng),
            b2: vec![0.0; vocab_len],
            vocab,
        };

        let sentences = encode_sentences(&model.vocab, corpus);
        for _ in 0..epochs {
            for sentence in &sentences {
                for window in sentence.windows(CONTEXT + 1) {
                    let mut context = [0usize; CONTEXT];
                    context.copy_from_slice(&window[..CONTEXT]);
                    model.train_step(context, window[CONTEXT]);
                }
            }
        }
        model
    }

    /// Mean-pooled embedding of `text` over its in-vocabulary tokens (a
    /// bag-of-embeddings sentence vector), length [`EMBED`]. Zero vector when
    /// no token is known. Used by the natural-language intent router to
    /// compare an instruction against capability descriptions in the model's
    /// learned semantic space.
    #[must_use]
    pub fn embed_text(&self, text: &str) -> Vec<f32> {
        let mut sum = vec![0.0_f32; EMBED];
        let mut n = 0usize;
        for token in text.split_whitespace().filter_map(normalize) {
            if let Some(id) = self.vocab.id(&token) {
                let base = id * EMBED;
                for (acc, &value) in sum.iter_mut().zip(&self.embed[base..base + EMBED]) {
                    *acc += value;
                }
                n += 1;
            }
        }
        if n > 0 {
            let inv = 1.0 / count(n);
            for value in &mut sum {
                *value *= inv;
            }
        }
        sum
    }

    /// Embeds the temporal window, then applies the DCT along the time axis
    /// of each channel to produce the flattened spectral features.
    // Flat-indexed spectral/matrix math reads more clearly as range loops
    // with `sum += a * b` than as iterator/`mul_add` rewrites.
    #[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
    fn spectral_features(&self, context: [usize; CONTEXT]) -> (Vec<f32>, Vec<f32>) {
        let mut embeds = vec![0.0_f32; CONTEXT * EMBED];
        for (step, &token) in context.iter().enumerate() {
            let base = token * EMBED;
            embeds[step * EMBED..(step + 1) * EMBED]
                .copy_from_slice(&self.embed[base..base + EMBED]);
        }

        // spectral[k*EMBED + d] = sum_n dct[k][n] * embeds[n][d]
        let mut spectral = vec![0.0_f32; FEAT];
        for k in 0..CONTEXT {
            for d in 0..EMBED {
                let mut sum = 0.0;
                for n in 0..CONTEXT {
                    sum += self.dct[k * CONTEXT + n] * embeds[n * EMBED + d];
                }
                spectral[k * EMBED + d] = sum;
            }
        }
        (embeds, spectral)
    }

    /// Residual (multi-stage) quantization of `spectral`: each stage picks
    /// the nearest entry in its codebook to the running residual, adds it to
    /// the reconstruction, and passes the shrinking residual on. Returns the
    /// per-stage code indices and the summed quantized vector.
    fn residual_quantize(&self, spectral: &[f32]) -> (Vec<usize>, Vec<f32>) {
        let mut residual = spectral.to_vec();
        let mut quant = vec![0.0_f32; FEAT];
        let mut codes = Vec::with_capacity(self.codebooks.len());
        for codebook in &self.codebooks {
            let code = nearest_code(codebook, &residual);
            codes.push(code);
            let base = code * FEAT;
            for f in 0..FEAT {
                quant[f] += codebook[base + f];
                residual[f] -= codebook[base + f];
            }
        }
        (codes, quant)
    }

    /// Full forward pass for `context`.
    #[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
    fn forward(&self, context: [usize; CONTEXT]) -> Forward {
        let (_embeds, spectral) = self.spectral_features(context);
        let (codes, quant) = self.residual_quantize(&spectral);

        let mut hidden = vec![0.0_f32; HIDDEN];
        for i in 0..HIDDEN {
            let mut sum = self.b1[i];
            for f in 0..FEAT {
                sum += self.w1[i * FEAT + f] * quant[f];
            }
            hidden[i] = sum.tanh();
        }

        let vocab_len = self.vocab.len();
        let mut logits = vec![0.0_f32; vocab_len];
        for v in 0..vocab_len {
            let mut sum = self.b2[v];
            for i in 0..HIDDEN {
                sum += self.w2[v * HIDDEN + i] * hidden[i];
            }
            logits[v] = sum;
        }
        softmax(&mut logits);

        Forward {
            spectral,
            codes,
            quant,
            hidden,
            probs: logits,
        }
    }

    /// One SGD step of cross-entropy loss (plus VQ commitment/codebook
    /// penalties) for `context -> target`.
    #[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
    fn train_step(&mut self, context: [usize; CONTEXT], target: usize) {
        let pass = self.forward(context);
        let vocab_len = self.vocab.len();

        // dL/dlogits for softmax + cross-entropy.
        let mut dlogits = pass.probs;
        dlogits[target] -= 1.0;

        // Hidden-layer gradient (using current w2, before update).
        let mut dhidden = [0.0_f32; HIDDEN];
        for i in 0..HIDDEN {
            let mut sum = 0.0;
            for v in 0..vocab_len {
                sum += self.w2[v * HIDDEN + i] * dlogits[v];
            }
            dhidden[i] = sum * (1.0 - pass.hidden[i] * pass.hidden[i]);
        }

        // Gradient w.r.t. the quantized code fed to the head (using current
        // w1). The straight-through estimator passes this straight back to
        // the spectral features.
        let mut dquant = [0.0_f32; FEAT];
        for f in 0..FEAT {
            let mut sum = 0.0;
            for i in 0..HIDDEN {
                sum += self.w1[i * FEAT + f] * dhidden[i];
            }
            dquant[f] = sum;
        }

        // Update the prediction head.
        for v in 0..vocab_len {
            for i in 0..HIDDEN {
                self.w2[v * HIDDEN + i] -= LEARNING_RATE * dlogits[v] * pass.hidden[i];
            }
            self.b2[v] -= LEARNING_RATE * dlogits[v];
        }
        for i in 0..HIDDEN {
            for f in 0..FEAT {
                self.w1[i * FEAT + f] -= LEARNING_RATE * dhidden[i] * pass.quant[f];
            }
            self.b1[i] -= LEARNING_RATE * dhidden[i];
        }

        // Each residual stage's codebook moves its chosen code toward that
        // stage's input residual; the commitment loss pulls the spectral
        // features toward the full reconstruction and joins the
        // straight-through gradient.
        let mut residual = pass.spectral.clone();
        for (stage, &code) in pass.codes.iter().enumerate() {
            let base = code * FEAT;
            for f in 0..FEAT {
                // Use the code value from the forward pass to advance the
                // residual, then move the code toward the residual it saw.
                let code_value = self.codebooks[stage][base + f];
                let toward = code_value - residual[f];
                self.codebooks[stage][base + f] -= LEARNING_RATE * COMMITMENT * 2.0 * toward;
                residual[f] -= code_value;
            }
        }

        let mut dspectral = [0.0_f32; FEAT];
        for f in 0..FEAT {
            dspectral[f] = dquant[f] + COMMITMENT * 2.0 * (pass.spectral[f] - pass.quant[f]);
        }

        // Backprop the spectral gradient through the (linear) DCT to the
        // embeddings: dEmbed[n][d] = sum_k dct[k][n] * dSpectral[k][d].
        let mut dembeds = [0.0_f32; CONTEXT * EMBED];
        for n in 0..CONTEXT {
            for d in 0..EMBED {
                let mut sum = 0.0;
                for k in 0..CONTEXT {
                    sum += self.dct[k * CONTEXT + n] * dspectral[k * EMBED + d];
                }
                dembeds[n * EMBED + d] = sum;
            }
        }
        for (step, &token) in context.iter().enumerate() {
            let base = token * EMBED;
            for d in 0..EMBED {
                self.embed[base + d] -= LEARNING_RATE * dembeds[step * EMBED + d];
            }
        }
    }

    /// Mean cross-entropy loss over `corpus` — used by tests to confirm the
    /// model actually learns.
    #[cfg(test)]
    #[must_use]
    fn mean_loss(&self, corpus: &str) -> f32 {
        let sentences = encode_sentences(&self.vocab, corpus);
        let mut total = 0.0;
        let mut steps = 0usize;
        for sentence in &sentences {
            for window in sentence.windows(CONTEXT + 1) {
                let mut context = [0usize; CONTEXT];
                context.copy_from_slice(&window[..CONTEXT]);
                let pass = self.forward(context);
                total += -(pass.probs[window[CONTEXT]].max(f32::MIN_POSITIVE)).ln();
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
        let pass = self.forward(context);
        pass.probs
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
            // Slide the temporal window forward by one token.
            for slot in 0..CONTEXT - 1 {
                context[slot] = context[slot + 1];
            }
            context[CONTEXT - 1] = next;
        }
        produced.join(" ")
    }

    fn perplexity(&self, text: &str) -> f32 {
        let sentences = encode_sentences(&self.vocab, text);
        let mut total = 0.0;
        let mut steps = 0usize;
        for sentence in &sentences {
            for window in sentence.windows(CONTEXT + 1) {
                let mut context = [0usize; CONTEXT];
                context.copy_from_slice(&window[..CONTEXT]);
                let pass = self.forward(context);
                total += -(pass.probs[window[CONTEXT]].max(f32::MIN_POSITIVE)).ln();
                steps += 1;
            }
        }
        if steps == 0 {
            return f32::INFINITY;
        }
        (total / count(steps)).exp()
    }
}

/// Index of the entry in `codebook` (a flat `CODES × FEAT` matrix) nearest
/// to `query` in squared Euclidean distance. Ties resolve to the lowest
/// index (deterministic).
#[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
fn nearest_code(codebook: &[f32], query: &[f32]) -> usize {
    let mut best = 0;
    let mut best_dist = f32::INFINITY;
    for c in 0..CODES {
        let mut dist = 0.0;
        for f in 0..FEAT {
            let diff = query[f] - codebook[c * FEAT + f];
            dist += diff * diff;
        }
        if dist < best_dist {
            best_dist = dist;
            best = c;
        }
    }
    best
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
    #[allow(clippy::suboptimal_flops)]
    fn dct_concentrates_a_constant_signal_in_the_zeroth_coefficient() {
        // DCT-II of a constant signal puts all energy in coefficient 0.
        let dct = dct_matrix();
        let signal = [2.0_f32; CONTEXT];
        let mut coeffs = [0.0_f32; CONTEXT];
        for k in 0..CONTEXT {
            let mut sum = 0.0;
            for n in 0..CONTEXT {
                sum += dct[k * CONTEXT + n] * signal[n];
            }
            coeffs[k] = sum;
        }
        assert!((coeffs[0] - 2.0 * count(CONTEXT)).abs() < 1e-4);
        for &c in &coeffs[1..] {
            assert!(c.abs() < 1e-3, "non-DC coefficient should be ~0, got {c}");
        }
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
    fn vector_quantization_uses_multiple_codes() {
        // A trained model should route different contexts to more than one
        // first-stage codebook entry (the VQ bottleneck is not collapsed).
        let model = NeuralLanguageModel::bundled();
        let sentences = encode_sentences(&model.vocab, SECURITY_CORPUS);
        let mut used = std::collections::HashSet::new();
        for sentence in &sentences {
            for window in sentence.windows(CONTEXT + 1) {
                let mut context = [0usize; CONTEXT];
                context.copy_from_slice(&window[..CONTEXT]);
                used.insert(model.forward(context).codes[0]);
            }
        }
        assert!(
            used.len() > 1,
            "expected multiple codes in use, got {}",
            used.len()
        );
    }

    #[test]
    fn nearest_code_picks_the_closest_codebook_entry() {
        let model = NeuralLanguageModel::bundled();
        // A query equal to code 3's first-stage vector must select code 3.
        let target = 3;
        let codebook = &model.codebooks[0];
        let query: Vec<f32> = codebook[target * FEAT..target * FEAT + FEAT].to_vec();
        assert_eq!(nearest_code(codebook, &query), target);
    }

    #[test]
    fn residual_quantization_lowers_error_and_loss() {
        // A second residual stage should reconstruct the spectral features
        // more accurately (lower quantization error) and, in turn, not
        // increase — and here reduce — the model's loss.
        let one = NeuralLanguageModel::trained_staged(SECURITY_CORPUS, EPOCHS, 1);
        let two = NeuralLanguageModel::trained_staged(SECURITY_CORPUS, EPOCHS, 2);

        // Average residual quantization error over the corpus.
        let quant_error = |model: &NeuralLanguageModel| -> f32 {
            let sentences = encode_sentences(&model.vocab, SECURITY_CORPUS);
            let mut total = 0.0;
            let mut steps = 0usize;
            for sentence in &sentences {
                for window in sentence.windows(CONTEXT + 1) {
                    let mut context = [0usize; CONTEXT];
                    context.copy_from_slice(&window[..CONTEXT]);
                    let (_, spectral) = model.spectral_features(context);
                    let (_, quant) = model.residual_quantize(&spectral);
                    total += spectral
                        .iter()
                        .zip(&quant)
                        .map(|(s, q)| (s - q) * (s - q))
                        .sum::<f32>();
                    steps += 1;
                }
            }
            total / count(steps.max(1))
        };

        assert!(
            quant_error(&two) < quant_error(&one),
            "residual VQ should reduce quantization error"
        );
        assert!(
            two.mean_loss(SECURITY_CORPUS) <= one.mean_loss(SECURITY_CORPUS) + 1e-3,
            "residual VQ should not worsen loss"
        );
    }

    #[test]
    fn generation_is_deterministic_and_in_vocabulary() {
        let model = NeuralLanguageModel::bundled();
        let first = model.generate("the coordinator plans an", 8);
        let second = model.generate("the coordinator plans an", 8);
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
        let out = model.generate("qqqq zzzz", 6);
        let vocab = Vocabulary::from_corpus(SECURITY_CORPUS);
        for token in out.split_whitespace() {
            assert!(vocab.id(token).is_some());
        }
        let _ = model.generate("", 4);
    }

    #[test]
    fn in_domain_text_has_lower_perplexity_than_gibberish() {
        let model = NeuralLanguageModel::bundled();
        let in_domain = model.perplexity("the policy engine denies out of scope targets");
        let gibberish = model.perplexity("targets scope of out denies engine policy the");
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
        let mut rng = Rng::new(SEED);
        for _ in 0..1000 {
            assert!((-0.3..0.3).contains(&rng.symmetric(0.3)));
        }
    }
}
