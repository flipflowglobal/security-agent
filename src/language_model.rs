//! A small, fully-local vector-quantized temporal-frequency neural language
//! model.
//!
//! This is a genuine (if tiny) neural language model with a deliberately
//! unusual architecture, and it stays true to the rest of the crate — **no
//! external crates, no network, no model weights on disk**. It trains
//! itself, deterministically, from a security-domain corpus compiled into
//! the binary ([`SECURITY_CORPUS`]).
//!
//! The prediction path is *self-attentive + temporal-frequency +
//! vector-quantized*:
//!
//! 1. **Embed** the recent window of [`CONTEXT`] tokens into learned
//!    vectors, giving a short multi-channel *time signal*
//!    (`CONTEXT` steps × [`EMBED`] channels).
//! 2. **Self-attend**: a single-head scaled dot-product attention layer
//!    lets every position in the window mix in every other position's
//!    value vector, weighted by a learned, *content-dependent* query/key
//!    match — unlike the fixed DCT below, what each position ends up
//!    representing depends on what is actually in the window, not just
//!    where. There's no causal mask: every position in `CONTEXT` is already
//!    known context for the token being predicted *after* the window, so
//!    positions may freely attend to each other. The attended output is
//!    added residually to the raw embeddings.
//! 3. **Temporal → frequency**: apply a Discrete Cosine Transform (DCT-II)
//!    along the time axis of each (now attention-mixed) channel, so the
//!    model reasons about *how* the context changes across the window (its
//!    spectral content) rather than the raw sequence.
//! 4. **Vector-quantize** the flattened spectral features against a learned
//!    codebook (VQ-VAE style, with a straight-through estimator and a
//!    commitment penalty), collapsing them to the nearest discrete code.
//! 5. **Predict** the next token from that quantized code through a tanh
//!    hidden layer and a softmax over the vocabulary.
//! 6. **Sample**: [`generate`](NeuralLanguageModel::generate) draws from
//!    that distribution with temperature and top-`k` filtering rather than
//!    always taking the most probable token, seeded deterministically from
//!    the prompt so the same prompt still always produces the same
//!    continuation.
//!
//! Training itself is two-phase. [`NeuralLanguageModel::bundled`] first runs
//! ordinary SGD (cross-entropy loss, backpropagated by hand end to end),
//! then hands the self-attention projections to
//! [`NeuralLanguageModel::lm_refine_attention`] — a hand-rolled
//! **Levenberg-Marquardt** pass. LM needs a genuine nonlinear
//! least-squares residual to operate on, which cross-entropy isn't, but
//! the model already has one sitting right there: the residual VQ
//! reconstruction error `‖spectral − quant‖²` from step 4. Fitting the
//! attention projections against *that* with a proper Gauss-Newton/trust-
//! region step (adaptive damping, a gain ratio gating each step) gives the
//! model's most content-sensitive layer a second-order polish that SGD's
//! fixed-step gradient descent can't match — without paying to run LM over
//! the whole (thousands-of-parameters) network, which the dense `JᵀJ`
//! it needs to form and invert would make computationally infeasible.
//!
//! Everything — the DCT, the codebook nearest-neighbor search, the
//! self-attention and Levenberg-Marquardt forward/backward passes, and a
//! deterministic `SplitMix64` RNG — is hand-rolled, so the whole model
//! ships inside the offline binary like every other capability here.
//! Being tiny, its text is modest; like the cognitive layer, it is
//! advisory and never affects authorization.

/// Strips the model's own `ChatML` markers from free-form text so user or tool
/// content can never break the turn structure (or impersonate another role).
#[must_use]
pub fn strip_chat_markers(text: &str) -> String {
    text.replace("<|im_start|>", "").replace("<|im_end|>", "")
}

/// Builds the `ChatML` prompt for a chat turn.
///
/// Prior `user`/`assistant` turns, an optional block of tool results (the
/// context the assistant can quote), and the current user message are joined,
/// ending with the assistant marker so the generated continuation *is* the
/// reply.
#[must_use]
pub fn chat_prompt(context: &str, turns: &[(String, String)], message: &str) -> String {
    let mut prompt = String::with_capacity(256 + context.len() + message.len());
    for (role, text) in turns {
        if role != "user" && role != "assistant" {
            continue;
        }
        prompt.push_str("<|im_start|>");
        prompt.push_str(role);
        prompt.push('\n');
        prompt.push_str(&strip_chat_markers(text));
        prompt.push_str("<|im_end|>\n");
    }
    if !context.trim().is_empty() {
        prompt.push_str("<|im_start|>user\nTool results from this session:\n");
        prompt.push_str(&strip_chat_markers(context));
        prompt.push_str("<|im_end|>\n");
    }
    prompt.push_str("<|im_start|>user\n");
    prompt.push_str(&strip_chat_markers(message));
    prompt.push_str("<|im_end|>\n<|im_start|>assistant\n");
    prompt
}

/// Anything that can continue a prompt and score how surprising text is.
/// Implemented by [`NeuralLanguageModel`]; kept as a trait so a larger
/// backend can be substituted without touching callers.
pub trait LanguageModel {
    /// Continues `prompt` for up to `max_tokens` tokens. Decoding samples
    /// with temperature and top-`k` filtering rather than always taking the
    /// most probable token, which avoids the short repetition loops greedy
    /// decoding falls into; it stays fully deterministic because the
    /// sampling RNG is seeded from `prompt`, so the same prompt always
    /// produces the same continuation.
    fn generate(&self, prompt: &str, max_tokens: usize) -> String;

    /// The model's perplexity on `text` — its average per-token surprise.
    /// Lower means the text looks more like what the model was trained on.
    fn perplexity(&self, text: &str) -> f32;

    /// Produces the assistant's reply to `message` given optional tool-result
    /// `context` and prior `turns` (each `(role, text)`, role `user` or
    /// `assistant`). The default builds the `ChatML` prompt and delegates to
    /// [`LanguageModel::generate`]; backends that wrap prompts internally
    /// (so a double wrap would confuse the model) override it.
    fn generate_chat(
        &self,
        context: &str,
        turns: &[(String, String)],
        message: &str,
        max_tokens: usize,
    ) -> String {
        let prompt = chat_prompt(context, turns, message);
        self.generate(&prompt, max_tokens)
    }
}

/// Number of previous tokens in the temporal window the model transforms.
const CONTEXT: usize = 4;
/// Embedding channels per token (the temporal signal's channel count).
const EMBED: usize = 10;
/// Flattened spectral-feature width (`CONTEXT` frequencies × `EMBED`
/// channels).
const FEAT: usize = CONTEXT * EMBED;
/// Number of entries in each vector-quantization codebook.
const CODES: usize = 56;
/// Number of residual quantization stages. Each stage quantizes the
/// residual the previous stage left behind (`q = q1 + q2 + ...`), a
/// residual path *through* the quantizer that shrinks quantization error and
/// recovers detail the discrete bottleneck would otherwise lose.
const VQ_STAGES: usize = 2;
/// Hidden-layer width of the prediction head. Widened alongside the corpus
/// scale-up: the extra capacity sharpens perplexity discrimination on the
/// larger, more varied training text without inflating `FEAT` (which is tied
/// to `EMBED`), so training cost stays moderate.
const HIDDEN: usize = 40;
/// Training passes over the corpus. The bundled model trains on the
/// hand-written corpus plus the generated catalog corpus (one sentence per
/// cataloged tool). Both have grown — more windows per epoch — so few epochs
/// reach ample total gradient exposure while keeping training fast. Held-out
/// perplexity discrimination and routing accuracy (see `crate::lm_eval`) stay
/// well above their floors at this count.
const EPOCHS: usize = 30;
/// SGD learning rate.
const LEARNING_RATE: f32 = 0.05;
/// Weight of the VQ commitment/codebook penalties.
const COMMITMENT: f32 = 0.25;
/// Deterministic seed for weight initialization.
const SEED: u64 = 0x5EC0_0DED_1234_5678;
/// Decoding temperature for [`generate`](NeuralLanguageModel::generate).
/// Applied as `probs.powf(1 / TEMPERATURE)` before top-`k` filtering and
/// renormalization — equivalent to dividing logits by `TEMPERATURE` before
/// softmax. Below 1, it sharpens the distribution toward the mode (closer
/// to greedy); above 1, it flattens it.
const TEMPERATURE: f32 = 0.7;
/// Only the `TOP_K` most probable next tokens are eligible to be sampled at
/// each decoding step; the long low-probability tail is discarded before
/// sampling so generation stays on-topic while still varying.
const TOP_K: usize = 8;

/// Learned parameters the Levenberg-Marquardt refinement pass (see
/// [`NeuralLanguageModel::lm_refine_attention`]) optimizes: the three
/// `EMBED * EMBED` self-attention projections, concatenated into one
/// parameter vector. Kept out of SGD's reach — LM is layered on top,
/// applied only to this small, well-posed sum-of-squares sub-problem.
const LM_PARAMS: usize = 3 * EMBED * EMBED;
/// Levenberg-Marquardt refinement iterations run on the attention
/// projections after SGD training completes.
const LM_ITERATIONS: usize = 3;
/// Initial LM damping scale: `mu0 = LM_TAU * max(diag(JtJ))`, the standard
/// Marquardt initialization heuristic.
const LM_TAU: f32 = 1e-3;
/// Only every `LM_WINDOW_STRIDE`th training window is used to build the LM
/// normal equations. Forming `JtJ` costs `O(LM_PARAMS^2)` per residual
/// component per window, so subsampling keeps each refinement pass fast
/// while still covering the corpus broadly.
const LM_WINDOW_STRIDE: usize = 12;

/// Sentence-boundary token (also used as left padding for the first tokens).
const BOS: &str = "<s>";
/// End-of-sentence token; generation stops when it is produced.
const EOS: &str = "</s>";
/// The single-character byte-fallback alphabet: every character
/// [`normalize`] can emit (ASCII lowercase letters and digits). Seeding
/// these into the vocabulary makes every normalized word representable, so
/// an out-of-vocabulary word decomposes into its characters instead of being
/// dropped before scoring.
const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789";

/// The percentile of the model's in-domain per-sentence perplexity taken as
/// the base of the self-calibrated anomaly threshold (see
/// [`NeuralLanguageModel::calibrate_anomaly_threshold`]). A high percentile is
/// robust to the heavy right tail a few unusual training sentences create —
/// unlike a mean-plus-k-sigma fit, whose sigma that tail inflates until the
/// threshold overshoots even gibberish.
const ANOMALY_CALIBRATION_PERCENTILE: f32 = 0.90;
/// Multiplier applied to that percentile to leave headroom above ordinary
/// in-domain surprise while staying far below out-of-vocabulary gibberish
/// (in-domain perplexity reaches the hundreds; gibberish, tens of thousands).
const ANOMALY_CALIBRATION_MARGIN: f32 = 6.0;
/// Lower bound for the calibrated threshold, so a degenerate corpus can never
/// drive it low enough to flag ordinary text.
const ANOMALY_THRESHOLD_FLOOR: f32 = 100.0;
/// Threshold used before calibration runs (or when there is nothing to
/// calibrate on). Matches the historical hand-tuned default.
const ANOMALY_THRESHOLD_FALLBACK: f32 = 1000.0;

/// Magic prefix of the serialized-weights blob format (see
/// [`NeuralLanguageModel::to_weight_bytes`]). Bumped if the layout changes so
/// an old blob is cleanly rejected instead of misread.
const WEIGHTS_MAGIC: &[u8; 8] = b"SAMDLW1\0";

/// The trained bundled model's weights, compiled into the binary. Generated
/// by `cargo run --example train_weights` and kept in sync with the training
/// code by a drift test (see this module's tests). [`NeuralLanguageModel::bundled`]
/// deserializes this instead of retraining; an empty or stale blob simply
/// triggers a from-scratch training fallback.
const BUNDLED_WEIGHTS: &[u8] = include_bytes!("model_weights.bin");

/// In-domain training text, compiled into the binary. Larger than a bare
/// minimum on purpose — broad enough to cover the agent's own vocabulary
/// (recon, web, cloud, mobile, network, social engineering, governance,
/// reporting) so both generation and the NLU router's
/// [`NeuralLanguageModel::embed_text`] space see more of the terms real
/// capability phrasings use. It deliberately includes finding-title-style
/// sentences ("a port scan detected an open service on a remote host") so the
/// model learns the structure of real finding text, which lifts word-level
/// coverage of realistic findings (see `crate::lm_eval`). It stays small
/// enough that training (SGD, deterministic, from scratch) remains fast.
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
the specialist maps techniques to approved tools within scope.
an assessment begins with passive reconnaissance of the authorized scope.
active scanning enumerates open ports and running services.
a vulnerability scanner correlates service versions with known exploits.
cross site scripting lets an attacker inject a script into a trusted page.
sql injection lets an attacker manipulate a backend database query.
server side request forgery tricks a server into fetching an internal resource.
an insecure direct object reference exposes a record the requester should not reach.
a container image scan flags outdated packages and known vulnerabilities.
a misconfigured storage bucket can leak sensitive customer data.
an exposed cloud metadata endpoint can hand an attacker temporary credentials.
a mobile application decompiled with jadx can reveal a hardcoded api key.
weak certificate pinning lets an attacker intercept mobile app traffic.
a phishing email is a common entry point for social engineering.
a suspicious login from an unfamiliar location can indicate account compromise.
anomalous outbound traffic often signals a compromised host.
malicious payloads are frequently obfuscated to evade static detection.
a weird or surprising string in a log line is worth a closer look.
the specialist drafts a finding with reproduction steps and evidence.
the coordinator can write a summary of the assessment for the client.
the agent will continue an incomplete report from the last checkpoint.
the report composes a narrative from every scored finding.
the operator can reschedule a retest when remediation slips.
every authorized action is written to the immutable audit ledger.
the governance layer requires explicit approval for a high impact technique.
the capability graph maps each technique to an approved tool.
the belief propagation model updates risk as new findings arrive.
calibration tracks whether the agent is overconfident or underconfident.
the intensity guard throttles requests to avoid disrupting production.
a deny listed target is refused before any scan begins.
network policy keeps the agent offline until the operator opts in.
compliance reporting maps findings to a recognized control framework.
the retest confirms whether a remediated finding has actually been fixed.
a port scan detected an open service on a remote host.
a service banner revealed the running version on an open port.
an exposed admin panel returned a login page without authentication.
a directory scan found a hidden git folder exposed on the staging host.
a subdomain enumeration discovered an unlisted host outside the inventory.
a web scan flagged an outdated plugin on the content management system.
a password spray attempted many logins against the exposed portal.
a decompiled application exposed an embedded key in the mobile binary.
a network capture revealed cleartext credentials traveling on the wire.
a certificate check reported an expired certificate on the login host.
a fuzzing run triggered an unhandled error in the request handler.
a directory listing exposed a backup archive on the public server.
a default credential granted access to the management console.
a verbose error message leaked a stack trace and an internal path.
an open redirect forwarded a victim to an attacker controlled domain.
a session token failed to expire after the user logged out.
a memory image analysis recovered artifacts of a running process.
a wireless capture recorded a handshake from a nearby access point.
a local privilege escalation abused a misconfigured service permission.
a supply chain review flagged an unpinned dependency with a known flaw.
an api endpoint returned another user record without an authorization check.
a rate limit was missing on the password reset endpoint.
a secret was committed to the repository history in plaintext.
a firewall rule allowed inbound traffic to an internal service.
the scanner ranks each open service by exposure and likely impact.
the operator reviews the evidence before the finding is confirmed.
the coordinator schedules the next wave once discovery completes.
discovery of a new host expands the authorized scan to reachable services.
the report groups related findings by affected host and severity.
a credential stuffing attempt reused leaked passwords against the login.
the specialist verifies a suspected vulnerability before reporting it.";

/// The full training corpus for the bundled model: the hand-written
/// [`SECURITY_CORPUS`] followed by the generated catalog corpus (one sentence
/// per cataloged tool, see [`crate::corpus_gen`]). Concatenated at runtime so
/// the two sources stay separately editable; the result is deterministic.
fn bundled_corpus() -> String {
    let mut corpus =
        String::with_capacity(SECURITY_CORPUS.len() + crate::corpus_gen::CATALOG_CORPUS.len() + 1);
    corpus.push_str(SECURITY_CORPUS);
    corpus.push('\n');
    corpus.push_str(crate::corpus_gen::CATALOG_CORPUS);
    corpus
}

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

    /// A uniform sample in `[0, 1)`.
    fn unit(&mut self) -> f32 {
        // Top 24 bits are an integer in [0, 2^24), exactly representable in
        // f32; dividing by 2^24 gives a unit value in [0, 1).
        const TWO_POW_24: f32 = 16_777_216.0;
        #[allow(clippy::cast_precision_loss)]
        let value = (self.next_u64() >> 40) as f32 / TWO_POW_24;
        value
    }

    /// A uniform sample in `[-scale, scale)`.
    fn symmetric(&mut self, scale: f32) -> f32 {
        self.unit().mul_add(2.0, -1.0) * scale
    }
}

/// A cheap, fully-deterministic string hash (FNV-1a), used to seed
/// [`generate`](NeuralLanguageModel::generate)'s per-call sampling RNG from
/// the prompt: the same prompt always draws the same sequence of samples,
/// while different prompts land on different (still reproducible) draws.
fn hash_prompt(prompt: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in prompt.as_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

/// `usize` -> `f32` for counts small enough to be exact here.
#[allow(clippy::cast_precision_loss)]
const fn count(value: usize) -> f32 {
    value as f32
}

/// Appends each `f32` of `values` as little-endian bytes.
fn write_f32_slice(out: &mut Vec<u8>, values: &[f32]) {
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Splits `count` bytes off the front of `cursor`, advancing it. `None` if
/// fewer than `count` bytes remain.
const fn take_bytes<'a>(cursor: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    if cursor.len() < count {
        return None;
    }
    let (head, tail) = cursor.split_at(count);
    *cursor = tail;
    Some(head)
}

/// Reads a little-endian `u32` off the front of `cursor`.
fn take_u32(cursor: &mut &[u8]) -> Option<u32> {
    let bytes = take_bytes(cursor, 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a little-endian `f32` off the front of `cursor`.
fn take_f32(cursor: &mut &[u8]) -> Option<f32> {
    let bytes = take_bytes(cursor, 4)?;
    Some(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads `len` little-endian `f32`s off the front of `cursor`.
fn take_f32_vec(cursor: &mut &[u8], len: usize) -> Option<Vec<f32>> {
    let bytes = take_bytes(cursor, len * 4)?;
    Some(
        bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect(),
    )
}

/// The `q`-quantile (`q` in `[0, 1]`) of an ascending-sorted, non-empty slice,
/// by nearest-rank. Deterministic and allocation-free.
fn percentile(sorted: &[f32], q: f32) -> f32 {
    let last = sorted.len() - 1;
    let rank = (q.clamp(0.0, 1.0) * count(last)).round();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let index = (rank as usize).min(last);
    sorted[index]
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
#[derive(Debug, Clone, PartialEq, Eq)]
struct Vocabulary {
    tokens: Vec<String>,
    ids: std::collections::HashMap<String, usize>,
    /// Per-id flag: whether the token is valid *generation output*. True for
    /// whole corpus words and [`EOS`]; false for [`BOS`] and the single
    /// character byte-fallback tokens, which exist only to encode unknown
    /// *input* and should never be emitted as raw characters. A character
    /// that also occurs as a standalone corpus word (e.g. `a`) is upgraded to
    /// emittable.
    emittable: Vec<bool>,
}

impl Vocabulary {
    fn from_corpus(corpus: &str) -> Self {
        // BOS is padding-only (never emitted); EOS is emittable so generation
        // can stop.
        let mut tokens = vec![BOS.to_string(), EOS.to_string()];
        let mut emittable = vec![false, true];
        let mut ids = std::collections::HashMap::new();
        ids.insert(BOS.to_string(), 0);
        ids.insert(EOS.to_string(), 1);
        // Seed the single-character byte-fallback alphabet before any corpus
        // word, so every character `normalize` can emit has a token. This is
        // what lets an out-of-vocabulary word decompose into characters
        // rather than being dropped (see [`Self::tokenize_word`]). The
        // alphabet is fixed and corpus-independent, so these ids are stable
        // across corpora. Characters are input-side fallback only, so they
        // start non-emittable.
        for ch in ALPHABET.chars() {
            let token = ch.to_string();
            if !ids.contains_key(&token) {
                ids.insert(token.clone(), tokens.len());
                tokens.push(token);
                emittable.push(false);
            }
        }
        for token in corpus.split_whitespace().filter_map(normalize) {
            if let Some(&id) = ids.get(&token) {
                // A character that also appears as a standalone word (e.g.
                // `a`) becomes a valid generation output.
                emittable[id] = true;
            } else {
                ids.insert(token.clone(), tokens.len());
                tokens.push(token);
                emittable.push(true);
            }
        }
        Self {
            tokens,
            ids,
            emittable,
        }
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

    /// Tokenizes one already-[`normalize`]d word: the word itself when the
    /// vocabulary knows it as a whole, otherwise its character byte-fallback.
    /// Because [`from_corpus`](Self::from_corpus) seeds every character
    /// [`normalize`] can produce, the fallback never drops anything — an
    /// unknown word always yields at least one token. An empty input yields
    /// no tokens.
    fn tokenize_word(&self, word: &str) -> Vec<usize> {
        if let Some(id) = self.id(word) {
            return vec![id];
        }
        word.chars()
            .filter_map(|ch| self.id(&ch.to_string()))
            .collect()
    }

    /// Whether `word` is a first-class whole-word token (as opposed to one
    /// that must fall back to characters). Used by the evaluation harness to
    /// measure word-level vocabulary coverage separately from the byte-level
    /// representability the fallback guarantees.
    fn knows_word(&self, word: &str) -> bool {
        self.id(word).is_some()
    }

    /// Whether the token `id` may be produced as generation output. Character
    /// byte-fallback tokens and [`BOS`] are input-only and return false.
    fn is_emittable(&self, id: usize) -> bool {
        self.emittable.get(id).copied().unwrap_or(false)
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
/// with `CONTEXT` leading [`BOS`] ids and a trailing [`EOS`] id. Words the
/// vocabulary does not know as a whole are decomposed into character tokens
/// by [`Vocabulary::tokenize_word`] rather than dropped, so no content is
/// silently lost before scoring or training.
fn encode_sentences(vocab: &Vocabulary, text: &str) -> Vec<Vec<usize>> {
    let bos = vocab.id(BOS).unwrap_or(0);
    let eos = vocab.id(EOS).unwrap_or(1);
    text.split('.')
        .filter_map(|sentence| {
            let mut ids: Vec<usize> = vec![bos; CONTEXT];
            for word in sentence.split_whitespace().filter_map(normalize) {
                ids.extend(vocab.tokenize_word(&word));
            }
            if ids.len() == CONTEXT {
                return None; // empty sentence
            }
            ids.push(eos);
            Some(ids)
        })
        .collect()
}

/// Intermediates from [`NeuralLanguageModel::self_attend`]'s forward pass,
/// retained so the backward pass can reuse them without recomputing.
struct Attention {
    /// Per-position query vectors, `CONTEXT * EMBED`.
    q: Vec<f32>,
    /// Per-position key vectors, `CONTEXT * EMBED`.
    k: Vec<f32>,
    /// Per-position value vectors, `CONTEXT * EMBED`.
    v: Vec<f32>,
    /// Row-`i` softmax attention weights, `CONTEXT * CONTEXT`:
    /// `weights[i * CONTEXT + j]` is how much position `i` attends to `j`.
    weights: Vec<f32>,
    /// Per-position attended output (the weighted mix of `v`), `CONTEXT *
    /// EMBED` — added residually to the raw embeddings before the DCT.
    attended: Vec<f32>,
}

/// Intermediates from a forward pass, retained so the backward pass can
/// reuse them.
struct Forward {
    /// Raw per-position token embeddings before attention, `CONTEXT *
    /// EMBED` — needed to backprop into both the attention projections and
    /// the token embedding table.
    embeds: Vec<f32>,
    /// The self-attention layer's forward intermediates.
    attn: Attention,
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
/// single-head self-attention over its context window and residual
/// (multi-stage) quantization.
#[derive(Debug, Clone, PartialEq)]
pub struct NeuralLanguageModel {
    vocab: Vocabulary,
    dct: Vec<f32>,            // CONTEXT * CONTEXT
    embed: Vec<f32>,          // vocab_len * EMBED
    attn_wq: Vec<f32>,        // EMBED * EMBED
    attn_wk: Vec<f32>,        // EMBED * EMBED
    attn_wv: Vec<f32>,        // EMBED * EMBED
    codebooks: Vec<Vec<f32>>, // stages × (CODES * FEAT)
    w1: Vec<f32>,             // HIDDEN * FEAT
    b1: Vec<f32>,             // HIDDEN
    w2: Vec<f32>,             // vocab_len * HIDDEN
    b2: Vec<f32>,             // vocab_len
    /// Self-calibrated anomaly threshold: the perplexity above which text is
    /// treated as out-of-domain, derived from this model's own in-domain
    /// perplexity distribution (see [`Self::calibrate_anomaly_threshold`])
    /// rather than a hand-tuned constant. Set after training.
    anomaly_threshold: f32,
}

impl Default for NeuralLanguageModel {
    fn default() -> Self {
        Self::bundled()
    }
}

impl NeuralLanguageModel {
    /// Builds and trains the default model on the bundled security corpus
    /// augmented with the catalog corpus, then polishes its self-attention
    /// projections with a Levenberg-Marquardt refinement pass (see
    /// [`Self::lm_refine_attention`]). Deterministic: the same binary always
    /// yields the same model.
    ///
    /// The catalog corpus ([`crate::corpus_gen::CATALOG_CORPUS`]) contributes
    /// one sentence per cataloged tool, so every tool name enters the model's
    /// vocabulary and the execution-class language is reinforced. It is
    /// appended only here; the `trained_*` constructors train on exactly the
    /// corpus they are given, keeping test baselines pure.
    ///
    /// Loading is memoized in a process-wide [`std::sync::OnceLock`] and
    /// subsequent calls return a clone. The bundled weights are deserialized
    /// from the compiled-in blob ([`BUNDLED_WEIGHTS`]) rather than retrained,
    /// so process start is fast and every platform runs byte-identical
    /// weights. If the blob is missing, malformed, or built for different
    /// dimensions, it falls back to training from scratch — always correct,
    /// just slower. [`Self::trained_on`] and [`Self::trained_staged`]
    /// deliberately skip the LM pass, so tests comparing epoch counts stay
    /// pure-SGD baselines.
    #[must_use]
    pub fn bundled() -> Self {
        static CACHED: std::sync::OnceLock<NeuralLanguageModel> = std::sync::OnceLock::new();
        CACHED
            .get_or_init(|| {
                Self::from_weight_bytes(BUNDLED_WEIGHTS).unwrap_or_else(Self::train_bundled)
            })
            .clone()
    }

    /// Trains the canonical bundled model from scratch: SGD on the combined
    /// corpus, the Levenberg-Marquardt attention refinement, then anomaly-
    /// threshold calibration. This is what [`BUNDLED_WEIGHTS`] is a serialized
    /// snapshot of; [`Self::bundled`] uses it only as a fallback.
    #[must_use]
    fn train_bundled() -> Self {
        let corpus = bundled_corpus();
        let mut model = Self::trained_on(&corpus, EPOCHS);
        model.lm_refine_attention(&corpus);
        // Re-calibrate after refinement, since the LM pass shifts the
        // perplexity distribution the threshold is derived from.
        model.anomaly_threshold = model.calibrate_anomaly_threshold(&corpus);
        model
    }

    /// Serializes the freshly-trained canonical model's weights into the blob
    /// format [`Self::from_weight_bytes`] reads. Used by the `train_weights`
    /// example to regenerate `src/model_weights.bin`; never on the hot path.
    #[must_use]
    pub fn bundled_weight_blob() -> Vec<u8> {
        Self::train_bundled().to_weight_bytes()
    }

    /// Serializes this model's learned parameters into the compact,
    /// dependency-free blob format. The vocabulary is *not* stored — it is
    /// deterministically rebuilt from the corpus on load — so only the header
    /// (dimensions, for validation), the calibrated threshold, and the weight
    /// tensors are written, each `f32` little-endian.
    #[must_use]
    fn to_weight_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(WEIGHTS_MAGIC);
        for dimension in [
            EMBED,
            HIDDEN,
            CONTEXT,
            CODES,
            self.codebooks.len(),
            self.vocab.len(),
        ] {
            let dimension = u32::try_from(dimension).expect("model dimension fits in u32");
            out.extend_from_slice(&dimension.to_le_bytes());
        }
        out.extend_from_slice(&self.anomaly_threshold.to_le_bytes());
        write_f32_slice(&mut out, &self.dct);
        write_f32_slice(&mut out, &self.embed);
        write_f32_slice(&mut out, &self.attn_wq);
        write_f32_slice(&mut out, &self.attn_wk);
        write_f32_slice(&mut out, &self.attn_wv);
        for codebook in &self.codebooks {
            write_f32_slice(&mut out, codebook);
        }
        write_f32_slice(&mut out, &self.w1);
        write_f32_slice(&mut out, &self.b1);
        write_f32_slice(&mut out, &self.w2);
        write_f32_slice(&mut out, &self.b2);
        out
    }

    /// Reconstructs a model from a [`Self::to_weight_bytes`] blob, rebuilding
    /// the vocabulary from the corpus. Returns `None` — so the caller can fall
    /// back to training — if the blob's magic, dimensions, rebuilt vocabulary
    /// size, or byte length do not match this build exactly.
    #[allow(clippy::similar_names)] // attn_wq / attn_wk / attn_wv mirror the fields
    fn from_weight_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cursor = bytes;
        if take_bytes(&mut cursor, WEIGHTS_MAGIC.len())? != WEIGHTS_MAGIC {
            return None;
        }
        let embed = take_u32(&mut cursor)? as usize;
        let hidden = take_u32(&mut cursor)? as usize;
        let context = take_u32(&mut cursor)? as usize;
        let codes = take_u32(&mut cursor)? as usize;
        let stages = take_u32(&mut cursor)? as usize;
        let vocab_len = take_u32(&mut cursor)? as usize;

        // Reject a blob built for a different architecture rather than
        // misinterpreting its bytes.
        if (embed, hidden, context, codes) != (EMBED, HIDDEN, CONTEXT, CODES) {
            return None;
        }
        let vocab = Vocabulary::from_corpus(&bundled_corpus());
        if vocab.len() != vocab_len {
            return None;
        }
        let feat = context * embed;

        let anomaly_threshold = take_f32(&mut cursor)?;
        let dct = take_f32_vec(&mut cursor, context * context)?;
        let embed_table = take_f32_vec(&mut cursor, vocab_len * embed)?;
        let attn_wq = take_f32_vec(&mut cursor, embed * embed)?;
        let attn_wk = take_f32_vec(&mut cursor, embed * embed)?;
        let attn_wv = take_f32_vec(&mut cursor, embed * embed)?;
        let mut codebooks = Vec::with_capacity(stages);
        for _ in 0..stages {
            codebooks.push(take_f32_vec(&mut cursor, codes * feat)?);
        }
        let w1 = take_f32_vec(&mut cursor, hidden * feat)?;
        let b1 = take_f32_vec(&mut cursor, hidden)?;
        let w2 = take_f32_vec(&mut cursor, vocab_len * hidden)?;
        let b2 = take_f32_vec(&mut cursor, vocab_len)?;

        // Any trailing bytes mean the blob does not match this layout.
        if !cursor.is_empty() {
            return None;
        }

        Some(Self {
            vocab,
            dct,
            embed: embed_table,
            attn_wq,
            attn_wk,
            attn_wv,
            codebooks,
            w1,
            b1,
            w2,
            b2,
            anomaly_threshold,
        })
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
            attn_wq: init(EMBED * EMBED, 0.3, &mut rng),
            attn_wk: init(EMBED * EMBED, 0.3, &mut rng),
            attn_wv: init(EMBED * EMBED, 0.3, &mut rng),
            codebooks,
            w1: init(HIDDEN * FEAT, 0.3, &mut rng),
            b1: vec![0.0; HIDDEN],
            w2: init(vocab_len * HIDDEN, 0.3, &mut rng),
            b2: vec![0.0; vocab_len],
            vocab,
            anomaly_threshold: ANOMALY_THRESHOLD_FALLBACK,
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
        // Calibrate the anomaly threshold against the trained model's own
        // in-domain perplexity distribution.
        model.anomaly_threshold = model.calibrate_anomaly_threshold(corpus);
        model
    }

    /// Mean-pooled embedding of `text` (a bag-of-embeddings sentence vector),
    /// length [`EMBED`]. Every word contributes: a known word through its
    /// whole-word embedding, an unknown word through the mean of its
    /// character embeddings (byte-fallback, see
    /// [`Vocabulary::tokenize_word`]), so out-of-vocabulary terms are no
    /// longer silently ignored. Zero vector only for empty or
    /// non-alphanumeric input. Used by the natural-language intent router to
    /// compare an instruction against capability descriptions in the model's
    /// learned semantic space.
    #[must_use]
    pub fn embed_text(&self, text: &str) -> Vec<f32> {
        let mut sum = vec![0.0_f32; EMBED];
        let mut n = 0usize;
        for word in text.split_whitespace().filter_map(normalize) {
            for id in self.vocab.tokenize_word(&word) {
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

    /// Whether `word` is a first-class whole-word vocabulary token rather
    /// than one that falls back to characters. Exposed for the evaluation
    /// harness's word-level coverage metric.
    #[must_use]
    pub fn knows_word(&self, word: &str) -> bool {
        normalize(word).is_some_and(|w| self.vocab.knows_word(&w))
    }

    /// The self-calibrated anomaly threshold: perplexity at or above which a
    /// string is out-of-domain enough to flag (see [`crate::anomaly`]).
    ///
    /// Derived from this model's own in-domain perplexity distribution rather
    /// than a hand-tuned constant, so it tracks the model automatically —
    /// corpus, tokenizer, or training changes that shift the perplexity scale
    /// no longer require re-tuning a magic number.
    #[must_use]
    pub const fn anomaly_threshold(&self) -> f32 {
        self.anomaly_threshold
    }

    /// Computes the anomaly threshold from the model's per-sentence perplexity
    /// over `corpus`, its notion of "normal" in-domain text.
    ///
    /// The threshold is a high percentile
    /// ([`ANOMALY_CALIBRATION_PERCENTILE`]) of the per-sentence perplexities,
    /// scaled by [`ANOMALY_CALIBRATION_MARGIN`]. A percentile is deliberately
    /// used instead of a mean-plus-k-sigma fit: perplexity is heavy-tailed, so
    /// a handful of unusually surprising training sentences inflate the
    /// standard deviation until the threshold overshoots even gibberish,
    /// whereas a percentile tracks the bulk of the distribution regardless of
    /// the tail. Floored by [`ANOMALY_THRESHOLD_FLOOR`] and falling back to
    /// [`ANOMALY_THRESHOLD_FALLBACK`] when the corpus yields no finite score.
    fn calibrate_anomaly_threshold(&self, corpus: &str) -> f32 {
        let mut perplexities: Vec<f32> = corpus
            .split('.')
            .map(str::trim)
            .filter(|sentence| !sentence.is_empty())
            .map(|sentence| self.perplexity(sentence))
            .filter(|p| p.is_finite() && *p > 0.0)
            .collect();

        if perplexities.is_empty() {
            return ANOMALY_THRESHOLD_FALLBACK;
        }

        perplexities.sort_by(f32::total_cmp);
        let base = percentile(&perplexities, ANOMALY_CALIBRATION_PERCENTILE);
        (base * ANOMALY_CALIBRATION_MARGIN).max(ANOMALY_THRESHOLD_FLOOR)
    }

    /// Looks up the raw per-position token embeddings for `context`,
    /// `CONTEXT * EMBED`, before self-attention mixes them.
    fn window_embeds(&self, context: [usize; CONTEXT]) -> Vec<f32> {
        let mut embeds = vec![0.0_f32; CONTEXT * EMBED];
        for (step, &token) in context.iter().enumerate() {
            let base = token * EMBED;
            embeds[step * EMBED..(step + 1) * EMBED]
                .copy_from_slice(&self.embed[base..base + EMBED]);
        }
        embeds
    }

    /// Single-head scaled dot-product self-attention over the `CONTEXT`
    /// window: each position's query is matched against every position's
    /// key (itself included — there's no causal mask, since every position
    /// here is already-known context for the token being predicted *after*
    /// the window), and the resulting softmax weights mix the value
    /// vectors. Unlike the fixed DCT downstream, this weighting is learned
    /// and *input-dependent*: which earlier positions matter most can
    /// change with what's actually in the window.
    #[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
    fn self_attend(&self, embeds: &[f32]) -> Attention {
        let mut q = vec![0.0_f32; CONTEXT * EMBED];
        let mut k = vec![0.0_f32; CONTEXT * EMBED];
        let mut v = vec![0.0_f32; CONTEXT * EMBED];
        for n in 0..CONTEXT {
            for out in 0..EMBED {
                let mut sq = 0.0;
                let mut sk = 0.0;
                let mut sv = 0.0;
                for inp in 0..EMBED {
                    let e = embeds[n * EMBED + inp];
                    sq += e * self.attn_wq[inp * EMBED + out];
                    sk += e * self.attn_wk[inp * EMBED + out];
                    sv += e * self.attn_wv[inp * EMBED + out];
                }
                q[n * EMBED + out] = sq;
                k[n * EMBED + out] = sk;
                v[n * EMBED + out] = sv;
            }
        }

        // Scaled dot-product scores, softmax-normalized per query row.
        let scale = 1.0 / count(EMBED).sqrt();
        let mut weights = vec![0.0_f32; CONTEXT * CONTEXT];
        for i in 0..CONTEXT {
            let mut scores = [0.0_f32; CONTEXT];
            for j in 0..CONTEXT {
                let mut dot = 0.0;
                for d in 0..EMBED {
                    dot += q[i * EMBED + d] * k[j * EMBED + d];
                }
                scores[j] = dot * scale;
            }
            softmax(&mut scores);
            weights[i * CONTEXT..(i + 1) * CONTEXT].copy_from_slice(&scores);
        }

        let mut attended = vec![0.0_f32; CONTEXT * EMBED];
        for i in 0..CONTEXT {
            for d in 0..EMBED {
                let mut sum = 0.0;
                for j in 0..CONTEXT {
                    sum += weights[i * CONTEXT + j] * v[j * EMBED + d];
                }
                attended[i * EMBED + d] = sum;
            }
        }

        Attention {
            q,
            k,
            v,
            weights,
            attended,
        }
    }

    /// Applies the DCT along the time axis of each channel of `combined`
    /// (the attention-mixed embeddings) to produce the flattened spectral
    /// features.
    // Flat-indexed spectral/matrix math reads more clearly as range loops
    // with `sum += a * b` than as iterator/`mul_add` rewrites.
    #[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
    fn dct_transform(&self, combined: &[f32]) -> Vec<f32> {
        // spectral[k*EMBED + d] = sum_n dct[k][n] * combined[n][d]
        let mut spectral = vec![0.0_f32; FEAT];
        for k in 0..CONTEXT {
            for d in 0..EMBED {
                let mut sum = 0.0;
                for n in 0..CONTEXT {
                    sum += self.dct[k * CONTEXT + n] * combined[n * EMBED + d];
                }
                spectral[k * EMBED + d] = sum;
            }
        }
        spectral
    }

    /// Embeds the temporal window, self-attends over it, and applies the
    /// DCT to the resulting (embed + attention) representation, producing
    /// the flattened spectral features. A convenience for callers that only
    /// need the final representation and the spectral features (tests
    /// comparing quantization quality); [`Self::forward`] calls the
    /// lower-level steps directly since training also needs the attention
    /// intermediates for backprop.
    #[cfg(test)]
    fn spectral_features(&self, context: [usize; CONTEXT]) -> (Vec<f32>, Vec<f32>) {
        let embeds = self.window_embeds(context);
        let attn = self.self_attend(&embeds);
        let mut combined = embeds;
        for (c, a) in combined.iter_mut().zip(&attn.attended) {
            *c += a;
        }
        let spectral = self.dct_transform(&combined);
        (combined, spectral)
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
        let embeds = self.window_embeds(context);
        let attn = self.self_attend(&embeds);
        let mut combined = embeds.clone();
        for (c, a) in combined.iter_mut().zip(&attn.attended) {
            *c += a;
        }
        let spectral = self.dct_transform(&combined);
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
            embeds,
            attn,
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
        // combined (embed + attention) representation:
        // dCombined[n][d] = sum_k dct[k][n] * dSpectral[k][d].
        let mut dcombined = [0.0_f32; CONTEXT * EMBED];
        for n in 0..CONTEXT {
            for d in 0..EMBED {
                let mut sum = 0.0;
                for k in 0..CONTEXT {
                    sum += self.dct[k * CONTEXT + n] * dspectral[k * EMBED + d];
                }
                dcombined[n * EMBED + d] = sum;
            }
        }

        // combined = embeds + attended, so the residual sends dCombined
        // straight through to both branches: directly to the token
        // embeddings below, and back through self-attention here.
        let mut dwq = [0.0_f32; EMBED * EMBED];
        let mut dwk = [0.0_f32; EMBED * EMBED];
        let mut dwv = [0.0_f32; EMBED * EMBED];
        let dembeds_from_attn = attend_backward(
            &pass.embeds,
            &pass.attn,
            &dcombined,
            &mut dwq,
            &mut dwk,
            &mut dwv,
            &self.attn_wq,
            &self.attn_wk,
            &self.attn_wv,
        );
        for i in 0..EMBED * EMBED {
            self.attn_wq[i] -= LEARNING_RATE * dwq[i];
            self.attn_wk[i] -= LEARNING_RATE * dwk[i];
            self.attn_wv[i] -= LEARNING_RATE * dwv[i];
        }

        for (step, &token) in context.iter().enumerate() {
            let base = token * EMBED;
            for d in 0..EMBED {
                let dembed = dcombined[step * EMBED + d] + dembeds_from_attn[step * EMBED + d];
                self.embed[base + d] -= LEARNING_RATE * dembed;
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

    /// Draws the next token id for `context` by temperature/top-`k`
    /// sampling: [`TEMPERATURE`]-sharpen the predicted distribution, keep
    /// only its [`TOP_K`] most probable tokens, then draw one proportionally
    /// to those (unnormalized) weights by scaling `rng`'s `[0, 1)` draw by
    /// their sum — equivalent to renormalizing them to probabilities first.
    /// Candidates are ranked by weight with token id as an explicit
    /// tie-breaker (`f32::total_cmp`, not `partial_cmp`), so ties and any
    /// stray `NaN` can't leave the ordering — and so the sampled token —
    /// dependent on sort stability. If floating-point rounding leaves a
    /// sliver of the draw unconsumed after the loop, or `probs` is somehow
    /// empty, this falls back to the top-ranked candidate (or token id `0`
    /// if there were none at all).
    fn sample_next(&self, context: [usize; CONTEXT], rng: &mut Rng) -> usize {
        let pass = self.forward(context);

        // Restrict sampling to emittable tokens: whole words and EOS. The
        // character byte-fallback tokens exist only to encode unknown input
        // and must never be generated as raw characters, which would derail
        // the continuation.
        let mut candidates: Vec<(usize, f32)> = pass
            .probs
            .iter()
            .enumerate()
            .filter(|&(id, _)| self.vocab.is_emittable(id))
            .map(|(id, &p)| (id, p.max(f32::MIN_POSITIVE).powf(1.0 / TEMPERATURE)))
            .collect();
        candidates.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        candidates.truncate(TOP_K.min(candidates.len()));

        let total: f32 = candidates.iter().map(|&(_, weight)| weight).sum();
        let mut draw = rng.unit() * total;
        for &(id, weight) in &candidates {
            if draw < weight {
                return id;
            }
            draw -= weight;
        }
        candidates.first().map_or(0, |&(id, _)| id)
    }

    /// Encodes `prompt` into an initial context of the last [`CONTEXT`]
    /// token ids, padding with [`BOS`] when the prompt is short. Unknown
    /// words fall back to character tokens (see
    /// [`Vocabulary::tokenize_word`]) rather than being dropped, so a prompt
    /// made only of out-of-vocabulary words still seeds a real context.
    fn seed_context(&self, prompt: &str) -> [usize; CONTEXT] {
        let bos = self.vocab.id(BOS).unwrap_or(0);
        let known: Vec<usize> = prompt
            .split_whitespace()
            .filter_map(normalize)
            .flat_map(|word| self.vocab.tokenize_word(&word))
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

    /// Flattens the three attention projection matrices into one
    /// [`LM_PARAMS`]-length parameter vector, in `wq, wk, wv` order.
    fn attn_params(&self) -> Vec<f32> {
        let mut params = Vec::with_capacity(LM_PARAMS);
        params.extend_from_slice(&self.attn_wq);
        params.extend_from_slice(&self.attn_wk);
        params.extend_from_slice(&self.attn_wv);
        params
    }

    /// Writes a flattened [`LM_PARAMS`]-length parameter vector (as
    /// produced by [`Self::attn_params`]) back into the three attention
    /// projection matrices.
    fn set_attn_params(&mut self, params: &[f32]) {
        let n = EMBED * EMBED;
        self.attn_wq.copy_from_slice(&params[..n]);
        self.attn_wk.copy_from_slice(&params[n..2 * n]);
        self.attn_wv.copy_from_slice(&params[2 * n..]);
    }

    /// A deterministic, strided sample of `corpus`'s training windows
    /// (every [`LM_WINDOW_STRIDE`]th one), used as the residual set for
    /// Levenberg-Marquardt refinement.
    fn lm_sample_windows(&self, corpus: &str) -> Vec<[usize; CONTEXT]> {
        let sentences = encode_sentences(&self.vocab, corpus);
        sentences
            .iter()
            .flat_map(|sentence| sentence.windows(CONTEXT + 1))
            .step_by(LM_WINDOW_STRIDE)
            .map(|window| {
                let mut context = [0usize; CONTEXT];
                context.copy_from_slice(&window[..CONTEXT]);
                context
            })
            .collect()
    }

    /// Sum of squared residuals `||spectral - quant||^2` over `windows` —
    /// the Levenberg-Marquardt objective `F(w)` — without building the
    /// Jacobian. Used to cheaply evaluate a trial step.
    fn lm_sum_squared_residual(&self, windows: &[[usize; CONTEXT]]) -> f32 {
        let mut sse = 0.0_f32;
        for &context in windows {
            let embeds = self.window_embeds(context);
            let attn = self.self_attend(&embeds);
            let mut combined = embeds;
            for (c, a) in combined.iter_mut().zip(&attn.attended) {
                *c += a;
            }
            let spectral = self.dct_transform(&combined);
            let (_, quant) = self.residual_quantize(&spectral);
            sse += spectral
                .iter()
                .zip(&quant)
                .map(|(s, q)| (s - q) * (s - q))
                .sum::<f32>();
        }
        sse
    }

    /// Builds the Gauss-Newton normal-equation accumulators for the
    /// nonlinear least-squares problem this Levenberg-Marquardt pass
    /// solves: minimize `sum_over_windows ||spectral(attn) - quant||^2`
    /// over the attention projection parameters, treating each window's
    /// `quant` (its VQ codebook reconstruction) as a fixed local target —
    /// consistent with the straight-through treatment the rest of training
    /// already gives the discrete VQ bottleneck.
    ///
    /// Row `f` of the (never fully materialized) Jacobian, for residual
    /// component `f` of a window, is obtained by backpropagating a one-hot
    /// seed at `spectral[f]` through the (linear) DCT and then through
    /// [`attend_backward`] — the same machinery [`Self::forward`]'s
    /// training step uses, reused here as a vector-Jacobian-product
    /// primitive instead of a scalar-loss gradient.
    ///
    /// Returns `(JtJ, Jtr, sse)`: `JtJ` is `LM_PARAMS * LM_PARAMS`
    /// (row-major), `Jtr` is length `LM_PARAMS`, `sse` is the total sum of
    /// squared residuals (`F(w)`).
    #[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
    fn lm_normal_equations(&self, windows: &[[usize; CONTEXT]]) -> (Vec<f32>, Vec<f32>, f32) {
        let mut jtj = vec![0.0_f32; LM_PARAMS * LM_PARAMS];
        let mut jtr = vec![0.0_f32; LM_PARAMS];
        let mut sse = 0.0_f32;

        for &context in windows {
            let embeds = self.window_embeds(context);
            let attn = self.self_attend(&embeds);
            let mut combined = embeds.clone();
            for (c, a) in combined.iter_mut().zip(&attn.attended) {
                *c += a;
            }
            let spectral = self.dct_transform(&combined);
            let (_, quant) = self.residual_quantize(&spectral);

            let mut residual = [0.0_f32; FEAT];
            for f in 0..FEAT {
                residual[f] = spectral[f] - quant[f];
                sse += residual[f] * residual[f];
            }

            for f in 0..FEAT {
                // One-hot seed at spectral[f], backpropagated through the
                // linear DCT to get the matching seed on `combined`.
                let mut dspectral = [0.0_f32; FEAT];
                dspectral[f] = 1.0;
                let mut dcombined = [0.0_f32; CONTEXT * EMBED];
                for n in 0..CONTEXT {
                    for d in 0..EMBED {
                        let mut sum = 0.0;
                        for k in 0..CONTEXT {
                            sum += self.dct[k * CONTEXT + n] * dspectral[k * EMBED + d];
                        }
                        dcombined[n * EMBED + d] = sum;
                    }
                }

                let mut dwq = [0.0_f32; EMBED * EMBED];
                let mut dwk = [0.0_f32; EMBED * EMBED];
                let mut dwv = [0.0_f32; EMBED * EMBED];
                attend_backward(
                    &embeds,
                    &attn,
                    &dcombined,
                    &mut dwq,
                    &mut dwk,
                    &mut dwv,
                    &self.attn_wq,
                    &self.attn_wk,
                    &self.attn_wv,
                );

                let mut row = [0.0_f32; LM_PARAMS];
                let n = EMBED * EMBED;
                row[..n].copy_from_slice(&dwq);
                row[n..2 * n].copy_from_slice(&dwk);
                row[2 * n..].copy_from_slice(&dwv);

                let r = residual[f];
                for a in 0..LM_PARAMS {
                    jtr[a] += row[a] * r;
                    for b in a..LM_PARAMS {
                        jtj[a * LM_PARAMS + b] += row[a] * row[b];
                    }
                }
            }
        }

        // JtJ is symmetric; only the upper triangle was accumulated above.
        for a in 0..LM_PARAMS {
            for b in 0..a {
                jtj[a * LM_PARAMS + b] = jtj[b * LM_PARAMS + a];
            }
        }

        (jtj, jtr, sse)
    }

    /// Refines the self-attention projections (`attn_wq`, `attn_wk`,
    /// `attn_wv`) with a hand-rolled Levenberg-Marquardt pass, minimizing
    /// the residual VQ reconstruction error `||spectral - quant||^2` over a
    /// sample of `corpus`'s training windows — a genuine nonlinear
    /// least-squares problem, unlike the cross-entropy prediction loss SGD
    /// trains against.
    ///
    /// Standard trust-region LM: each iteration solves the damped normal
    /// equations `h = -(JtJ + mu*I)^-1 * Jtr` for a trial step, accepts it
    /// only if the *actual* error reduction tracks the *quadratic model's
    /// predicted* reduction closely enough (the gain ratio `q`), and
    /// shrinks the damping `mu` on a good step or grows it on a bad one —
    /// so it behaves like Gauss-Newton (fast) near a good fit and like
    /// gradient descent (safe) when the local quadratic model is
    /// untrustworthy. Because a step is only ever kept when it actually
    /// reduced the sum of squared residuals, this method can only leave
    /// `sse` the same or lower than where it started, never higher.
    #[allow(clippy::needless_range_loop, clippy::suboptimal_flops)]
    pub fn lm_refine_attention(&mut self, corpus: &str) {
        let windows = self.lm_sample_windows(corpus);
        if windows.is_empty() {
            return;
        }

        let mut mu: Option<f32> = None;
        let mut v = 2.0_f32;

        for _ in 0..LM_ITERATIONS {
            let (jtj, jtr, sse) = self.lm_normal_equations(&windows);
            let damping = *mu.get_or_insert_with(|| {
                LM_TAU
                    * (0..LM_PARAMS)
                        .map(|i| jtj[i * LM_PARAMS + i])
                        .fold(f32::MIN_POSITIVE, f32::max)
            });

            let Some(h) = solve_damped(&jtj, &jtr, damping, LM_PARAMS) else {
                // Numerically singular: treat like a failed step.
                mu = Some(damping * v);
                v *= 2.0;
                continue;
            };
            let h: Vec<f32> = h.iter().map(|value| -value).collect();

            // L(0) - L(h), from the quadratic model of Definition 2: the
            // predicted error reduction for this step.
            let mut jtj_h = vec![0.0_f32; LM_PARAMS];
            for a in 0..LM_PARAMS {
                let mut sum = 0.0;
                for b in 0..LM_PARAMS {
                    sum += jtj[a * LM_PARAMS + b] * h[b];
                }
                jtj_h[a] = sum;
            }
            let h_dot_jtr: f32 = h.iter().zip(&jtr).map(|(hi, gi)| hi * gi).sum();
            let h_jtj_h: f32 = h.iter().zip(&jtj_h).map(|(hi, ji)| hi * ji).sum();
            // jtr = J^T r is the gradient of 0.5*sse (not raw sse), and jtj
            // is the matching Gauss-Newton approximation to its Hessian, so
            // this predicted reduction is in 0.5*sse units too — `actual`
            // below must match, or the gain ratio q is systematically
            // wrong by a factor of ~2.
            let predicted = -(h_dot_jtr + 0.5 * h_jtj_h);

            // Swap the trial params into self to score them (cheaper than
            // cloning the whole model — vocab, embed table, codebooks —
            // just to evaluate three small attention matrices), restoring
            // the originals below if the step is rejected.
            let params = self.attn_params();
            let trial: Vec<f32> = params.iter().zip(&h).map(|(p, hi)| p + hi).collect();
            self.set_attn_params(&trial);
            let trial_sse = self.lm_sum_squared_residual(&windows);

            let actual = 0.5 * (sse - trial_sse);
            let q = if predicted.abs() > f32::MIN_POSITIVE {
                actual / predicted
            } else {
                0.0
            };

            if q > 0.0 {
                // Trial params are already in place; keep them.
                mu = Some(damping * (1.0_f32 / 3.0).max(1.0 - (2.0 * q - 1.0).powi(3)));
                v = 2.0;
            } else {
                self.set_attn_params(&params);
                mu = Some(damping * v);
                v *= 2.0;
            }
        }
    }
}

impl LanguageModel for NeuralLanguageModel {
    fn generate(&self, prompt: &str, max_tokens: usize) -> String {
        let bos = self.vocab.id(BOS).unwrap_or(0);
        let eos = self.vocab.id(EOS).unwrap_or(1);
        let mut context = self.seed_context(prompt);
        let mut produced = Vec::new();
        // Seeded from the prompt so the same prompt always draws the same
        // sequence of samples, while different prompts land on different
        // (still reproducible) draws.
        let mut rng = Rng::new(SEED ^ hash_prompt(prompt));

        for _ in 0..max_tokens {
            let next = self.sample_next(context, &mut rng);
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

/// Backprop through [`NeuralLanguageModel::self_attend`]. Given `dattended`
/// (the loss gradient w.r.t. `attn.attended`), accumulates the query/key/
/// value projection-weight gradients into `dwq`/`dwk`/`dwv` (each `EMBED *
/// EMBED`, added in place so a caller can zero them once and reuse the same
/// buffers) and returns the gradient w.r.t. `embeds` flowing back through
/// the attention branch. A free function (not a method) so it can borrow
/// `wq`/`wk`/`wv` immutably while the caller still holds `&mut self`.
#[allow(
    clippy::needless_range_loop,
    clippy::suboptimal_flops,
    clippy::too_many_arguments
)]
fn attend_backward(
    embeds: &[f32],
    attn: &Attention,
    dattended: &[f32],
    dwq: &mut [f32],
    dwk: &mut [f32],
    dwv: &mut [f32],
    wq: &[f32],
    wk: &[f32],
    wv: &[f32],
) -> [f32; CONTEXT * EMBED] {
    let scale = 1.0 / count(EMBED).sqrt();

    // dV[j] = sum_i weights[i][j] * dAttended[i]
    let mut dv = [0.0_f32; CONTEXT * EMBED];
    for i in 0..CONTEXT {
        for j in 0..CONTEXT {
            let w = attn.weights[i * CONTEXT + j];
            for d in 0..EMBED {
                dv[j * EMBED + d] += w * dattended[i * EMBED + d];
            }
        }
    }

    // dWeights[i][j] = dAttended[i] . V[j]
    let mut dweights = [0.0_f32; CONTEXT * CONTEXT];
    for i in 0..CONTEXT {
        for j in 0..CONTEXT {
            let mut dot = 0.0;
            for d in 0..EMBED {
                dot += dattended[i * EMBED + d] * attn.v[j * EMBED + d];
            }
            dweights[i * CONTEXT + j] = dot;
        }
    }

    // Backprop each row's softmax: dScores[i][j] = w_ij * (dWeights_ij -
    // sum_k w_ik * dWeights_ik).
    let mut dscores = [0.0_f32; CONTEXT * CONTEXT];
    for i in 0..CONTEXT {
        let mut dot = 0.0;
        for j in 0..CONTEXT {
            dot += attn.weights[i * CONTEXT + j] * dweights[i * CONTEXT + j];
        }
        for j in 0..CONTEXT {
            let w = attn.weights[i * CONTEXT + j];
            dscores[i * CONTEXT + j] = w * (dweights[i * CONTEXT + j] - dot);
        }
    }

    // scores[i][j] = (Q[i] . K[j]) * scale
    let mut dq = [0.0_f32; CONTEXT * EMBED];
    let mut dk = [0.0_f32; CONTEXT * EMBED];
    for i in 0..CONTEXT {
        for j in 0..CONTEXT {
            let ds = dscores[i * CONTEXT + j] * scale;
            for d in 0..EMBED {
                dq[i * EMBED + d] += ds * attn.k[j * EMBED + d];
                dk[j * EMBED + d] += ds * attn.q[i * EMBED + d];
            }
        }
    }

    // Q/K/V[n] = embeds[n] . W{q,k,v}: accumulate the projection-weight
    // gradients and propagate back to embeds.
    let mut dembeds = [0.0_f32; CONTEXT * EMBED];
    for n in 0..CONTEXT {
        for out in 0..EMBED {
            let grad_q = dq[n * EMBED + out];
            let grad_k = dk[n * EMBED + out];
            let grad_v = dv[n * EMBED + out];
            for inp in 0..EMBED {
                let e = embeds[n * EMBED + inp];
                dwq[inp * EMBED + out] += e * grad_q;
                dwk[inp * EMBED + out] += e * grad_k;
                dwv[inp * EMBED + out] += e * grad_v;
                dembeds[n * EMBED + inp] += grad_q * wq[inp * EMBED + out]
                    + grad_k * wk[inp * EMBED + out]
                    + grad_v * wv[inp * EMBED + out];
            }
        }
    }
    dembeds
}

/// Solves `(A + mu*I) x = b` for `x` via Gauss-Jordan elimination with
/// partial pivoting, where `A` is `n * n` (row-major, symmetric — as `JtJ`
/// always is) and `b` has length `n`. Returns `None` if the system is
/// numerically singular (a pivot too close to zero after the best
/// available row swap), in which case the caller should treat the step as
/// failed rather than trust a garbage solution.
#[allow(clippy::needless_range_loop)]
fn solve_damped(a: &[f32], b: &[f32], mu: f32, n: usize) -> Option<Vec<f32>> {
    // Augmented [A + mu*I | b] matrix, row-major, n rows by (n + 1) columns.
    let mut aug = vec![0.0_f32; n * (n + 1)];
    for i in 0..n {
        for j in 0..n {
            aug[i * (n + 1) + j] = a[i * n + j];
        }
        aug[i * (n + 1) + i] += mu;
        aug[i * (n + 1) + n] = b[i];
    }

    for col in 0..n {
        let mut pivot_row = col;
        let mut pivot_val = aug[col * (n + 1) + col].abs();
        for row in (col + 1)..n {
            let val = aug[row * (n + 1) + col].abs();
            if val > pivot_val {
                pivot_val = val;
                pivot_row = row;
            }
        }
        if pivot_val < 1e-10 {
            return None;
        }
        if pivot_row != col {
            for k in 0..=n {
                aug.swap(col * (n + 1) + k, pivot_row * (n + 1) + k);
            }
        }

        let pivot = aug[col * (n + 1) + col];
        for k in 0..=n {
            aug[col * (n + 1) + k] /= pivot;
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = aug[row * (n + 1) + col];
            if factor == 0.0 {
                continue;
            }
            for k in 0..=n {
                aug[row * (n + 1) + k] -= factor * aug[col * (n + 1) + k];
            }
        }
    }

    Some((0..n).map(|i| aug[i * (n + 1) + n]).collect())
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
    fn weight_blob_round_trips_exactly() {
        let model = NeuralLanguageModel::bundled();
        let bytes = model.to_weight_bytes();
        let restored =
            NeuralLanguageModel::from_weight_bytes(&bytes).expect("round-trip must deserialize");
        assert_eq!(model, restored, "serialize -> deserialize must be lossless");
    }

    #[test]
    fn from_weight_bytes_rejects_malformed_input() {
        assert!(NeuralLanguageModel::from_weight_bytes(b"").is_none());
        assert!(NeuralLanguageModel::from_weight_bytes(b"not a weights blob").is_none());
        // Correct magic but truncated body.
        assert!(NeuralLanguageModel::from_weight_bytes(WEIGHTS_MAGIC).is_none());
    }

    #[test]
    fn bundled_loads_from_the_committed_blob() {
        // The blob must be present and valid so the fast path is actually
        // taken; otherwise bundled() silently falls back to slow training.
        assert!(
            NeuralLanguageModel::from_weight_bytes(BUNDLED_WEIGHTS).is_some(),
            "committed weights blob failed to load — regenerate with \
             `cargo run --release --example train_weights > src/model_weights.bin`",
        );
    }

    // Deterministic training is only *bit-identical* to the committed blob on
    // the exact platform the blob was generated on: the f32 transcendentals it
    // drives (`exp`/`tanh`/`cos`/`powf`/`sqrt`) differ by a few ULPs across
    // glibc versions and CPU microarchitectures, and SGD amplifies those
    // differences. The check below therefore compares every learned tensor
    // with a cross-libm tolerance instead of exact equality. Empirically the
    // whole-tensor worst case across environments is < 1e-3 (~8e-4), while a
    // genuine corpus/architecture/hyperparameter change shifts the training
    // trajectory far past 1e-2 — so the tolerance catches real staleness yet
    // ignores cross-environment numerical noise.
    //
    // The check is also opt-in: it only runs when `SECURITY_AGENT_WEIGHT_DRIFT`
    // is set (CI sets it), so a plain `cargo test` on any machine stays green
    // and skips the comparatively expensive training pass unless a maintainer
    // explicitly asks for it. Every platform still loads and validates the
    // same canonical blob via `bundled_loads_from_the_committed_blob` and the
    // functional tests.
    #[cfg(target_os = "linux")]
    const WEIGHT_DRIFT_TOL: f32 = 1e-2;
    // The self-calibrated anomaly threshold is a large-magnitude derived value
    // (hundreds–thousands), so it is checked with a relative tolerance.
    #[cfg(target_os = "linux")]
    const THRESHOLD_DRIFT_REL_TOL: f32 = 1e-2;

    /// Largest absolute element-wise difference between two equal-length
    /// tensors, or `f32::INFINITY` if their lengths differ (a structural
    /// mismatch the caller should surface as staleness).
    #[cfg(target_os = "linux")]
    fn max_abs_diff(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return f32::INFINITY;
        }
        a.iter()
            .zip(b)
            .map(|(x, y)| (x - y).abs())
            .fold(0.0_f32, f32::max)
    }

    // The committed blob is the single canonical set of weights every platform
    // loads. This drift check asserts that the committed blob still matches a
    // freshly trained model to within cross-libm numerical tolerance, so it
    // catches a stale blob (corpus/architecture/hyperparameter change without
    // regeneration) without failing merely because CI's libm differs by a few
    // ULP from the machine that generated the blob.
    #[cfg(target_os = "linux")]
    #[test]
    fn committed_weights_match_a_freshly_trained_model() {
        if std::env::var_os("SECURITY_AGENT_WEIGHT_DRIFT").is_none() {
            eprintln!(
                "skipping weight-drift check (float training is not bit-reproducible \
                 across machines); set SECURITY_AGENT_WEIGHT_DRIFT=1 to run it on the \
                 canonical platform after changing training code",
            );
            return;
        }
        let trained = NeuralLanguageModel::train_bundled();
        let loaded = NeuralLanguageModel::from_weight_bytes(BUNDLED_WEIGHTS)
            .expect("committed weights blob must load");

        let stale = "src/model_weights.bin is stale — regenerate with \
             `cargo run --release --example train_weights > src/model_weights.bin`";

        // Vocabulary is structural, not numerical: any drift means the corpus
        // (and therefore the model dimensions) changed and the blob is stale.
        assert_eq!(trained.vocab, loaded.vocab, "vocabulary drift — {stale}");
        assert_eq!(
            trained.codebooks.len(),
            loaded.codebooks.len(),
            "codebook-stage count drift — {stale}"
        );

        // Every learned tensor, compared element-wise; codebook stages are
        // appended so residual-quantizer drift is covered too.
        let mut tensors: Vec<(&'static str, &[f32], &[f32])> = vec![
            ("dct", &trained.dct, &loaded.dct),
            ("embed", &trained.embed, &loaded.embed),
            ("attn_wq", &trained.attn_wq, &loaded.attn_wq),
            ("attn_wk", &trained.attn_wk, &loaded.attn_wk),
            ("attn_wv", &trained.attn_wv, &loaded.attn_wv),
            ("w1", &trained.w1, &loaded.w1),
            ("b1", &trained.b1, &loaded.b1),
            ("w2", &trained.w2, &loaded.w2),
            ("b2", &trained.b2, &loaded.b2),
        ];
        for (a, b) in trained.codebooks.iter().zip(&loaded.codebooks) {
            tensors.push(("codebook", a, b));
        }

        let mut worst = 0.0_f32;
        let mut worst_where = "";
        for (name, a, b) in tensors {
            let d = max_abs_diff(a, b);
            if d > worst {
                worst = d;
                worst_where = name;
            }
        }

        assert!(
            worst <= WEIGHT_DRIFT_TOL,
            "weight drift {worst:.6} in `{worst_where}` exceeds tolerance \
             {WEIGHT_DRIFT_TOL} — {stale}",
        );

        let denom = loaded.anomaly_threshold.abs().max(1e-6);
        let rel = (trained.anomaly_threshold - loaded.anomaly_threshold).abs() / denom;
        assert!(
            rel <= THRESHOLD_DRIFT_REL_TOL,
            "anomaly-threshold drift {rel:.6} (trained {t}, committed {c}) exceeds \
             relative tolerance {THRESHOLD_DRIFT_REL_TOL} — {stale}",
            t = trained.anomaly_threshold,
            c = loaded.anomaly_threshold,
        );
    }

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
        // more accurately *relative to their own scale* and, in turn, not
        // increase — and here reduce — the model's loss.
        //
        // `one` and `two` are independently-trained models (different
        // codebook depth changes how freely the embeddings can spread out
        // to separate a large vocabulary for prediction), so their raw
        // spectral magnitudes differ and an unnormalized squared error is
        // not comparable between them. Dividing by the spectral energy
        // gives the fraction of signal the quantizer leaves unexplained,
        // which is what "reconstructs more accurately" actually means here.
        let one = NeuralLanguageModel::trained_staged(SECURITY_CORPUS, EPOCHS, 1);
        let two = NeuralLanguageModel::trained_staged(SECURITY_CORPUS, EPOCHS, 2);

        // Relative residual quantization error over the corpus: unexplained
        // energy divided by total spectral energy.
        let relative_quant_error = |model: &NeuralLanguageModel| -> f32 {
            let sentences = encode_sentences(&model.vocab, SECURITY_CORPUS);
            let mut error = 0.0;
            let mut energy = 0.0;
            for sentence in &sentences {
                for window in sentence.windows(CONTEXT + 1) {
                    let mut context = [0usize; CONTEXT];
                    context.copy_from_slice(&window[..CONTEXT]);
                    let (_, spectral) = model.spectral_features(context);
                    let (_, quant) = model.residual_quantize(&spectral);
                    error += spectral
                        .iter()
                        .zip(&quant)
                        .map(|(s, q)| (s - q) * (s - q))
                        .sum::<f32>();
                    energy += spectral.iter().map(|s| s * s).sum::<f32>();
                }
            }
            error / energy.max(f32::MIN_POSITIVE)
        };

        assert!(
            relative_quant_error(&two) < relative_quant_error(&one),
            "residual VQ should reduce relative quantization error"
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
        assert_eq!(first, second, "sampling must be deterministic per prompt");

        // The bundled model trains on the combined corpus, so its vocabulary
        // (and therefore its emittable tokens) includes catalog tool names.
        let vocab = Vocabulary::from_corpus(&bundled_corpus());
        for token in first.split_whitespace() {
            assert!(
                vocab.id(token).is_some(),
                "generated token '{token}' must be in the vocabulary"
            );
        }
    }

    #[test]
    fn generate_is_deterministic_across_several_distinct_prompts() {
        // A guaranteed invariant (unlike asserting distinct prompts produce
        // distinct output, which isn't guaranteed — e.g. two prompts could
        // both hit EOS immediately): the prompt-seeded sampling RNG must
        // make every one of these prompts individually reproducible.
        let model = NeuralLanguageModel::bundled();
        for prompt in [
            "the coordinator plans an",
            "a phishing email is",
            "calibration measures",
            "a container image scan",
        ] {
            assert_eq!(model.generate(prompt, 12), model.generate(prompt, 12));
        }
    }

    #[test]
    fn sample_next_can_diverge_from_the_greedy_pick() {
        let model = NeuralLanguageModel::bundled();
        // A sentence-start context (all padding) spreads probability across
        // many sentence openers, so the next-token distribution is flat enough
        // that sampling reliably diverges from the top pick on every platform.
        // A peaked mid-sentence context can, under different float rounding,
        // leave the top token dominant enough that no seed diverges.
        let context = model.seed_context("");
        let pass = model.forward(context);
        // Greedy over the tokens `sample_next` can actually emit, so the
        // comparison matches the candidate set sampling draws from.
        let greedy = pass
            .probs
            .iter()
            .enumerate()
            .filter(|&(id, _)| model.vocab.is_emittable(id))
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(0, |(id, _)| id);

        let diverged = (0..256u64).any(|seed| {
            let mut rng = Rng::new(seed);
            model.sample_next(context, &mut rng) != greedy
        });
        assert!(
            diverged,
            "temperature/top-k sampling should sometimes pick a token other than the greedy one"
        );
    }

    #[test]
    fn sample_next_never_leaves_the_vocabulary() {
        let model = NeuralLanguageModel::bundled();
        let context = model.seed_context("a container image scan");
        let mut rng = Rng::new(SEED);
        for _ in 0..200 {
            let id = model.sample_next(context, &mut rng);
            assert!(id < model.vocab.len());
        }
    }

    #[test]
    fn self_attend_weights_are_a_softmax_per_query_row() {
        let model = NeuralLanguageModel::bundled();
        let embeds = model.window_embeds(model.seed_context("the coordinator plans an"));
        let attn = model.self_attend(&embeds);
        for i in 0..CONTEXT {
            let row = &attn.weights[i * CONTEXT..(i + 1) * CONTEXT];
            let sum: f32 = row.iter().sum();
            assert!((sum - 1.0).abs() < 1e-5, "row {i} sums to {sum}, not 1");
            assert!(row.iter().all(|&w| (0.0..=1.0).contains(&w)));
        }
    }

    #[test]
    fn training_updates_the_attention_projection_weights() {
        // attn_wq/wk/wv start from the same random (not uniform) init
        // regardless of training, so comparing a trained model's attention
        // *output* to a uniform distribution wouldn't prove training moved
        // anything — it could hold from the random init alone. Compare the
        // projection weights themselves before and after training instead:
        // if the backward pass wires up correctly, gradient descent must
        // move them from their zero-epoch starting point.
        let untrained = NeuralLanguageModel::trained_on(SECURITY_CORPUS, 0);
        let trained = NeuralLanguageModel::trained_on(SECURITY_CORPUS, EPOCHS);
        let moved = |before: &[f32], after: &[f32]| {
            before.iter().zip(after).any(|(b, a)| (b - a).abs() > 1e-4)
        };
        assert!(
            moved(&untrained.attn_wq, &trained.attn_wq)
                && moved(&untrained.attn_wk, &trained.attn_wk)
                && moved(&untrained.attn_wv, &trained.attn_wv),
            "training should move every attention projection away from its random initialization"
        );
    }

    /// Verifies [`attend_backward`]'s hand-derived gradients against
    /// central finite differences on an arbitrary scalar loss
    /// `dot(attended, dattended)` for a fixed random `dattended` — the
    /// strongest available check that the backprop math (softmax Jacobian,
    /// scaled dot-product, and the three projections) is actually correct,
    /// not just that it compiles and the surrounding training loop happens
    /// to converge.
    #[test]
    fn attend_backward_matches_finite_differences() {
        const EPS: f32 = 1e-3;
        const TOL: f32 = 5e-2;

        let model = NeuralLanguageModel::trained_on(SECURITY_CORPUS, 5);
        let embeds = model.window_embeds(model.seed_context("the coordinator plans an"));

        let mut rng = Rng::new(0xABCD_EF01_2345_6789);
        let dattended: Vec<f32> = (0..CONTEXT * EMBED).map(|_| rng.symmetric(1.0)).collect();

        // L(embeds, wq, wk, wv) = dot(self_attend(embeds).attended, dattended).
        let loss = |model: &NeuralLanguageModel, embeds: &[f32]| -> f32 {
            model
                .self_attend(embeds)
                .attended
                .iter()
                .zip(&dattended)
                .map(|(a, d)| a * d)
                .sum()
        };

        let attn = model.self_attend(&embeds);
        let mut dwq = [0.0_f32; EMBED * EMBED];
        let mut dwk = [0.0_f32; EMBED * EMBED];
        let mut dwv = [0.0_f32; EMBED * EMBED];
        let dembeds = attend_backward(
            &embeds,
            &attn,
            &dattended,
            &mut dwq,
            &mut dwk,
            &mut dwv,
            &model.attn_wq,
            &model.attn_wk,
            &model.attn_wv,
        );

        let assert_close = |numeric: f32, analytic: f32, label: &str| {
            assert!(
                (numeric - analytic).abs() < TOL,
                "{label}: numeric={numeric:.5} analytic={analytic:.5}"
            );
        };

        // Spot-check a handful of entries (first, middle, last) across each
        // gradient path rather than every one, to keep the test fast while
        // still exercising query, key, value, and the input branch.
        for &idx in &[0usize, 3, EMBED * EMBED - 1] {
            let mut plus = model.clone();
            plus.attn_wq[idx] += EPS;
            let mut minus = model.clone();
            minus.attn_wq[idx] -= EPS;
            let numeric = (loss(&plus, &embeds) - loss(&minus, &embeds)) / (2.0 * EPS);
            assert_close(numeric, dwq[idx], "wq");

            let mut plus = model.clone();
            plus.attn_wk[idx] += EPS;
            let mut minus = model.clone();
            minus.attn_wk[idx] -= EPS;
            let numeric = (loss(&plus, &embeds) - loss(&minus, &embeds)) / (2.0 * EPS);
            assert_close(numeric, dwk[idx], "wk");

            let mut plus = model.clone();
            plus.attn_wv[idx] += EPS;
            let mut minus = model.clone();
            minus.attn_wv[idx] -= EPS;
            let numeric = (loss(&plus, &embeds) - loss(&minus, &embeds)) / (2.0 * EPS);
            assert_close(numeric, dwv[idx], "wv");
        }

        for &idx in &[0usize, EMBED, CONTEXT * EMBED - 1] {
            let mut plus_embeds = embeds.clone();
            plus_embeds[idx] += EPS;
            let mut minus_embeds = embeds.clone();
            minus_embeds[idx] -= EPS;
            let numeric = (loss(&model, &plus_embeds) - loss(&model, &minus_embeds)) / (2.0 * EPS);
            assert_close(numeric, dembeds[idx], "embeds");
        }
    }

    #[test]
    fn solve_damped_matches_a_known_system() {
        // 3x3 SPD system with mu = 0 (an exact, undamped solve): A x = b,
        // A = [[4,1,1],[1,3,1],[1,1,2]], chosen so x = [1, 2, -1] exactly.
        let a = [4.0_f32, 1.0, 1.0, 1.0, 3.0, 1.0, 1.0, 1.0, 2.0];
        let x_expected = [1.0_f32, 2.0, -1.0];
        let mut b = [0.0_f32; 3];
        for i in 0..3 {
            for j in 0..3 {
                b[i] = a[i * 3 + j].mul_add(x_expected[j], b[i]);
            }
        }
        let x = solve_damped(&a, &b, 0.0, 3).expect("well-posed system should solve");
        for (got, want) in x.iter().zip(&x_expected) {
            assert!((got - want).abs() < 1e-3, "got {x:?}, want {x_expected:?}");
        }
    }

    #[test]
    fn solve_damped_reports_a_singular_system() {
        // A rank-deficient 2x2 (second row is a multiple of the first),
        // undamped: no unique solution.
        let a = [1.0_f32, 2.0, 2.0, 4.0];
        let b = [1.0_f32, 2.0];
        assert!(solve_damped(&a, &b, 0.0, 2).is_none());
    }

    #[test]
    fn lm_normal_equations_jtr_matches_finite_differences() {
        // Jtr = J^T r is the gradient of 0.5 * sse w.r.t. the attention
        // parameters; check it against central finite differences on
        // lm_sum_squared_residual, the strongest available check that the
        // one-hot-seeded DCT/attend_backward reuse inside
        // lm_normal_equations actually builds a correct Jacobian, not just
        // one that compiles and happens to make lm_refine_attention behave
        // reasonably.
        const EPS: f32 = 1e-3;
        const TOL: f32 = 5e-1;

        let model = NeuralLanguageModel::trained_on(SECURITY_CORPUS, 5);
        let windows = model.lm_sample_windows(SECURITY_CORPUS);
        let windows = &windows[..windows.len().min(3)];

        let (_, jtr, _) = model.lm_normal_equations(windows);
        let params = model.attn_params();

        for &idx in &[0usize, EMBED * EMBED, 2 * EMBED * EMBED + 3, LM_PARAMS - 1] {
            let mut plus = model.clone();
            let mut plus_params = params.clone();
            plus_params[idx] += EPS;
            plus.set_attn_params(&plus_params);

            let mut minus = model.clone();
            let mut minus_params = params.clone();
            minus_params[idx] -= EPS;
            minus.set_attn_params(&minus_params);

            let sse_plus = plus.lm_sum_squared_residual(windows);
            let sse_minus = minus.lm_sum_squared_residual(windows);
            let numeric = 0.5 * (sse_plus - sse_minus) / (2.0 * EPS);
            assert!(
                (numeric - jtr[idx]).abs() < TOL,
                "param {idx}: numeric={numeric:.4} jtr={:.4}",
                jtr[idx]
            );
        }
    }

    #[test]
    fn lm_refine_attention_never_increases_reconstruction_error() {
        let mut model = NeuralLanguageModel::trained_on(SECURITY_CORPUS, 5);
        let windows = model.lm_sample_windows(SECURITY_CORPUS);
        let before = model.lm_sum_squared_residual(&windows);

        model.lm_refine_attention(SECURITY_CORPUS);

        let after = model.lm_sum_squared_residual(&windows);
        assert!(
            after <= before + 1e-3,
            "LM refinement should never leave reconstruction error higher: before={before:.4} after={after:.4}"
        );
        assert!(
            after < before,
            "expected at least one accepted LM step to improve on a lightly-trained model: before={before:.4} after={after:.4}"
        );
    }

    #[test]
    fn lm_refine_attention_keeps_weights_finite() {
        let mut model = NeuralLanguageModel::trained_on(SECURITY_CORPUS, 5);
        model.lm_refine_attention(SECURITY_CORPUS);
        for value in model
            .attn_wq
            .iter()
            .chain(&model.attn_wk)
            .chain(&model.attn_wv)
        {
            assert!(
                value.is_finite(),
                "attention weight went non-finite: {value}"
            );
        }
    }

    #[test]
    fn generation_handles_unknown_and_empty_prompts() {
        let model = NeuralLanguageModel::bundled();
        let out = model.generate("qqqq zzzz", 6);
        // Compare against the model's actual training vocabulary (the combined
        // corpus), which includes catalog tool names the model may emit.
        let vocab = Vocabulary::from_corpus(&bundled_corpus());
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
    fn calibrated_anomaly_threshold_separates_in_domain_from_gibberish() {
        let model = NeuralLanguageModel::bundled();
        let threshold = model.anomaly_threshold();

        assert!(
            threshold >= ANOMALY_THRESHOLD_FLOOR,
            "threshold {threshold:.1} must respect the floor {ANOMALY_THRESHOLD_FLOOR:.1}",
        );
        for text in [
            "the policy engine denies out of scope targets",
            "static analysis surfaces injection and unsafe deserialization bugs",
            "the audit ledger records every authorized action",
        ] {
            assert!(
                model.perplexity(text) < threshold,
                "in-domain text should sit below the calibrated threshold ({threshold:.1}): {text}",
            );
        }
        for text in ["zzq xqv vfrb qwx ncbz", "qwph jklzx mbvpre ttghre plfwqz"] {
            assert!(
                model.perplexity(text) >= threshold,
                "gibberish should sit at or above the calibrated threshold ({threshold:.1}): {text}",
            );
        }
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

    #[test]
    fn hash_prompt_is_deterministic_and_distinguishes_prompts() {
        assert_eq!(
            hash_prompt("the coordinator plans an"),
            hash_prompt("the coordinator plans an")
        );
        assert_ne!(
            hash_prompt("the coordinator plans an"),
            hash_prompt("a phishing email is")
        );
    }
}
