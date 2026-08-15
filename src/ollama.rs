//! Ollama HTTP client.
//!
//! Integrates the locally-running [Ollama](https://ollama.com) service
//! (v0.32+) over its native HTTP API, exposed through the dedicated
//! `--ollama-status`, `--ollama-generate`, and `--ollama-chat` commands.
//!
//! It deliberately does **not** implement [`crate::language_model::LanguageModel`]:
//! Ollama's HTTP endpoints expose no per-token log-probabilities, so no honest
//! perplexity exists, and failures must surface as hard errors rather than be
//! swallowed into empty continuations.
//!
//! **Design constraints (matching the crate's zero-external-dependency
//! invariant for runtime crates):**
//!
//! * HTTP is spoken over a raw [`std::net::TcpStream`] — no `reqwest`, no
//!   `hyper`, no `ureq`.
//! * JSON is parsed with the in-house [`crate::json`] parser.
//! * No async runtime: all I/O is blocking (Ollama responds in one shot for
//!   the non-streaming generate endpoint).
//!
//! **Offline-first / network-gating invariant:**
//!
//! Ollama lives on `localhost`, so it does not open egress to the public
//! internet; however, any socket activity is considered "network" by the
//! agent's policy. Callers **must** check [`NetworkMode::allows_active`]
//! before constructing an [`OllamaClient`] and pass an explicit
//! `allow_network: bool` parameter to every entry point. The constructor
//! returns [`OllamaError::NetworkNotAllowed`] when the flag is `false`.
//!
//! **Supported Ollama API surface:**
//!
//! * `POST /api/generate` — non-streaming prompt continuation
//!   ([`OllamaClient::generate_raw`]).
//! * `POST /api/chat` — non-streaming chat completion
//!   ([`OllamaClient::chat`]).
//! * `GET  /api/tags` — model list ([`OllamaClient::list_models`]).
//! * `GET  /api/version` — version probe ([`OllamaClient::version`]).

use crate::json::JsonValue;
use std::fmt;
use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors that can occur when communicating with the Ollama service.
#[derive(Debug)]
pub enum OllamaError {
    /// The caller did not pass `--allow-network`; no socket was opened.
    NetworkNotAllowed,
    /// A TCP connection or I/O error.
    Io(String),
    /// The HTTP response carried a non-2xx status code.
    Http(u16, String),
    /// The response body was not valid JSON or was missing expected fields.
    Parse(String),
}

impl fmt::Display for OllamaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkNotAllowed => write!(
                formatter,
                "Ollama requires --allow-network (it opens a local socket)"
            ),
            Self::Io(message) => write!(formatter, "ollama I/O error: {message}"),
            Self::Http(status, body) => {
                write!(formatter, "ollama HTTP {status}: {body}")
            }
            Self::Parse(message) => write!(formatter, "ollama response parse error: {message}"),
        }
    }
}

impl std::error::Error for OllamaError {}

// ────────────────────────────────────────────────────────────────────────────
// Chat message types (mirrors Ollama's `message` object)
// ────────────────────────────────────────────────────────────────────────────

/// A single turn in a chat conversation.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// `"system"`, `"user"`, or `"assistant"`.
    pub role: String,
    /// The message text.
    pub content: String,
}

impl ChatMessage {
    /// Builds a `"user"` message.
    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
        }
    }

    /// Builds a `"system"` message.
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
        }
    }

    /// Builds an `"assistant"` message.
    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
        }
    }

    /// Renders this message as a JSON object string.
    fn to_json(&self) -> String {
        format!(
            "{{\"role\":{},\"content\":{}}}",
            json_string(&self.role),
            json_string(&self.content)
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Model info (from /api/tags)
// ────────────────────────────────────────────────────────────────────────────

/// One entry from `GET /api/tags`.
#[derive(Debug, Clone)]
pub struct OllamaModel {
    /// The model tag, e.g. `"llama3.2:latest"`.
    pub name: String,
    /// Disk size in bytes.
    pub size: u64,
}

// ────────────────────────────────────────────────────────────────────────────
// Client
// ────────────────────────────────────────────────────────────────────────────

/// Blocking HTTP client for a locally-running Ollama service.
///
/// Construction succeeds only when `allow_network` is `true`.
///
/// Connections are opened lazily per request; construction does not attempt to
/// connect to the service and does not validate the address beyond storing the
/// provided `host:port` string.
/// The default address is `127.0.0.1:11434` matching Ollama's default.
#[derive(Debug, Clone)]
pub struct OllamaClient {
    /// Model tag to use for `/api/generate` and `/api/chat` requests.
    model: String,
    timeout: Duration,
}

impl OllamaClient {
    /// The default Ollama listen address.
    pub const DEFAULT_ADDR: &'static str = "127.0.0.1:11434";
    /// Default socket timeout (5 minutes — enough for large local models).
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

    /// Creates a client that talks to Ollama at `addr` with the given model.
    ///
    /// # Errors
    ///
    /// Returns [`OllamaError::NetworkNotAllowed`] when `allow_network` is
    /// `false` — the caller must pass `--allow-network` to unlock any Ollama
    /// integration.
    pub fn new(
        addr: impl Into<String>,
        model: impl Into<String>,
        allow_network: bool,
    ) -> Result<Self, OllamaError> {
        if !allow_network {
            return Err(OllamaError::NetworkNotAllowed);
        }
        Ok(Self {
            addr: addr.into(),
            model: model.into(),
            timeout: Self::DEFAULT_TIMEOUT,
        })
    }

    /// Convenience constructor using the default address and timeout.
    ///
    /// # Errors
    ///
    /// Returns [`OllamaError::NetworkNotAllowed`] when `allow_network` is
    /// `false`.
    pub fn default_addr(
        model: impl Into<String>,
        allow_network: bool,
    ) -> Result<Self, OllamaError> {
        Self::new(Self::DEFAULT_ADDR, model, allow_network)
    }

    /// The model tag this client was built for.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The address this client connects to.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Override the socket read/write timeout (default: 5 minutes).
    #[must_use]
    // The body mutates `self` (field write), so this cannot be const despite
    // what the `missing_const_for_fn` lint suggests.
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    // ── Low-level HTTP helpers ────────────────────────────────────────────

    /// Opens a fresh TCP connection to the Ollama service. Each request gets
    /// its own connection because Ollama serves HTTP/1.1 without keep-alive
    /// on the generate endpoints.
    fn connect(&self) -> Result<TcpStream, OllamaError> {
        let stream =
            TcpStream::connect(&self.addr).map_err(|error| OllamaError::Io(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| OllamaError::Io(error.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|error| OllamaError::Io(error.to_string()))?;
        Ok(stream)
    }

    /// Sends a raw HTTP request and reads back the complete response body.
    ///
    /// - `method` is `"GET"` or `"POST"`.
    /// - `path` is e.g. `"/api/generate"`.
    /// - `body` is the (already serialised) JSON body for POST; `None` for GET.
    fn http_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<String, OllamaError> {
        let mut stream = self.connect()?;
        let host = &self.addr;

        // Build HTTP/1.1 request.
        let mut request = String::with_capacity(512);
        // Use write! (FmtWrite) to avoid intermediate allocations from format!.
        let _ = write!(request, "{method} {path} HTTP/1.1\r\n");
        let _ = write!(request, "Host: {host}\r\n");
        request.push_str("Connection: close\r\n");
        if let Some(json_body) = body {
            request.push_str("Content-Type: application/json\r\n");
            let _ = write!(request, "Content-Length: {}\r\n", json_body.len());
            request.push_str("\r\n");
            request.push_str(json_body);
        } else {
            request.push_str("\r\n");
        }

        stream
            .write_all(request.as_bytes())
            .map_err(|error| OllamaError::Io(error.to_string()))?;

        // Read response.
        let mut reader = BufReader::new(stream);

        // --- status line ---
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|error| OllamaError::Io(error.to_string()))?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // --- headers ---
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        loop {
            let mut header_line = String::new();
            reader
                .read_line(&mut header_line)
                .map_err(|error| OllamaError::Io(error.to_string()))?;
            let trimmed = header_line.trim();
            if trimmed.is_empty() {
                break; // blank line → end of headers
            }
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                content_length = lower
                    .trim_start_matches("content-length:")
                    .trim()
                    .parse()
                    .ok();
            } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
        }

        // --- body ---
        let response_body = if chunked {
            read_chunked_body(&mut reader)?
        } else if let Some(length) = content_length {
            let mut buf = vec![0_u8; length];
            reader
                .read_exact(&mut buf)
                .map_err(|error| OllamaError::Io(error.to_string()))?;
            String::from_utf8_lossy(&buf).into_owned()
        } else {
            // No content-length and not chunked — read until EOF (e.g. GET
            // /api/version with Connection: close).
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .map_err(|error| OllamaError::Io(error.to_string()))?;
            String::from_utf8_lossy(&buf).into_owned()
        };

        if !(200..300).contains(&status) {
            return Err(OllamaError::Http(status, response_body));
        }
        Ok(response_body)
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Probes Ollama's `/api/version` endpoint and returns the version string
    /// (e.g. `"0.32.9"`).
    ///
    /// # Errors
    ///
    /// Returns [`OllamaError::Io`] when the service is unreachable, or
    /// [`OllamaError::Parse`] when the version field is absent.
    pub fn version(&self) -> Result<String, OllamaError> {
        let body = self.http_request("GET", "/api/version", None)?;
        let value = crate::json::parse(&body)
            .ok_or_else(|| OllamaError::Parse("invalid JSON from /api/version".to_string()))?;
        value
            .get("version")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
            .ok_or_else(|| OllamaError::Parse("missing 'version' field".to_string()))
    }

    /// Lists installed models via `GET /api/tags`.
    ///
    /// # Errors
    ///
    /// Returns [`OllamaError`] on I/O or parse failure.
    pub fn list_models(&self) -> Result<Vec<OllamaModel>, OllamaError> {
        let body = self.http_request("GET", "/api/tags", None)?;
        let value = crate::json::parse(&body)
            .ok_or_else(|| OllamaError::Parse("invalid JSON from /api/tags".to_string()))?;
        let models_value = value
            .get("models")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| OllamaError::Parse("missing 'models' array".to_string()))?;
        let mut models = Vec::with_capacity(models_value.len());
        for entry in models_value {
            let name = entry
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string();
            let size = entry.get("size").and_then(JsonValue::as_u64).unwrap_or(0);
            models.push(OllamaModel { name, size });
        }
        Ok(models)
    }

    /// Generates a completion for `prompt` via `POST /api/generate`.
    ///
    /// Uses the non-streaming endpoint (`stream: false`), so the full
    /// response arrives in one HTTP response body.
    ///
    /// # Errors
    ///
    /// Returns [`OllamaError`] on I/O, HTTP, or parse failure.
    pub fn generate_raw(&self, prompt: &str, max_tokens: usize) -> Result<String, OllamaError> {
        let json_body = format!(
            "{{\"model\":{},\"prompt\":{},\"stream\":false,\"options\":{{\"num_predict\":{}}}}}",
            json_string(&self.model),
            json_string(prompt),
            max_tokens,
        );
        let body = self.http_request("POST", "/api/generate", Some(&json_body))?;
        extract_generate_response(&body)
    }

    /// Sends a multi-turn chat request via `POST /api/chat`.
    ///
    /// Uses the non-streaming endpoint (`stream: false`). Returns the
    /// assistant's reply text.
    ///
    /// # Errors
    ///
    /// Returns [`OllamaError`] on I/O, HTTP, or parse failure.
    pub fn chat(&self, messages: &[ChatMessage], max_tokens: usize) -> Result<String, OllamaError> {
        let messages_json: Vec<String> = messages.iter().map(ChatMessage::to_json).collect();
        let json_body = format!(
            "{{\"model\":{},\"messages\":[{}],\"stream\":false,\"options\":{{\"num_predict\":{}}}}}",
            json_string(&self.model),
            messages_json.join(","),
            max_tokens,
        );
        let body = self.http_request("POST", "/api/chat", Some(&json_body))?;
        extract_chat_response(&body)
    }
}

// ── LanguageModel integration ────────────────────────────────────────────────

// NOTE: `OllamaClient` deliberately does NOT implement [`LanguageModel`].
// That trait promises both prompt continuation *and* perplexity scoring, and
// Ollama's HTTP API exposes no per-token log-probabilities through the
// endpoints we use, so no honest perplexity value exists. Pretending to score
// text with a constant would be fake work, and silently swallowing a failed
// `generate` into an empty string would hide real errors. Ollama is instead
// reached through its own commands (`--ollama-status`, `--ollama-generate`,
// `--ollama-chat`), which surface every failure as a hard error.

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// JSON-encodes a string with correct escaping: the five mandatory escapes
/// (`"`, `\`, `\n`, `\r`, `\t`) plus a `\u00XX` escape for every other
/// control character, which JSON forbids as raw bytes.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Extracts the generated text from an `/api/generate` response body.
///
/// The non-streaming response is a single JSON object with the text in the
/// `"response"` field. Some servers ignore `stream:false` and return NDJSON
/// (one object per token); we concatenate the `response` fields of each line.
fn extract_generate_response(body: &str) -> Result<String, OllamaError> {
    if let Some(value) = crate::json::parse(body) {
        if let Some(text) = value.get("response").and_then(JsonValue::as_str) {
            return Ok(text.to_owned());
        }
    }
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = crate::json::parse(line) {
            if let Some(text) = value.get("response").and_then(JsonValue::as_str) {
                out.push_str(text);
            }
        }
    }
    if out.is_empty() {
        Err(OllamaError::Parse(
            "no 'response' field in generate response".to_string(),
        ))
    } else {
        Ok(out)
    }
}

/// Extracts the assistant reply from an `/api/chat` response body.
///
/// Single-object form: `{"message":{"role":"assistant","content":"..."},...}`.
/// NDJSON fallback concatenates each line's `message.content` field.
fn extract_chat_response(body: &str) -> Result<String, OllamaError> {
    if let Some(value) = crate::json::parse(body) {
        if let Some(content) = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(JsonValue::as_str)
        {
            return Ok(content.to_owned());
        }
    }
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = crate::json::parse(line) {
            if let Some(content) = value
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(JsonValue::as_str)
            {
                out.push_str(content);
            }
        }
    }
    if out.is_empty() {
        Err(OllamaError::Parse(
            "no 'message.content' field in chat response".to_string(),
        ))
    } else {
        Ok(out)
    }
}

/// Reads an HTTP/1.1 chunked-encoded body from `reader`.
fn read_chunked_body(reader: &mut impl BufRead) -> Result<String, OllamaError> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        reader
            .read_line(&mut size_line)
            .map_err(|error| OllamaError::Io(error.to_string()))?;
        let chunk_size = usize::from_str_radix(size_line.trim(), 16)
            .map_err(|_| OllamaError::Parse("invalid chunk size".to_string()))?;
        if chunk_size == 0 {
            break;
        }
        let mut chunk = vec![0_u8; chunk_size];
        reader
            .read_exact(&mut chunk)
            .map_err(|error| OllamaError::Io(error.to_string()))?;
        out.extend_from_slice(&chunk);
        // Consume the trailing CRLF after the chunk data; a truncated response
        // is an I/O error, not a successful (short) body.
        let mut crlf = [0_u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|error| OllamaError::Io(error.to_string()))?;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// ────────────────────────────────────────────────────────────────────────────
// Probe helper (used by the --ollama-status command)
// ────────────────────────────────────────────────────────────────────────────

/// Probes the locally-running Ollama instance for status and installed models.
///
/// Returns `Ok((version, models))` when Ollama is reachable, or an
/// [`OllamaError`] otherwise.
///
/// # Errors
///
/// Returns [`OllamaError::NetworkNotAllowed`] when `allow_network` is `false`.
pub fn probe_ollama(allow_network: bool) -> Result<(String, Vec<OllamaModel>), OllamaError> {
    // Any model name works for a probe since we only call version/list.
    let client = OllamaClient::default_addr("probe", allow_network)?;
    let version = client.version()?;
    let models = client.list_models()?;
    Ok((version, models))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // None of these tests open a real socket — they validate the
    // network-policy gate, the JSON escaping helper, and the NDJSON
    // accumulation path using mock response strings only.

    #[test]
    fn client_rejects_when_network_not_allowed() {
        let result = OllamaClient::default_addr("llama3.2", false);
        assert!(
            matches!(result, Err(OllamaError::NetworkNotAllowed)),
            "must refuse construction without allow_network"
        );
    }

    #[test]
    fn client_accepts_when_network_allowed() {
        // We allow_network=true but deliberately use an address that will
        // *never* connect so the test stays deterministic: construction itself
        // must succeed even if the service is not running.
        let result = OllamaClient::new("127.0.0.1:19999", "llama3.2", true);
        assert!(
            result.is_ok(),
            "construction should succeed with allow_network=true"
        );
        let client = result.unwrap();
        assert_eq!(client.model(), "llama3.2");
        assert_eq!(client.addr(), "127.0.0.1:19999");
    }

    #[test]
    fn json_string_escapes_special_chars() {
        assert_eq!(json_string("hello"), "\"hello\"");
        assert_eq!(json_string("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(json_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_string("line\nnew"), "\"line\\nnew\"");
        assert_eq!(json_string("tab\there"), "\"tab\\there\"");
    }

    #[test]
    fn chat_message_to_json() {
        let msg = ChatMessage::user("hello world");
        assert_eq!(
            msg.to_json(),
            "{\"role\":\"user\",\"content\":\"hello world\"}"
        );
        let msg = ChatMessage::system("be helpful");
        assert_eq!(
            msg.to_json(),
            "{\"role\":\"system\",\"content\":\"be helpful\"}"
        );
    }

    #[test]
    fn generate_response_single_object() {
        assert_eq!(
            extract_generate_response("{\"response\":\"hello world\"}").unwrap(),
            "hello world"
        );
    }

    #[test]
    fn generate_response_ndjson_accumulates() {
        let ndjson = "{\"response\":\"hello\"}\n{\"response\":\" world\"}\n";
        assert_eq!(extract_generate_response(ndjson).unwrap(), "hello world");
    }

    #[test]
    fn generate_response_missing_field_is_error() {
        assert!(matches!(
            extract_generate_response("{\"model\":\"llama3.2\"}"),
            Err(OllamaError::Parse(_))
        ));
        assert!(matches!(
            extract_generate_response("not json"),
            Err(OllamaError::Parse(_))
        ));
        assert!(matches!(
            extract_generate_response(""),
            Err(OllamaError::Parse(_))
        ));
    }

    #[test]
    fn chat_response_single_object() {
        let body = "{\"message\":{\"role\":\"assistant\",\"content\":\"foo\"}}";
        assert_eq!(extract_chat_response(body).unwrap(), "foo");
    }

    #[test]
    fn chat_response_ndjson_accumulates() {
        let ndjson = "{\"message\":{\"role\":\"assistant\",\"content\":\"foo\"}}\n\
             {\"message\":{\"role\":\"assistant\",\"content\":\"bar\"}}\n";
        assert_eq!(extract_chat_response(ndjson).unwrap(), "foobar");
    }

    #[test]
    fn chat_response_missing_field_is_error() {
        assert!(matches!(
            extract_chat_response("{\"done\":true}"),
            Err(OllamaError::Parse(_))
        ));
        assert!(matches!(
            extract_chat_response("garbage"),
            Err(OllamaError::Parse(_))
        ));
    }

    #[test]
    fn probe_rejects_without_network() {
        let result = probe_ollama(false);
        assert!(
            matches!(result, Err(OllamaError::NetworkNotAllowed)),
            "probe must refuse without allow_network"
        );
    }
}
