//! Secret handling for authenticated tooling.
//!
//! Authenticated tools (evil-winrm, netexec, hydra, wpscan with an API token)
//! need credentials, and the two ways that goes wrong are leaking them into
//! logs/reports and hard-coding them into commands. This module addresses
//! both: [`Secret`] wraps a credential so it never renders in `Debug`/
//! `Display` output, and [`SecretStore`] resolves named secrets from the
//! environment or an on-disk file, substitutes `${secret:NAME}` references in
//! a tool's arguments at spawn time, and [redacts](SecretStore::redact) any
//! secret value that appears in captured tool output before it is logged,
//! persisted, or reported.
//!
//! The store is the single choke point for credentials: adapters and configs
//! reference a secret by name, the plaintext is injected only into the argv
//! actually handed to the process, and everything the crate records is run
//! through redaction first.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

/// Environment-variable prefix [`SecretStore::from_env`] loads secrets from.
/// `SECAGENT_SECRET_API_TOKEN=...` becomes the secret named `api_token`.
pub const ENV_PREFIX: &str = "SECAGENT_SECRET_";

/// The reference syntax substituted in tool arguments: `${secret:NAME}`.
const REF_OPEN: &str = "${secret:";

/// A credential that does not leak through logging.
///
/// `Debug` and `Display` both render a fixed redaction marker, never the
/// value. The plaintext is reachable only through the explicit
/// [`Secret::expose`], which makes every access an auditable call site.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    value: String,
}

impl Secret {
    /// Wraps a credential value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Returns the plaintext. Every call is an explicit, greppable exposure
    /// point — use it only where the value truly must leave the store (the
    /// argv handed to a process).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("***")
    }
}

/// Errors resolving secret references.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// A `${secret:NAME}` reference named a secret the store does not hold.
    Unresolved(String),
    /// A `${secret:` reference was opened but never closed with `}`.
    Malformed(String),
    /// The secrets file could not be read.
    Io(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved(name) => write!(formatter, "no secret named '{name}' is configured"),
            Self::Malformed(arg) => write!(formatter, "malformed secret reference in '{arg}'"),
            Self::Io(message) => write!(formatter, "cannot read secrets file: {message}"),
        }
    }
}

impl std::error::Error for SecretError {}

/// A store of named secrets, ordered for deterministic iteration.
#[derive(Default)]
pub struct SecretStore {
    secrets: BTreeMap<String, Secret>,
}

impl SecretStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads every `SECAGENT_SECRET_*` environment variable into the store,
    /// lowercasing the remainder of the name (`SECAGENT_SECRET_API_TOKEN` →
    /// `api_token`).
    #[must_use]
    pub fn from_env() -> Self {
        let mut store = Self::new();
        for (key, value) in std::env::vars() {
            if let Some(name) = key.strip_prefix(ENV_PREFIX) {
                if !name.is_empty() {
                    store.insert(name.to_ascii_lowercase(), Secret::new(value));
                }
            }
        }
        store
    }

    /// Loads `name=value` lines from a file, merging them into the store.
    /// Blank lines and lines beginning with `#` are ignored; a value may
    /// contain `=`. Later definitions override earlier ones.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Io`] if the file cannot be read.
    pub fn load_file(&mut self, path: &Path) -> Result<(), SecretError> {
        let contents =
            std::fs::read_to_string(path).map_err(|error| SecretError::Io(error.to_string()))?;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((name, value)) = trimmed.split_once('=') {
                let name = name.trim();
                if !name.is_empty() {
                    self.insert(name.to_string(), Secret::new(value.trim().to_string()));
                }
            }
        }
        Ok(())
    }

    /// Inserts or replaces a secret.
    pub fn insert(&mut self, name: impl Into<String>, secret: Secret) {
        self.secrets.insert(name.into(), secret);
    }

    /// Looks up a secret by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.secrets.get(name)
    }

    /// The configured secret names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.secrets.keys().map(String::as_str).collect()
    }

    /// Whether the store holds no secrets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Resolves every `${secret:NAME}` reference in each argument to its
    /// plaintext, returning the argv to hand to the process.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Unresolved`] for a reference to an unknown
    /// secret, or [`SecretError::Malformed`] for an unterminated reference —
    /// failing closed rather than spawning a tool with a literal `${secret:…}`
    /// or an empty credential.
    pub fn resolve_args(&self, args: &[String]) -> Result<Vec<String>, SecretError> {
        args.iter().map(|arg| self.substitute(arg)).collect()
    }

    /// Replaces `${secret:NAME}` occurrences in one argument.
    fn substitute(&self, arg: &str) -> Result<String, SecretError> {
        let mut out = String::with_capacity(arg.len());
        let mut rest = arg;
        while let Some(start) = rest.find(REF_OPEN) {
            out.push_str(&rest[..start]);
            let after = &rest[start + REF_OPEN.len()..];
            let Some(end) = after.find('}') else {
                return Err(SecretError::Malformed(arg.to_string()));
            };
            let name = &after[..end];
            let secret = self
                .get(name)
                .ok_or_else(|| SecretError::Unresolved(name.to_string()))?;
            out.push_str(secret.expose());
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    /// Masks every configured secret value occurring in `text` with `***`.
    /// Run captured tool output through this before logging, persisting, or
    /// reporting it, so a credential echoed by a tool never reaches disk.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for secret in self.secrets.values() {
            let value = secret.expose();
            if !value.is_empty() {
                out = out.replace(value, "***");
            }
        }
        out
    }
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Names are safe to show; values never are.
        formatter
            .debug_struct("SecretStore")
            .field("names", &self.names())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `${secret:NAME}` reference without a literal `{…}` in source
    /// (which the formatting-args lint would flag in test strings).
    fn sref(name: &str) -> String {
        format!("${{secret:{name}}}")
    }

    #[test]
    fn secret_never_renders_its_value() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret}"), "***");
        assert_eq!(format!("{secret:?}"), "Secret(***)");
        // The store's Debug must not leak either.
        let mut store = SecretStore::new();
        store.insert("pw", secret);
        assert!(!format!("{store:?}").contains("hunter2"));
        assert!(format!("{store:?}").contains("pw"));
    }

    #[test]
    fn resolves_references_to_plaintext() {
        let mut store = SecretStore::new();
        store.insert("api_token", Secret::new("t0ken"));
        store.insert("pw", Secret::new("s3cret"));
        let args = vec![
            "--user".to_string(),
            "admin".to_string(),
            format!("--token={}", sref("api_token")),
            sref("pw"),
        ];
        let resolved = store.resolve_args(&args).expect("resolves");
        assert_eq!(resolved[2], "--token=t0ken");
        assert_eq!(resolved[3], "s3cret");
    }

    #[test]
    fn unresolved_reference_fails_closed() {
        let store = SecretStore::new();
        let args = vec![sref("missing")];
        assert_eq!(
            store.resolve_args(&args),
            Err(SecretError::Unresolved("missing".to_string())),
        );
    }

    #[test]
    fn malformed_reference_is_rejected() {
        let store = SecretStore::new();
        let args = vec![format!("${{secret:{}", "unterminated")];
        assert!(matches!(
            store.resolve_args(&args),
            Err(SecretError::Malformed(_)),
        ));
    }

    #[test]
    fn redaction_masks_every_secret_in_output() {
        let mut store = SecretStore::new();
        store.insert("pw", Secret::new("s3cret"));
        store.insert("tok", Secret::new("abc123"));
        let log = "login ok with s3cret and token abc123 echoed";
        let redacted = store.redact(log);
        assert!(!redacted.contains("s3cret"));
        assert!(!redacted.contains("abc123"));
        assert_eq!(redacted, "login ok with *** and token *** echoed");
    }

    #[test]
    fn load_file_parses_name_value_pairs() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sa-secrets-{}", std::process::id()));
        std::fs::write(&path, "# creds\napi_token = t0ken\npw=p=with=eq\n\n").expect("write");
        let mut store = SecretStore::new();
        store.load_file(&path).expect("load");
        assert_eq!(store.get("api_token").map(Secret::expose), Some("t0ken"));
        // A value may itself contain '='.
        assert_eq!(store.get("pw").map(Secret::expose), Some("p=with=eq"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn multiple_references_in_one_arg() {
        let mut store = SecretStore::new();
        store.insert("a", Secret::new("A"));
        store.insert("b", Secret::new("B"));
        let args = vec![format!("{}-{}", sref("a"), sref("b"))];
        assert_eq!(store.resolve_args(&args).expect("ok")[0], "A-B");
    }

    #[test]
    fn args_without_references_pass_through() {
        let store = SecretStore::new();
        let args = vec!["-sV".to_string(), "10.0.0.1".to_string()];
        assert_eq!(store.resolve_args(&args).expect("ok"), args);
    }
}
