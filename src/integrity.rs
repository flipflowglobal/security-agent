//! Offline integrity verification for locally installed tool binaries.
//!
//! Real execution (see `crate::execution`) resolves a tool's binary on
//! `PATH` but, on its own, never checks *what* that binary is. This module
//! adds an optional, offline pin: a bundled manifest
//! (`assets/tool_integrity.txt`, compiled in via `include_str!`) maps a
//! cataloged tool name to the expected lowercase-hex SHA-256 of its
//! executable. [`verify`] hashes the resolved binary with the crate's own
//! SHA-256 (`crate::builtin_tools::sha256_file` — no external crate) and
//! compares.
//!
//! The default is deliberately permissive: the shipped manifest is empty,
//! so every tool is [`IntegrityStatus::Unpinned`] and executes exactly as
//! before. Only a tool with a manifest entry is ever hashed, and only a
//! [`IntegrityStatus::Mismatch`] blocks execution — so pinning is strictly
//! opt-in per tool and never hashes a binary that has no entry.

use crate::builtin_tools::sha256_file;
use std::collections::BTreeMap;
use std::path::Path;

const BUNDLED_MANIFEST: &str = include_str!("../assets/tool_integrity.txt");

/// The outcome of checking one tool's binary against the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// A manifest entry exists and the local binary's hash matches it.
    Verified,
    /// A manifest entry exists but the local binary's hash differs.
    /// Execution refuses this tool (see `crate::execution`).
    Mismatch,
    /// No manifest entry for this tool. The default for every tool while
    /// the shipped manifest is empty; executes normally.
    Unpinned,
}

impl IntegrityStatus {
    /// A short, stable label for status lines (`--list-tools`, `--offline-status`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::Unpinned => "unpinned",
        }
    }
}

/// Parsed `name=sha256hex` integrity manifest.
#[derive(Debug, Clone, Default)]
pub struct IntegrityManifest {
    entries: BTreeMap<String, String>,
}

impl IntegrityManifest {
    /// Loads the manifest compiled into the binary from
    /// `assets/tool_integrity.txt`.
    #[must_use]
    pub fn bundled() -> Self {
        Self::parse(BUNDLED_MANIFEST)
    }

    /// Parses `name=sha256hex` lines. Blank lines and `#` comments are
    /// ignored; a line without `=` is skipped rather than failing the whole
    /// parse (the manifest is advisory, not a hard schema). Hashes are
    /// stored lowercased so comparison is case-insensitive.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut entries = BTreeMap::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((name, hash)) = line.split_once('=') {
                let name = name.trim();
                let hash = hash.trim();
                if !name.is_empty() && !hash.is_empty() {
                    entries.insert(name.to_string(), hash.to_ascii_lowercase());
                }
            }
        }
        Self { entries }
    }

    /// The expected lowercase-hex SHA-256 for `tool`, if pinned.
    #[must_use]
    pub fn expected_sha256(&self, tool: &str) -> Option<&str> {
        self.entries.get(tool).map(String::as_str)
    }

    /// Number of pinned tools (manifest entries).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest has no pinned tools.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Verifies the tool named `tool` whose resolved binary is `executable`
/// against `manifest`.
///
/// Returns [`IntegrityStatus::Unpinned`] immediately (without hashing)
/// when the tool has no manifest entry or has no resolved executable —
/// so tools without a pin, which is every tool by default, never incur
/// hashing cost. Only a pinned, installed tool is hashed; a hashing error
/// (e.g. the file vanished between resolution and verification) is treated
/// conservatively as a [`IntegrityStatus::Mismatch`].
#[must_use]
pub fn verify(
    tool: &str,
    executable: Option<&Path>,
    manifest: &IntegrityManifest,
) -> IntegrityStatus {
    let Some(expected) = manifest.expected_sha256(tool) else {
        return IntegrityStatus::Unpinned;
    };
    let Some(path) = executable else {
        return IntegrityStatus::Unpinned;
    };
    match sha256_file(path) {
        Ok(actual) if actual.eq_ignore_ascii_case(expected) => IntegrityStatus::Verified,
        _ => IntegrityStatus::Mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "security-agent-integrity-{name}-{}",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).expect("create temp file");
        file.write_all(contents).expect("write temp file");
        path
    }

    #[test]
    fn manifest_parses_name_equals_hash_lines() {
        let manifest = IntegrityManifest::parse("semgrep=ABCDEF\njadx=012345\n");
        // Stored lowercased.
        assert_eq!(manifest.expected_sha256("semgrep"), Some("abcdef"));
        assert_eq!(manifest.expected_sha256("jadx"), Some("012345"));
        assert_eq!(manifest.len(), 2);
    }

    #[test]
    fn manifest_ignores_comments_and_blanks() {
        let manifest = IntegrityManifest::parse("# a comment\n\n  \nsemgrep=abc\nnot-a-pair\n");
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest.expected_sha256("semgrep"), Some("abc"));
        assert!(manifest.expected_sha256("nonexistent").is_none());
    }

    #[test]
    fn bundled_manifest_is_empty_by_default() {
        // The shipped manifest pins nothing, so nothing is ever blocked
        // until an operator adds a vetted entry.
        assert!(IntegrityManifest::bundled().is_empty());
    }

    #[test]
    fn reports_unpinned_for_absent_entry() {
        let manifest = IntegrityManifest::default();
        let path = temp_file("unpinned", b"any contents");
        let status = verify("semgrep", Some(&path), &manifest);
        std::fs::remove_file(&path).ok();
        assert_eq!(status, IntegrityStatus::Unpinned);
    }

    #[test]
    fn verifies_matching_hash() {
        let path = temp_file("match", b"hello integrity");
        let expected = sha256_file(&path).expect("hash temp file");
        let manifest = IntegrityManifest::parse(&format!("mytool={expected}"));

        let status = verify("mytool", Some(&path), &manifest);
        std::fs::remove_file(&path).ok();
        assert_eq!(status, IntegrityStatus::Verified);
    }

    #[test]
    fn flags_mismatch() {
        let path = temp_file("mismatch", b"real contents");
        let manifest = IntegrityManifest::parse(
            "mytool=0000000000000000000000000000000000000000000000000000000000000000",
        );

        let status = verify("mytool", Some(&path), &manifest);
        std::fs::remove_file(&path).ok();
        assert_eq!(status, IntegrityStatus::Mismatch);
    }

    #[test]
    fn pinned_but_not_installed_is_unpinned_not_mismatch() {
        // A pin for a tool that isn't installed can't be verified or
        // violated — there's nothing to run — so it reads as Unpinned.
        let manifest = IntegrityManifest::parse("mytool=abc");
        assert_eq!(verify("mytool", None, &manifest), IntegrityStatus::Unpinned);
    }
}
