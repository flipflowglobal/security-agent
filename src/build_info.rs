//! Build provenance, surfaced at runtime.
//!
//! `build.rs` captures the commit, build date, target, profile, and compiler
//! at compile time and passes them in as `cargo:rustc-env` values; this module
//! reads those compile-time constants and renders them for `--version` and
//! `--build-info`. The point is that any distributed binary is
//! self-describing: given only the executable, an operator can recover exactly
//! which source it came from and how it was built — the same provenance
//! discipline the engagement audit trail applies to a run.

use std::fmt::Write as _;

/// The crate's package name (from Cargo).
pub const NAME: &str = env!("CARGO_PKG_NAME");
/// The crate's semantic version (from Cargo).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Short git commit the binary was built from, suffixed `-dirty` when the
/// working tree had uncommitted changes, or `"unknown"` when git was
/// unavailable at build time.
pub const GIT_COMMIT: &str = env!("SA_GIT_COMMIT");
/// Commit date of [`GIT_COMMIT`] (`YYYY-MM-DD`), or `"unknown"`.
pub const GIT_COMMIT_DATE: &str = env!("SA_GIT_COMMIT_DATE");
/// UTC date the binary was built (`YYYY-MM-DD`); pinned by `SOURCE_DATE_EPOCH`.
pub const BUILD_DATE: &str = env!("SA_BUILD_DATE");
/// Target triple the binary was built for.
pub const BUILD_TARGET: &str = env!("SA_BUILD_TARGET");
/// Cargo build profile (`debug` / `release`).
pub const BUILD_PROFILE: &str = env!("SA_BUILD_PROFILE");
/// The `rustc --version` line the binary was compiled with.
pub const RUSTC_VERSION: &str = env!("SA_RUSTC_VERSION");

/// A snapshot of the binary's build provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInfo {
    /// Package name.
    pub name: &'static str,
    /// Semantic version.
    pub version: &'static str,
    /// Short commit (with `-dirty` suffix when applicable), or `"unknown"`.
    pub git_commit: &'static str,
    /// Commit date (`YYYY-MM-DD`), or `"unknown"`.
    pub git_commit_date: &'static str,
    /// Build date (`YYYY-MM-DD`, UTC).
    pub build_date: &'static str,
    /// Target triple.
    pub build_target: &'static str,
    /// Build profile.
    pub build_profile: &'static str,
    /// Compiler version line.
    pub rustc_version: &'static str,
}

impl BuildInfo {
    /// This binary's build provenance.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            name: NAME,
            version: VERSION,
            git_commit: GIT_COMMIT,
            git_commit_date: GIT_COMMIT_DATE,
            build_date: BUILD_DATE,
            build_target: BUILD_TARGET,
            build_profile: BUILD_PROFILE,
            rustc_version: RUSTC_VERSION,
        }
    }

    /// A one-line version string: `name X.Y.Z (commit commit-date, target)`.
    #[must_use]
    pub fn version_line(&self) -> String {
        format!(
            "{} {} ({} {}, {})",
            self.name, self.version, self.git_commit, self.git_commit_date, self.build_target,
        )
    }

    /// A multi-line, human-readable provenance block.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{} {}", self.name, self.version);
        let _ = writeln!(out, "commit:       {}", self.git_commit);
        let _ = writeln!(out, "commit date:  {}", self.git_commit_date);
        let _ = writeln!(out, "built:        {}", self.build_date);
        let _ = writeln!(out, "target:       {}", self.build_target);
        let _ = writeln!(out, "profile:      {}", self.build_profile);
        let _ = writeln!(out, "rustc:        {}", self.rustc_version);
        out
    }

    /// The provenance as one JSON object line, with a fixed key order so the
    /// output is deterministic and machine-parseable.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut out = String::from('{');
        let pairs = [
            ("name", self.name),
            ("version", self.version),
            ("git_commit", self.git_commit),
            ("git_commit_date", self.git_commit_date),
            ("build_date", self.build_date),
            ("build_target", self.build_target),
            ("build_profile", self.build_profile),
            ("rustc_version", self.rustc_version),
        ];
        for (index, (key, value)) in pairs.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(out, "\"{}\":\"{}\"", esc(key), esc(value));
        }
        out.push('}');
        out
    }
}

/// Escapes the characters that would break a JSON string literal.
fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_populates_every_field() {
        let info = BuildInfo::current();
        for field in [
            info.name,
            info.version,
            info.git_commit,
            info.git_commit_date,
            info.build_date,
            info.build_target,
            info.build_profile,
            info.rustc_version,
        ] {
            assert!(!field.is_empty(), "provenance field must not be empty");
        }
        assert_eq!(info.name, "security-agent");
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn version_line_carries_name_version_and_target() {
        let info = BuildInfo::current();
        let line = info.version_line();
        assert!(line.contains(info.name));
        assert!(line.contains(info.version));
        assert!(line.contains(info.build_target));
    }

    #[test]
    fn plain_block_labels_each_fact() {
        let block = BuildInfo::current().render_plain();
        for label in [
            "commit:",
            "commit date:",
            "built:",
            "target:",
            "profile:",
            "rustc:",
        ] {
            assert!(block.contains(label), "missing label: {label}");
        }
    }

    #[test]
    fn json_is_parseable_and_carries_the_fields() {
        let info = BuildInfo::current();
        let json = info.render_json();
        let parsed = crate::json::parse(&json).expect("build-info JSON must parse");
        assert_eq!(parsed.get("name").and_then(|v| v.as_str()), Some(info.name));
        assert_eq!(
            parsed.get("version").and_then(|v| v.as_str()),
            Some(info.version)
        );
        assert_eq!(
            parsed.get("build_target").and_then(|v| v.as_str()),
            Some(info.build_target)
        );
        assert_eq!(
            parsed.get("git_commit").and_then(|v| v.as_str()),
            Some(info.git_commit)
        );
    }

    #[test]
    fn json_escapes_control_characters() {
        // The renderer must produce valid JSON even if a provenance value
        // contained a quote or backslash (e.g. an exotic rustc version line).
        let info = BuildInfo {
            rustc_version: "rustc \"1.97\" \\ build",
            ..BuildInfo::current()
        };
        let json = info.render_json();
        let parsed = crate::json::parse(&json).expect("must still parse");
        assert_eq!(
            parsed.get("rustc_version").and_then(|v| v.as_str()),
            Some("rustc \"1.97\" \\ build")
        );
    }

    #[test]
    fn renderers_are_deterministic() {
        let info = BuildInfo::current();
        assert_eq!(info.render_plain(), info.render_plain());
        assert_eq!(info.render_json(), info.render_json());
        assert_eq!(info.version_line(), info.version_line());
    }
}
