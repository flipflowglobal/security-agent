//! Runtime-environment detection for the interactive TUI.
//!
//! The agent behaves identically on a desktop and on a phone, but the *paths*
//! differ and typing them on a phone keyboard is painful. This module detects
//! whether it is running under Termux, a `UserLAnd` proot distribution, or an
//! ordinary desktop, and where that environment keeps its files — so the TUI
//! can pre-fill a platform-appropriate default path and auto-detect existing
//! inputs (databases, captures, configs) instead of asking the operator to
//! type a full path.
//!
//! Nothing here changes what the agent *does*; it only makes the interactive
//! surface usable on Android, where most of this project's real users run it.

use std::path::{Path, PathBuf};

/// The kind of runtime environment, detected best-effort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Termux on Android (its own `$PREFIX`/`$HOME` under `com.termux`).
    Termux,
    /// A `UserLAnd` proot Linux distribution on Android.
    UserLand,
    /// Desktop or server Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Anything else.
    Other,
}

impl Platform {
    /// A short human-readable label for status output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Termux => "Termux (Android)",
            Self::UserLand => "UserLAnd (Android proot)",
            Self::Linux => "Linux",
            Self::MacOs => "macOS",
            Self::Other => "unknown",
        }
    }

    /// Whether this is an Android environment, where raw-socket features (the
    /// reverse-shell listener) and `/sdcard` shared storage behave specially.
    #[must_use]
    pub const fn is_android(self) -> bool {
        matches!(self, Self::Termux | Self::UserLand)
    }
}

/// The detected environment plus where its data lives.
#[derive(Debug, Clone)]
pub struct Environment {
    /// The detected platform.
    pub platform: Platform,
    /// The home directory the agent stores and looks for files under.
    pub home: PathBuf,
}

impl Environment {
    /// Detects the current environment from the process's real environment.
    #[must_use]
    pub fn detect() -> Self {
        let platform = detect_platform(
            |key| std::env::var(key).ok(),
            |path| Path::new(path).exists(),
        );
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
        Self { platform, home }
    }

    /// A default path for a data file named `name` (e.g. `findings.sadb`),
    /// under the environment's home directory.
    #[must_use]
    pub fn default_data_path(&self, name: &str) -> PathBuf {
        self.home.join(name)
    }

    /// Directories worth scanning for existing inputs, most-relevant first: the
    /// current directory, the home directory, and — on Android — the shared
    /// storage locations, when they exist.
    #[must_use]
    pub fn candidate_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![PathBuf::from("."), self.home.clone()];
        if self.platform.is_android() {
            for shared in ["/sdcard", "/sdcard/Download", "/storage/emulated/0"] {
                let path = PathBuf::from(shared);
                if path.is_dir() {
                    dirs.push(path);
                }
            }
        }
        dedup_paths(dirs)
    }
}

/// Best-effort platform detection, parameterized over environment lookups and
/// path existence so it is deterministically testable.
fn detect_platform(
    env: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Platform {
    let is_termux = env("TERMUX_VERSION").is_some()
        || env("PREFIX").is_some_and(|prefix| prefix.contains("com.termux"))
        || env("HOME").is_some_and(|home| home.contains("com.termux"));
    if is_termux {
        return Platform::Termux;
    }
    // UserLAnd mounts its support scripts at `/support`; a reasonable marker for
    // a UserLAnd proot distro that otherwise looks like ordinary Linux.
    if env("USERLAND").is_some() || exists("/support") {
        return Platform::UserLand;
    }
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Other
    }
}

/// Files under `dirs` whose name ends with any of `extensions` (e.g.
/// `[".sadb"]`), in directory order, de-duplicated, and capped at `limit`.
#[must_use]
pub fn discover_inputs_in(dirs: &[PathBuf], extensions: &[&str], limit: usize) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut in_dir: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && has_extension(path, extensions))
            .collect();
        in_dir.sort();
        for path in in_dir {
            if !found.contains(&path) {
                found.push(path);
            }
            if found.len() >= limit {
                return found;
            }
        }
    }
    found
}

/// Whether `path`'s file name ends with one of `extensions`.
fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| extensions.iter().any(|ext| name.ends_with(ext)))
}

/// Resolves an operator's answer at an input prompt: a 1-based number selects a
/// discovered candidate; an empty answer takes `default`; anything else is
/// treated as a literal path.
#[must_use]
pub fn resolve_input_choice(raw: &str, candidates: &[PathBuf], default: &Path) -> PathBuf {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return default.to_path_buf();
    }
    if let Ok(index) = trimmed.parse::<usize>() {
        if index >= 1 && index <= candidates.len() {
            return candidates[index - 1].clone();
        }
    }
    PathBuf::from(trimmed)
}

/// De-duplicates a directory list, preserving first-seen order.
fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen: Vec<PathBuf> = Vec::new();
    for path in paths {
        if !seen.contains(&path) {
            seen.push(path);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_string())
        }
    }

    #[test]
    fn detects_termux_from_its_env() {
        let platform = detect_platform(env_from(&[("TERMUX_VERSION", "0.118")]), |_| false);
        assert_eq!(platform, Platform::Termux);
        let by_prefix = detect_platform(
            env_from(&[("PREFIX", "/data/data/com.termux/files/usr")]),
            |_| false,
        );
        assert_eq!(by_prefix, Platform::Termux);
    }

    #[test]
    fn detects_userland_from_the_support_mount() {
        let platform = detect_platform(env_from(&[]), |path| path == "/support");
        assert_eq!(platform, Platform::UserLand);
    }

    #[test]
    fn termux_outranks_the_userland_marker() {
        // A phone could show both signals; Termux is the more specific one.
        let platform = detect_platform(env_from(&[("TERMUX_VERSION", "0.118")]), |path| {
            path == "/support"
        });
        assert_eq!(platform, Platform::Termux);
    }

    #[test]
    fn android_platforms_are_flagged_as_android() {
        assert!(Platform::Termux.is_android());
        assert!(Platform::UserLand.is_android());
        assert!(!Platform::Linux.is_android());
    }

    #[test]
    fn discover_finds_matching_files_only() {
        let dir = std::env::temp_dir().join(format!("sa-platform-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        for name in ["findings.sadb", "audit.sadb", "notes.txt"] {
            std::fs::write(dir.join(name), b"x").expect("write");
        }

        let found = discover_inputs_in(std::slice::from_ref(&dir), &[".sadb"], 9);
        let names: Vec<String> = found
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
            .collect();

        std::fs::remove_dir_all(&dir).expect("cleanup");
        assert!(names.contains(&"findings.sadb".to_string()));
        assert!(names.contains(&"audit.sadb".to_string()));
        assert!(!names.contains(&"notes.txt".to_string()));
    }

    #[test]
    fn discover_respects_the_limit() {
        let dir = std::env::temp_dir().join(format!("sa-platform-lim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        for index in 0..5 {
            std::fs::write(dir.join(format!("db{index}.sadb")), b"x").expect("write");
        }
        let found = discover_inputs_in(std::slice::from_ref(&dir), &[".sadb"], 3);
        std::fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn resolve_choice_picks_a_number_default_or_literal_path() {
        let candidates = vec![PathBuf::from("/a/one.sadb"), PathBuf::from("/b/two.sadb")];
        let default = PathBuf::from("/home/findings.sadb");

        // A number selects the 1-based candidate.
        assert_eq!(
            resolve_input_choice("2", &candidates, &default),
            PathBuf::from("/b/two.sadb")
        );
        // Empty takes the default.
        assert_eq!(resolve_input_choice("   ", &candidates, &default), default);
        // Out-of-range number is treated as a literal path (not a panic).
        assert_eq!(
            resolve_input_choice("9", &candidates, &default),
            PathBuf::from("9")
        );
        // A path is taken literally.
        assert_eq!(
            resolve_input_choice("/tmp/custom.sadb", &candidates, &default),
            PathBuf::from("/tmp/custom.sadb")
        );
    }
}
