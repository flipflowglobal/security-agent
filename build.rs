//! Build script: captures build provenance and exposes it to the crate as
//! compile-time environment variables.
//!
//! A distributed binary should be able to say exactly what it is — which
//! commit it was built from, whether the tree was clean, when and for what
//! target it was built, and with which compiler. This script gathers those
//! facts at build time (`cargo:rustc-env=…`) so [`crate::build_info`] can
//! render them at runtime.
//!
//! Zero-dependency, like the rest of the crate: it only shells out to `git`
//! and reads Cargo-provided environment variables, degrading gracefully to
//! `"unknown"` when a fact can't be determined (for example, building from a
//! source tarball with no `.git`). The build date honors `SOURCE_DATE_EPOCH`
//! (the reproducible-builds standard), so a pinned epoch yields a
//! bit-reproducible binary.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Rebuild provenance when the checked-out commit (or its cleanliness)
    // could have changed, and when the reproducible-build epoch is set.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = match git(&["status", "--porcelain"]) {
        Some(status) if !status.trim().is_empty() => "-dirty",
        _ => "",
    };
    let commit_date = git(&["log", "-1", "--format=%cd", "--date=short"])
        .unwrap_or_else(|| "unknown".to_string());

    emit("SA_GIT_COMMIT", &format!("{commit}{dirty}"));
    emit("SA_GIT_COMMIT_DATE", &commit_date);
    emit("SA_BUILD_DATE", &build_date());
    emit(
        "SA_BUILD_TARGET",
        &std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
    );
    emit(
        "SA_BUILD_PROFILE",
        &std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string()),
    );
    emit(
        "SA_RUSTC_VERSION",
        &rustc_version().unwrap_or_else(|| "unknown".to_string()),
    );
}

/// Emits one `cargo:rustc-env` line so `env!(key)` resolves in the crate.
fn emit(key: &str, value: &str) {
    println!("cargo:rustc-env={key}={value}");
}

/// Runs `git` with `args`, returning trimmed stdout on success, or `None` if
/// git is missing, the command fails, or the output is empty/non-UTF-8.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    non_empty(&String::from_utf8(output.stdout).ok()?)
}

/// The compiler's `--version` line, using Cargo's `RUSTC` when set.
fn rustc_version() -> Option<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = Command::new(rustc).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    non_empty(&String::from_utf8(output.stdout).ok()?)
}

/// Trims `text`, returning an owned copy or `None` when nothing is left.
fn non_empty(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The build date as `YYYY-MM-DD` (UTC), honoring `SOURCE_DATE_EPOCH` so
/// reproducible builds pin it; otherwise the current wall-clock day.
fn build_date() -> String {
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs())
        });
    let (year, month, day) = civil_from_days(epoch / 86_400);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Civil (year, month, day) from a Unix day count — Howard Hinnant's
/// `civil_from_days`, valid for all dates at or after the Unix epoch. The
/// same algorithm the crate's report renderer uses; duplicated here because a
/// build script cannot depend on the crate it builds.
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}
