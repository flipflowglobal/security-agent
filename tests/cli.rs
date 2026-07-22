//! Black-box integration tests for the compiled `security-agent` binary.
//!
//! Unit tests call functions directly; these prove the built binary parses
//! argv, dispatches commands, and prints the expected output. Cargo builds
//! files under `tests/` as separate integration crates and exposes the
//! binary path via `CARGO_BIN_EXE_security-agent` — no path guessing, and
//! no `Cargo.toml` change.
//!
//! Every case is deterministic: it relies only on built-in assets and temp
//! files, never on optional external scanners (`semgrep`, `nmap`, …) being
//! installed.

use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_security-agent"))
        .args(args)
        .output()
        .expect("binary should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn unique_temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "security-agent-cli-it-{name}-{}.txt",
        std::process::id()
    ))
}

#[test]
fn offline_status_reports_core_fields() {
    let output = run(&["--offline-status"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("network_required=false"));
    assert!(text.contains("capability_coverage=ok"));
}

#[test]
fn about_prints_mission_and_roadmap() {
    let output = run(&["--about"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Defensive security orchestration"));
    assert!(text.contains("Phase 1"));
    assert!(text.contains("Phase 4"));
}

#[test]
fn list_skills_lists_the_general_skill() {
    let output = run(&["--list-skills"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("security-agent"));
}

#[test]
fn show_skill_prints_nmap_description() {
    let output = run(&["--show-skill", "nmap"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Network discovery"));
}

#[test]
fn list_tools_marks_builtin_substitutes() {
    let output = run(&["--list-tools"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("autopsy\tbuilt-in-substitute"));
}

#[test]
fn unknown_command_exits_2() {
    let output = run(&["--bogus"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn plan_scan_end_to_end_from_a_temp_config() {
    let config = unique_temp_path("plan-scan-ok");
    std::fs::write(
        &config,
        "\
engagement_id=eng-it-ok
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=99999999999
in_scope_targets=api-staging
allowed_techniques=PassiveRecon,ConfigurationAudit,ApiSecurity
max_intensity=Standard
high_impact_approved=false
penetrative_testing_approved=true

[target]
id=api-staging
target_type=Api
criticality=3
",
    )
    .expect("write temp config");

    let output = run(&["--plan-scan", &config.to_string_lossy()]);
    let _ = std::fs::remove_file(&config);

    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Execution Plan"));
    assert!(text.contains("eng-it-ok"));
}

#[test]
fn llm_generate_echoes_prompt_and_continues() {
    let output = run(&["--llm-generate", "the", "coordinator"]);
    assert!(output.status.success());
    let text = stdout(&output);
    // The prompt is echoed and a continuation appended; the bundled model
    // is trained on a security corpus, so a domain word should appear.
    assert!(text.contains("the coordinator"));
    assert!(text.split_whitespace().count() > 2);
}

#[test]
fn llm_generate_requires_a_prompt() {
    let output = run(&["--llm-generate"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn llm_perplexity_scores_text() {
    let output = run(&[
        "--llm-perplexity",
        "the",
        "policy",
        "engine",
        "denies",
        "scope",
    ]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("perplexity="));
}

#[test]
fn plan_scan_denied_config_exits_1() {
    let config = unique_temp_path("plan-scan-denied");
    std::fs::write(
        &config,
        "\
engagement_id=eng-it-denied
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=99999999999
in_scope_targets=prod-ledger
allowed_techniques=PassiveRecon
deny_list_targets=prod-ledger
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false

[target]
id=prod-ledger
target_type=Api
criticality=2
",
    )
    .expect("write temp config");

    let output = run(&["--plan-scan", &config.to_string_lossy()]);
    let _ = std::fs::remove_file(&config);

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("authorization denied"));
}
