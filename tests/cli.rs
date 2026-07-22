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
fn offline_status_reports_offline_default_and_online_opt_in() {
    let output = run(&["--offline-status"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("default_network_mode=offline"));
    assert!(text.contains("online_opt_in_flag=--allow-network"));
}

#[test]
fn run_external_tool_offline_refuses_active_tool_without_opt_in() {
    // `masscan` is ActiveNetwork. Without --allow-network it must be refused
    // for live activity — never silently run. `--version` is used so that no
    // packets are ever sent even if the binary happens to be installed; in
    // offline mode the tool is refused before it is spawned regardless.
    let output = run(&["--run-external-tool", "masscan", "--version"]);
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(
        err.contains("--allow-network") || err.contains("not installed"),
        "offline active-tool run must be refused, got: {err}"
    );
}

#[test]
fn run_external_tool_online_opt_in_is_acknowledged() {
    // With the explicit opt-in the online-mode banner is emitted before the
    // tool is attempted. `--version` keeps this non-networking so the test
    // never scans, even if `masscan` is installed in CI.
    let output = run(&[
        "--run-external-tool",
        "--allow-network",
        "masscan",
        "--version",
    ]);
    assert!(stderr(&output).contains("online mode engaged"));
}

#[test]
fn offline_status_counts_all_builtin_substitutes() {
    let output = run(&["--offline-status"]);
    assert!(output.status.success());
    // autopsy, volatility, wireshark, binwalk, foremost, bulk_extractor,
    // hashdeep are all in-house local analyzers.
    assert!(stdout(&output).contains("built_in_substitute_tools=7"));
}

#[test]
fn run_tool_binwalk_analyzes_a_local_blob() {
    let path = unique_temp_path("binwalk-blob");
    // A gzip magic embedded after some padding.
    std::fs::write(&path, b"\x00\x00\x00\x00\x1f\x8b\x08rest-of-stream").expect("write temp blob");
    let output = run(&["--run-tool", "binwalk", &path.to_string_lossy()]);
    let _ = std::fs::remove_file(&path);

    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Binwalk Local Firmware Report"));
    assert!(text.contains("gzip stream"));
}

#[test]
fn run_tool_bulk_extractor_pulls_indicators() {
    let path = unique_temp_path("bulk-blob");
    std::fs::write(
        &path,
        b"reach admin@example.com via https://c2.example/x from 198.51.100.9",
    )
    .expect("write temp blob");
    let output = run(&["--run-tool", "bulk_extractor", &path.to_string_lossy()]);
    let _ = std::fs::remove_file(&path);

    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("admin@example.com"));
    assert!(text.contains("198.51.100.9"));
    assert!(text.contains("https://c2.example/x"));
}

#[test]
fn run_tool_hashdeep_hashes_a_local_file() {
    let path = unique_temp_path("hashdeep-file");
    std::fs::write(&path, b"evidence").expect("write temp file");
    let output = run(&["--run-tool", "hashdeep", &path.to_string_lossy()]);
    let _ = std::fs::remove_file(&path);

    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Hashdeep Local Hash Audit"));
    assert!(text.contains("sha256 :"));
    assert!(text.contains("crc32  :"));
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

#[test]
fn ask_routes_plain_english_to_list_tools_and_runs_it() {
    let output = run(&["--ask", "what tools do you have"]);
    assert!(output.status.success());
    let text = stdout(&output);
    // Reports what it understood, then actually carries out the action.
    assert!(text.contains("Understood: list-tools"));
    assert!(text.contains("cataloged"));
}

#[test]
fn ask_reports_offline_status_from_plain_english() {
    let output = run(&["--ask", "are you healthy and ready"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Understood: offline-status"));
    assert!(text.contains("network_required=false"));
}

#[test]
fn ask_scores_a_quoted_string_for_anomaly() {
    let output = run(&["--ask", "is this suspicious: \"zzq xqv vfrb qwx ncbz\""]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Understood: anomaly-check"));
    assert!(text.contains("ANOMALOUS"));
}

#[test]
fn ask_declines_out_of_scope_requests() {
    let output = run(&["--ask", "book me a flight to paris"]);
    // Declining is still a successful, well-formed response.
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Understood: out-of-scope"));
    assert!(text.contains("outside my scope"));
}

#[test]
fn ask_requires_an_instruction() {
    let output = run(&["--ask"]);
    assert_eq!(output.status.code(), Some(2));
}
