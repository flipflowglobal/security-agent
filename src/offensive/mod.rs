//! Advanced offensive security toolkit — pure-Rust builtin implementations.
//!
//! Every tool in this module operates entirely offline on local data or
//! produces actionable output without requiring external crates or network
//! access at build time. Live network tools (nmap, hydra, etc.) remain
//! cataloged external tools; these builtins complement them with:
//!
//! - **Reconnaissance**: TCP port scanning, service fingerprinting, OS detection
//! - **Web exploitation**: SQL injection, XSS, directory traversal, LFI/RFI
//! - **Credential attacks**: hash cracking, brute-force wordlist generation, password analysis
//! - **Payload generation**: reverse shells, bind shells, encoded payloads
//! - **Post-exploitation**: privilege escalation checks, lateral movement helpers
//! - **Wireless**: WPA handshake analysis, WPS pin calculation, deauth frame crafting
//! - **Evasion**: payload encoding, obfuscation, fragmentation

pub mod cloud_security;
pub mod credential_attack;
pub mod evasion;
pub mod payload_gen;
pub mod post_exploit;
pub mod recon;
pub mod supply_chain;
pub mod web_exploit;
pub mod wireless;

pub use cloud_security::{
    AwsFinding, AzureFinding, CloudSecurityReport, GcpFinding, analyze_azure_nsg,
    analyze_azure_role, analyze_gcp_firewall, analyze_gcp_iam, analyze_iam_policy,
    analyze_s3_policy, analyze_security_group, generate_cloud_report,
};
pub use credential_attack::*;
pub use evasion::*;
pub use payload_gen::*;
pub use post_exploit::*;
pub use recon::*;
pub use supply_chain::{
    CicdFinding, DependencyFinding, DependencyInventory, FindingType, LicenseRisk,
    LockFileIntegrity, analyze_cargo_toml, analyze_github_workflow, analyze_lock_integrity,
    analyze_package_json, analyze_requirements_txt, check_license_risk, generate_inventory,
};
pub use web_exploit::*;
pub use wireless::*;
