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

pub mod recon;
pub mod web_exploit;
pub mod credential_attack;
pub mod payload_gen;
pub mod post_exploit;
pub mod wireless;
pub mod evasion;
pub mod cloud_security;
pub mod supply_chain;

pub use recon::*;
pub use web_exploit::*;
pub use credential_attack::*;
pub use payload_gen::*;
pub use post_exploit::*;
pub use wireless::*;
pub use evasion::*;
pub use cloud_security::*;
pub use supply_chain::*;
