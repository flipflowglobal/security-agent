//! Offline hash-identification engine.
//!
//! Serves the password-recovery tools (`hashcat`, `john`, `ophcrack`,
//! `rcrack`). Live brute force needs a wordlist and compute the offline
//! substitute deliberately withholds; instead every candidate hash is
//! classified by algorithm/family so an operator knows *what* they are up
//! against before taking the workload to an authorized cracking rig.

use std::fmt::Write as _;

use super::{payload_lines, text_banner};
use crate::offensive::credential_attack::identify_hash;

pub(super) fn report(tool: &str, text: &str) -> String {
    let mut out = text_banner(tool, "Offline Hash Identification");
    let hashes = payload_lines(text);
    if hashes.is_empty() {
        out.push_str("No candidate hashes found in input (one hash per line).\n");
        return out;
    }
    let _ = writeln!(out, "Candidate hashes analyzed: {}\n", hashes.len());
    for (index, hash) in hashes.iter().take(500).enumerate() {
        let analysis = identify_hash(hash);
        let _ = writeln!(out, "[{}] {analysis}", index + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn identifies_lines() {
        let report = super::report("hashcat", "5f4dcc3b5aa765d61d8327deb882cf99\n");
        assert!(report.contains("Candidate hashes analyzed: 1"));
    }
}
