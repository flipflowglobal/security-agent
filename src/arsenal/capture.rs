//! Passive-capture analysis engine.
//!
//! Serves the sniffing tools (`tcpdump`, `netsniff-ng`, `ettercap`,
//! `driftnet`, `mitmproxy`). Live capture is never performed; instead a
//! supplied capture file is analyzed offline. A real pcap gets the crate's
//! genuine packet analyzer; any other capture blob falls back to the shared
//! binary triage.

use std::path::Path;

use super::{ArsenalError, banner};

pub(super) fn report(tool: &str, input: &Path) -> Result<String, ArsenalError> {
    // A pcap file has a genuine builtin analyzer; reuse it. Otherwise fall
    // back to a generic binary analysis of the capture bytes.
    crate::pcap::run_wireshark(input).map_or_else(
        |_| super::mobile::binary_triage(tool, input, "Passive Capture Analysis"),
        |report| {
            Ok(format!(
                "{}{report}\n",
                banner(tool, &format!("{tool} — Passive Capture Analysis"), input)
            ))
        },
    )
}
