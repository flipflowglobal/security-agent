//! Evidence capture and chain-of-custody (Stage-4 territory).
//!
//! This module is a placeholder to be implemented: it will archive the raw
//! output of each executed tool alongside a content hash (reusing the
//! in-house SHA-256 in [`crate::builtin_tools`]) and provenance metadata, so
//! every finding is defensibly traceable back to the exact tool output that
//! produced it.
