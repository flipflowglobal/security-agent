//! Targeted wordlist-generation engine.
//!
//! Serves `crunch` (keyspace generation) and `cewl` (site-derived word
//! harvesting). The offline substitute takes a seed target on the first line
//! plus optional extra seed words and expands them into a candidate list
//! using the same mutation rules the credential engine understands.

use std::fmt::Write as _;

use super::{payload_lines, text_banner};
use crate::offensive::credential_attack::generate_targeted_wordlist;

pub(super) fn report(tool: &str, text: &str) -> String {
    let lines = payload_lines(text);
    let mut out = text_banner(tool, "Targeted Wordlist Generation");
    let Some((target, extra)) = lines.split_first() else {
        out.push_str("Provide a target/seed word on the first line, optional extra words after.\n");
        return out;
    };
    let wordlist = generate_targeted_wordlist(target, None, None, extra);
    let _ = writeln!(
        out,
        "Seed target    : {target}\nExtra seeds    : {}\nGenerated words: {}\n",
        extra.len(),
        wordlist.len()
    );
    for word in wordlist.iter().take(1000) {
        out.push_str(word);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn expands_a_seed() {
        let report = super::report("crunch", "acme\n");
        assert!(report.contains("Seed target    : acme"));
        assert!(report.contains("Generated words:"));
    }
}
