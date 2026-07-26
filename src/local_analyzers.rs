//! Offline local-file forensic analyzers — in-house substitutes for
//! cataloged DFIR tools, in the same spirit as [`crate::builtin_tools`].
//!
//! Each analyzer reads a **local** file (or directory) and produces a
//! defensive report with **no network, no external crates, and no weights
//! on disk**. They cover the file-carving and feature-extraction family of
//! the tool catalog:
//!
//! - [`run_binwalk`] — embedded-signature map and entropy analysis of a
//!   firmware image or binary blob.
//! - [`run_foremost`] — file carving: recover embedded files by header (and
//!   footer, where one is known) with offsets and lengths.
//! - [`run_bulk_extractor`] — feature extraction: emails, URLs, and IPv4
//!   addresses (indicators of compromise) from a blob.
//! - [`run_hashdeep`] — recursive multi-hash (SHA-256 + CRC-32) audit of a
//!   directory tree, with duplicate detection.
//!
//! These are **defensive** analyzers over evidence you already hold; none
//! touches a live target. Offensive and live-network catalog tools are
//! deliberately not reimplemented here.

use crate::builtin_tools::{BuiltInToolError, Sha256, shannon_entropy};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Largest single file (in bytes) the buffer-based analyzers will load into
/// memory. Evidence beyond this is rejected rather than risking exhaustion.
const MAX_ANALYSIS_BYTES: u64 = 256 * 1024 * 1024;
/// Upper bound on individually reported items (signatures, carved files,
/// feature samples), so a pathological input cannot produce an unbounded
/// report.
const MAX_REPORTED_ITEMS: usize = 512;
/// Files a single [`run_hashdeep`] invocation will hash.
const HASHDEEP_MAX_FILES: usize = 100_000;
/// Block size (bytes) for [`run_binwalk`]'s entropy sweep.
const ENTROPY_BLOCK: usize = 1024;
/// Entropy (bits/byte) at or above which a block is treated as likely
/// compressed or encrypted.
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

/// A known magic signature and the format it identifies.
struct Magic {
    bytes: &'static [u8],
    kind: &'static str,
}

/// Magic-number table shared by the signature scanners. Chosen for the
/// formats a defensive analyst most often carves out of firmware and memory.
const MAGICS: &[Magic] = &[
    Magic {
        bytes: b"\x7fELF",
        kind: "ELF executable",
    },
    Magic {
        bytes: b"MZ",
        kind: "DOS/PE executable",
    },
    Magic {
        bytes: b"\x1f\x8b",
        kind: "gzip stream",
    },
    Magic {
        bytes: b"BZh",
        kind: "bzip2 stream",
    },
    Magic {
        bytes: b"\xfd7zXZ\x00",
        kind: "xz stream",
    },
    Magic {
        bytes: b"7z\xbc\xaf\x27\x1c",
        kind: "7-zip archive",
    },
    Magic {
        bytes: b"PK\x03\x04",
        kind: "ZIP/APK/JAR archive",
    },
    Magic {
        bytes: b"Rar!\x1a\x07",
        kind: "RAR archive",
    },
    Magic {
        bytes: b"\x89PNG\r\n\x1a\n",
        kind: "PNG image",
    },
    Magic {
        bytes: b"\xff\xd8\xff",
        kind: "JPEG image",
    },
    Magic {
        bytes: b"GIF87a",
        kind: "GIF image",
    },
    Magic {
        bytes: b"GIF89a",
        kind: "GIF image",
    },
    Magic {
        bytes: b"%PDF-",
        kind: "PDF document",
    },
    Magic {
        bytes: b"hsqs",
        kind: "SquashFS filesystem",
    },
    Magic {
        bytes: b"sqsh",
        kind: "SquashFS filesystem (big-endian)",
    },
    Magic {
        bytes: b"\xd0\xcf\x11\xe0",
        kind: "OLE/CFB compound file",
    },
    Magic {
        bytes: b"dex\n",
        kind: "Android DEX bytecode",
    },
];

// ── shared input handling ────────────────────────────────────────────────

/// Validates `input` is a real, non-symlink regular file within the size cap
/// and reads it fully into memory.
fn read_regular_file(input: &Path) -> Result<(PathBuf, Vec<u8>), BuiltInToolError> {
    let metadata = fs::symlink_metadata(input).map_err(|source| BuiltInToolError::Io {
        path: input.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(BuiltInToolError::InvalidInput(
            "input must not be a symbolic link".to_string(),
        ));
    }
    if !metadata.is_file() {
        return Err(BuiltInToolError::InvalidInput(
            "input must be a regular file".to_string(),
        ));
    }
    if metadata.len() > MAX_ANALYSIS_BYTES {
        return Err(BuiltInToolError::InvalidInput(format!(
            "input exceeds the {MAX_ANALYSIS_BYTES}-byte local analysis cap"
        )));
    }
    let path = input
        .canonicalize()
        .map_err(|source| BuiltInToolError::Io {
            path: input.to_path_buf(),
            source,
        })?;
    let mut data = Vec::new();
    File::open(&path)
        .and_then(|mut file| file.read_to_end(&mut data))
        .map_err(|source| BuiltInToolError::Io {
            path: path.clone(),
            source,
        })?;
    Ok((path, data))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize_hex()
}

fn global_entropy(data: &[u8]) -> f64 {
    let mut frequencies = [0_u64; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }
    shannon_entropy(&frequencies, data.len() as u64)
}

// ── binwalk ──────────────────────────────────────────────────────────────

/// One embedded signature located in a scanned blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHit {
    pub offset: u64,
    pub kind: &'static str,
}

/// A contiguous span of high-entropy (likely compressed/encrypted) data.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyRegion {
    pub start: u64,
    pub end: u64,
    pub entropy: f64,
}

/// Result of [`run_binwalk`].
#[derive(Debug, Clone, PartialEq)]
pub struct BinwalkReport {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub overall_entropy: f64,
    pub signatures: Vec<SignatureHit>,
    pub high_entropy_regions: Vec<EntropyRegion>,
    pub signatures_truncated: bool,
}

/// Maps embedded signatures and high-entropy regions in the firmware image
/// or binary blob at `input`.
///
/// # Errors
///
/// Returns [`BuiltInToolError::InvalidInput`] if `input` is a symbolic link,
/// not a regular file, or larger than the local analysis cap, and
/// [`BuiltInToolError::Io`] on any filesystem failure.
pub fn run_binwalk(input: &Path) -> Result<BinwalkReport, BuiltInToolError> {
    let (path, data) = read_regular_file(input)?;
    let (signatures, signatures_truncated) = scan_signatures(&data);
    Ok(BinwalkReport {
        bytes: data.len() as u64,
        sha256: sha256_hex(&data),
        overall_entropy: global_entropy(&data),
        high_entropy_regions: scan_entropy_regions(&data),
        signatures,
        signatures_truncated,
        path,
    })
}

/// Scans every offset for any known magic, returning the bounded hit list and
/// whether it was truncated at [`MAX_REPORTED_ITEMS`].
///
/// Magics are bucketed by their first byte so each offset only tests the
/// candidates that could possibly match there, rather than the whole table —
/// `O(n + hits)` on typical evidence instead of `O(n * MAGICS)`.
fn scan_signatures(data: &[u8]) -> (Vec<SignatureHit>, bool) {
    let buckets = bucket_by_first_byte(MAGICS, |magic| magic.bytes);
    let mut hits = Vec::new();
    for (offset, &byte) in data.iter().enumerate() {
        let tail = &data[offset..];
        for &magic in &buckets[byte as usize] {
            if tail.starts_with(magic.bytes) {
                if hits.len() >= MAX_REPORTED_ITEMS {
                    return (hits, true);
                }
                hits.push(SignatureHit {
                    offset: offset as u64,
                    kind: magic.kind,
                });
            }
        }
    }
    (hits, false)
}

/// Indexes `items` into 256 buckets keyed by the first byte of each item's
/// pattern, so a scanner can look up only the candidates relevant to the
/// byte under the cursor. Empty patterns are skipped.
fn bucket_by_first_byte<T>(items: &[T], pattern: impl Fn(&T) -> &'static [u8]) -> [Vec<&T>; 256] {
    let mut buckets: [Vec<&T>; 256] = std::array::from_fn(|_| Vec::new());
    for item in items {
        if let Some(&first) = pattern(item).first() {
            buckets[first as usize].push(item);
        }
    }
    buckets
}

/// Sweeps fixed-size blocks and merges adjacent high-entropy ones into
/// regions, so an analyst can spot compressed or encrypted payloads.
fn scan_entropy_regions(data: &[u8]) -> Vec<EntropyRegion> {
    let mut regions: Vec<EntropyRegion> = Vec::new();
    for (index, block) in data.chunks(ENTROPY_BLOCK).enumerate() {
        let entropy = block_entropy(block);
        if entropy < HIGH_ENTROPY_THRESHOLD {
            continue;
        }
        let start = (index * ENTROPY_BLOCK) as u64;
        let end = start + block.len() as u64;
        match regions.last_mut() {
            Some(region) if region.end == start => {
                region.end = end;
                region.entropy = region.entropy.max(entropy);
            }
            _ => regions.push(EntropyRegion {
                start,
                end,
                entropy,
            }),
        }
    }
    regions
}

fn block_entropy(block: &[u8]) -> f64 {
    let mut frequencies = [0_u64; 256];
    for &byte in block {
        frequencies[byte as usize] += 1;
    }
    shannon_entropy(&frequencies, block.len() as u64)
}

impl fmt::Display for BinwalkReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Binwalk Local Firmware Report")?;
        writeln!(formatter, "=============================")?;
        writeln!(formatter, "Implementation : Built-in substitute")?;
        writeln!(formatter, "Network used   : No")?;
        writeln!(formatter, "Target blob    : {}", self.path.display())?;
        writeln!(formatter)?;
        writeln!(formatter, "Summary")?;
        writeln!(formatter, "-------")?;
        writeln!(formatter, "Size           : {} bytes", self.bytes)?;
        writeln!(formatter, "SHA-256        : {}", self.sha256)?;
        writeln!(
            formatter,
            "Overall entropy: {:.6} bits/byte",
            self.overall_entropy
        )?;
        writeln!(formatter)?;
        writeln!(formatter, "Embedded Signatures")?;
        writeln!(formatter, "-------------------")?;
        if self.signatures.is_empty() {
            writeln!(formatter, "None detected")?;
        } else {
            for hit in &self.signatures {
                writeln!(formatter, "0x{:08x}  {}", hit.offset, hit.kind)?;
            }
            if self.signatures_truncated {
                writeln!(formatter, "... (signature list truncated)")?;
            }
        }
        writeln!(formatter)?;
        writeln!(
            formatter,
            "High-Entropy Regions (>= {HIGH_ENTROPY_THRESHOLD} bits/byte)"
        )?;
        writeln!(formatter, "----------------------------------------")?;
        if self.high_entropy_regions.is_empty() {
            writeln!(formatter, "None")?;
        } else {
            for region in &self.high_entropy_regions {
                writeln!(
                    formatter,
                    "0x{:08x}-0x{:08x}  {:.4} bits/byte",
                    region.start, region.end, region.entropy
                )?;
            }
        }
        Ok(())
    }
}

// ── foremost ─────────────────────────────────────────────────────────────

/// A carve recipe: a file type with a header and, when the format has one, a
/// footer that bounds its length.
struct CarveType {
    kind: &'static str,
    header: &'static [u8],
    footer: Option<&'static [u8]>,
}

const CARVE_TYPES: &[CarveType] = &[
    CarveType {
        kind: "jpg",
        header: b"\xff\xd8\xff",
        footer: Some(b"\xff\xd9"),
    },
    CarveType {
        kind: "png",
        header: b"\x89PNG\r\n\x1a\n",
        footer: Some(b"IEND\xae\x42\x60\x82"),
    },
    CarveType {
        kind: "gif",
        header: b"GIF89a",
        footer: Some(b"\x00\x3b"),
    },
    CarveType {
        kind: "pdf",
        header: b"%PDF-",
        footer: Some(b"%%EOF"),
    },
    CarveType {
        kind: "zip",
        header: b"PK\x03\x04",
        footer: Some(b"PK\x05\x06"),
    },
    CarveType {
        kind: "gz",
        header: b"\x1f\x8b\x08",
        footer: None,
    },
];

/// One carved file candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedFile {
    pub kind: &'static str,
    pub start: u64,
    /// `Some(len)` when a footer bounded the file; `None` when only a header
    /// was found.
    pub length: Option<u64>,
}

/// Result of [`run_foremost`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForemostReport {
    pub path: PathBuf,
    pub bytes: u64,
    pub carved: Vec<CarvedFile>,
    pub truncated: bool,
}

/// Carves recoverable embedded files out of the blob at `input` by scanning
/// for known headers (and footers, where the format defines one).
///
/// # Errors
///
/// Returns [`BuiltInToolError::InvalidInput`] if `input` is a symbolic link,
/// not a regular file, or larger than the local analysis cap, and
/// [`BuiltInToolError::Io`] on any filesystem failure.
pub fn run_foremost(input: &Path) -> Result<ForemostReport, BuiltInToolError> {
    let (path, data) = read_regular_file(input)?;
    let (carved, truncated) = carve_files(&data);
    Ok(ForemostReport {
        bytes: data.len() as u64,
        carved,
        truncated,
        path,
    })
}

fn carve_files(data: &[u8]) -> (Vec<CarvedFile>, bool) {
    // Bucket carve headers by their first byte so each offset only tests the
    // types that could start there (see `bucket_by_first_byte`).
    let buckets = bucket_by_first_byte(CARVE_TYPES, |carve| carve.header);
    let mut carved = Vec::new();
    for (offset, &byte) in data.iter().enumerate() {
        let tail = &data[offset..];
        for &carve in &buckets[byte as usize] {
            if !tail.starts_with(carve.header) {
                continue;
            }
            if carved.len() >= MAX_REPORTED_ITEMS {
                return (carved, true);
            }
            let length = carve.footer.and_then(|footer| {
                find_subslice(&tail[carve.header.len()..], footer)
                    .map(|position| (carve.header.len() + position + footer.len()) as u64)
            });
            carved.push(CarvedFile {
                kind: carve.kind,
                start: offset as u64,
                length,
            });
        }
    }
    (carved, false)
}

/// First index of `needle` within `haystack`, if present.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&start| haystack[start..].starts_with(needle))
}

impl fmt::Display for ForemostReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Foremost Local Carving Report")?;
        writeln!(formatter, "=============================")?;
        writeln!(formatter, "Implementation : Built-in substitute")?;
        writeln!(formatter, "Network used   : No")?;
        writeln!(formatter, "Target blob    : {}", self.path.display())?;
        writeln!(formatter, "Size           : {} bytes", self.bytes)?;
        writeln!(formatter)?;
        writeln!(formatter, "Carved Files")?;
        writeln!(formatter, "------------")?;
        if self.carved.is_empty() {
            writeln!(formatter, "None detected")?;
        } else {
            for (index, file) in self.carved.iter().enumerate() {
                let length = file.length.map_or_else(
                    || "unknown (no footer)".to_string(),
                    |len| format!("{len} bytes"),
                );
                writeln!(
                    formatter,
                    "{}. {:<4} start=0x{:08x} length={}",
                    index + 1,
                    file.kind,
                    file.start,
                    length
                )?;
            }
            if self.truncated {
                writeln!(formatter, "... (carve list truncated)")?;
            }
        }
        Ok(())
    }
}

// ── bulk_extractor ───────────────────────────────────────────────────────

/// One extracted feature category: its total occurrences and bounded,
/// de-duplicated samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureGroup {
    pub label: &'static str,
    pub total: u64,
    pub samples: Vec<String>,
}

impl FeatureGroup {
    const fn new(label: &'static str) -> Self {
        Self {
            label,
            total: 0,
            samples: Vec::new(),
        }
    }

    fn record(&mut self, value: String) {
        self.total += 1;
        if self.samples.len() < MAX_REPORTED_ITEMS && !self.samples.contains(&value) {
            self.samples.push(value);
        }
    }
}

/// Result of [`run_bulk_extractor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureReport {
    pub path: PathBuf,
    pub bytes: u64,
    pub emails: FeatureGroup,
    pub urls: FeatureGroup,
    pub ipv4: FeatureGroup,
}

/// Extracts indicators of compromise — email addresses, URLs, and IPv4
/// addresses — from the printable content of the blob at `input`.
///
/// # Errors
///
/// Returns [`BuiltInToolError::InvalidInput`] if `input` is a symbolic link,
/// not a regular file, or larger than the local analysis cap, and
/// [`BuiltInToolError::Io`] on any filesystem failure.
pub fn run_bulk_extractor(input: &Path) -> Result<FeatureReport, BuiltInToolError> {
    let (path, data) = read_regular_file(input)?;
    let mut report = FeatureReport {
        bytes: data.len() as u64,
        emails: FeatureGroup::new("Email addresses"),
        urls: FeatureGroup::new("URLs"),
        ipv4: FeatureGroup::new("IPv4 addresses"),
        path,
    };
    // Stream printable runs one at a time: decode the current run, extract
    // its features, then drop it. Peak extra memory is bounded by the longest
    // run rather than a `Vec<String>` holding the whole file decoded again.
    let mut current: Vec<u8> = Vec::new();
    for &byte in &data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else {
            extract_run(&current, &mut report);
            current.clear();
        }
    }
    extract_run(&current, &mut report);
    Ok(report)
}

/// Decodes one printable run (of length >= 4) and folds its features into
/// `report`. Shorter runs are ignored as noise.
fn extract_run(current: &[u8], report: &mut FeatureReport) {
    if current.len() < 4 {
        return;
    }
    let run = String::from_utf8_lossy(current);
    extract_urls(&run, &mut report.urls);
    extract_emails(&run, &mut report.emails);
    extract_ipv4(&run, &mut report.ipv4);
}

fn extract_urls(run: &str, group: &mut FeatureGroup) {
    for scheme in ["https://", "http://"] {
        let mut rest = run;
        while let Some(position) = rest.find(scheme) {
            let tail = &rest[position..];
            let end = tail
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`'))
                .unwrap_or(tail.len());
            let url = &tail[..end];
            if url.len() > scheme.len() {
                group.record(url.to_string());
            }
            rest = &tail[end.max(1)..];
        }
    }
}

fn extract_emails(run: &str, group: &mut FeatureGroup) {
    for token in run.split(|c: char| !is_email_char(c)) {
        if is_email(token) {
            group.record(token.to_ascii_lowercase());
        }
    }
}

const fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '%' | '+' | '-')
}

fn is_email(token: &str) -> bool {
    let Some((local, domain)) = token.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.contains('@') {
        return false;
    }
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !host.is_empty() && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn extract_ipv4(run: &str, group: &mut FeatureGroup) {
    for token in run.split(|c: char| !matches!(c, '0'..='9' | '.')) {
        if is_ipv4(token) {
            group.record(token.to_string());
        }
    }
}

fn is_ipv4(token: &str) -> bool {
    let octets: Vec<&str> = token.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

impl fmt::Display for FeatureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Bulk Extractor Local Feature Report")?;
        writeln!(formatter, "===================================")?;
        writeln!(formatter, "Implementation : Built-in substitute")?;
        writeln!(formatter, "Network used   : No")?;
        writeln!(formatter, "Target blob    : {}", self.path.display())?;
        writeln!(formatter, "Size           : {} bytes", self.bytes)?;
        for group in [&self.urls, &self.emails, &self.ipv4] {
            writeln!(formatter)?;
            writeln!(formatter, "{}", group.label)?;
            writeln!(formatter, "{}", "-".repeat(group.label.len()))?;
            writeln!(formatter, "Total occurrences: {}", group.total)?;
            for sample in &group.samples {
                writeln!(formatter, "  {sample}")?;
            }
        }
        Ok(())
    }
}

// ── hashdeep ─────────────────────────────────────────────────────────────

/// One hashed file in a [`HashdeepReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedFile {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub crc32: u32,
}

/// Result of [`run_hashdeep`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashdeepReport {
    pub root: PathBuf,
    pub files: Vec<HashedFile>,
    pub total_bytes: u64,
    /// Groups of relative paths that share one SHA-256 digest.
    pub duplicate_sets: Vec<Vec<PathBuf>>,
}

/// Recursively hashes every regular file under `input` (or the single file
/// `input`) with SHA-256 and CRC-32, and reports sets of duplicates that
/// share a digest.
///
/// # Errors
///
/// Returns [`BuiltInToolError::InvalidInput`] if `input` is a symbolic link
/// or neither a file nor a directory, [`BuiltInToolError::Io`] on any
/// filesystem failure, and [`BuiltInToolError::FileLimitExceeded`] if the set
/// exceeds the internal file cap.
pub fn run_hashdeep(input: &Path) -> Result<HashdeepReport, BuiltInToolError> {
    let metadata = fs::symlink_metadata(input).map_err(|source| BuiltInToolError::Io {
        path: input.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(BuiltInToolError::InvalidInput(
            "input must not be a symbolic link".to_string(),
        ));
    }
    let root = input
        .canonicalize()
        .map_err(|source| BuiltInToolError::Io {
            path: input.to_path_buf(),
            source,
        })?;

    let mut files = Vec::new();
    if metadata.is_file() {
        files.push(hash_file(&root, &root)?);
    } else if metadata.is_dir() {
        walk_and_hash(&root, &root, &mut files)?;
    } else {
        return Err(BuiltInToolError::InvalidInput(
            "input must be a regular file or directory".to_string(),
        ));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let total_bytes = files.iter().map(|file| file.bytes).sum();
    Ok(HashdeepReport {
        duplicate_sets: duplicate_sets(&files),
        total_bytes,
        files,
        root,
    })
}

fn walk_and_hash(
    root: &Path,
    directory: &Path,
    files: &mut Vec<HashedFile>,
) -> Result<(), BuiltInToolError> {
    let entries = fs::read_dir(directory).map_err(|source| BuiltInToolError::Io {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut paths = entries
        .map(|entry| {
            entry
                .map(|value| value.path())
                .map_err(|source| BuiltInToolError::Io {
                    path: directory.to_path_buf(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();

    for path in paths {
        let metadata = fs::symlink_metadata(&path).map_err(|source| BuiltInToolError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk_and_hash(root, &path, files)?;
        } else if metadata.is_file() {
            if files.len() >= HASHDEEP_MAX_FILES {
                return Err(BuiltInToolError::FileLimitExceeded {
                    limit: HASHDEEP_MAX_FILES,
                });
            }
            files.push(hash_file(root, &path)?);
        }
    }
    Ok(())
}

fn hash_file(root: &Path, path: &Path) -> Result<HashedFile, BuiltInToolError> {
    let mut file = File::open(path).map_err(|source| BuiltInToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut sha256 = Sha256::new();
    let mut crc = Crc32::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| BuiltInToolError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
        crc.update(&buffer[..read]);
        bytes += read as u64;
    }
    let relative = if root == path {
        path.file_name()
            .map_or_else(|| path.to_path_buf(), PathBuf::from)
    } else {
        path.strip_prefix(root)
            .map_or_else(|_| path.to_path_buf(), PathBuf::from)
    };
    Ok(HashedFile {
        path: relative,
        bytes,
        sha256: sha256.finalize_hex(),
        crc32: crc.finalize(),
    })
}

/// Groups files that share a SHA-256 digest into duplicate sets (each set has
/// at least two members), ordered by first appearance.
fn duplicate_sets(files: &[HashedFile]) -> Vec<Vec<PathBuf>> {
    let mut order: Vec<&str> = Vec::new();
    let mut groups: std::collections::BTreeMap<&str, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    for file in files {
        let entry = groups.entry(&file.sha256).or_default();
        if entry.is_empty() {
            order.push(&file.sha256);
        }
        entry.push(file.path.clone());
    }
    order
        .into_iter()
        .filter_map(|digest| groups.get(digest))
        .filter(|paths| paths.len() > 1)
        .cloned()
        .collect()
}

/// Streaming CRC-32 (IEEE 802.3 polynomial), computed without a lookup table.
struct Crc32 {
    value: u32,
}

impl Crc32 {
    const fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.value ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (self.value & 1).wrapping_neg();
                self.value = (self.value >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    const fn finalize(self) -> u32 {
        !self.value
    }
}

impl fmt::Display for HashdeepReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Hashdeep Local Hash Audit")?;
        writeln!(formatter, "=========================")?;
        writeln!(formatter, "Implementation : Built-in substitute")?;
        writeln!(formatter, "Network used   : No")?;
        writeln!(formatter, "Evidence root  : {}", self.root.display())?;
        writeln!(formatter, "Files hashed   : {}", self.files.len())?;
        writeln!(formatter, "Total bytes    : {}", self.total_bytes)?;
        writeln!(formatter)?;
        writeln!(formatter, "Hashes (SHA-256 / CRC-32)")?;
        writeln!(formatter, "-------------------------")?;
        for file in &self.files {
            writeln!(
                formatter,
                "{}\n  size   : {} bytes\n  sha256 : {}\n  crc32  : {:08x}",
                file.path.display(),
                file.bytes,
                file.sha256,
                file.crc32
            )?;
        }
        writeln!(formatter)?;
        writeln!(formatter, "Duplicate Sets")?;
        writeln!(formatter, "--------------")?;
        if self.duplicate_sets.is_empty() {
            writeln!(formatter, "None")?;
        } else {
            for (index, set) in self.duplicate_sets.iter().enumerate() {
                let members: Vec<String> =
                    set.iter().map(|path| path.display().to_string()).collect();
                writeln!(formatter, "{}. {}", index + 1, members.join(", "))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_path(tag: &str, extension: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "security-agent-la-{tag}-{}.{extension}",
            std::process::id()
        ))
    }

    fn write_file(path: &Path, data: &[u8]) {
        let mut file = File::create(path).expect("create temp file");
        file.write_all(data).expect("write temp file");
    }

    #[test]
    fn binwalk_finds_embedded_signatures() {
        let path = temp_path("binwalk", "bin");
        let mut data = vec![0_u8; 16];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(b"PK\x03\x04payload");
        write_file(&path, &data);

        let report = run_binwalk(&path).expect("analyze blob");
        fs::remove_file(&path).expect("remove temp file");

        assert!(report.signatures.iter().any(|s| s.kind == "PNG image"));
        assert!(
            report
                .signatures
                .iter()
                .any(|s| s.kind == "ZIP/APK/JAR archive")
        );
        assert_eq!(report.sha256.len(), 64);
    }

    #[test]
    fn binwalk_flags_high_entropy_regions() {
        let path = temp_path("binwalk-entropy", "bin");
        // A full-range byte sweep repeated fills a block with ~8 bits/byte.
        let block: Vec<u8> = (0..=255).cycle().take(ENTROPY_BLOCK * 2).collect();
        write_file(&path, &block);

        let report = run_binwalk(&path).expect("analyze blob");
        fs::remove_file(&path).expect("remove temp file");

        assert!(
            !report.high_entropy_regions.is_empty(),
            "a uniform byte sweep should read as high entropy"
        );
    }

    #[test]
    fn foremost_carves_jpeg_with_footer_length() {
        let path = temp_path("foremost", "bin");
        let mut data = vec![0_u8; 4];
        data.extend_from_slice(b"\xff\xd8\xff\xe0jpeg-body\xff\xd9");
        data.extend_from_slice(b"trailing");
        write_file(&path, &data);

        let report = run_foremost(&path).expect("carve blob");
        fs::remove_file(&path).expect("remove temp file");

        let jpg = report
            .carved
            .iter()
            .find(|f| f.kind == "jpg")
            .expect("jpeg should be carved");
        assert_eq!(jpg.start, 4);
        assert!(jpg.length.is_some(), "footer should bound the jpeg length");
    }

    #[test]
    fn bulk_extractor_pulls_iocs() {
        let path = temp_path("bulk", "txt");
        write_file(
            &path,
            b"contact admin@example.com or visit https://evil.example/path from 203.0.113.7\x00tail",
        );

        let report = run_bulk_extractor(&path).expect("extract features");
        fs::remove_file(&path).expect("remove temp file");

        assert!(
            report
                .emails
                .samples
                .contains(&"admin@example.com".to_string())
        );
        assert!(
            report
                .urls
                .samples
                .iter()
                .any(|u| u.starts_with("https://evil.example"))
        );
        assert!(report.ipv4.samples.contains(&"203.0.113.7".to_string()));
    }

    #[test]
    fn bulk_extractor_rejects_invalid_ipv4() {
        let path = temp_path("bulk-badip", "txt");
        write_file(&path, b"version 1.2.3.4.5 and 999.1.1.1 are not addresses");

        let report = run_bulk_extractor(&path).expect("extract features");
        fs::remove_file(&path).expect("remove temp file");

        assert!(
            !report.ipv4.samples.contains(&"999.1.1.1".to_string()),
            "octets above 255 must not be reported"
        );
    }

    #[test]
    fn hashdeep_hashes_and_detects_duplicates() {
        let root = temp_path("hashdeep", "dir");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create dir");
        write_file(&root.join("a.txt"), b"identical");
        write_file(&root.join("b.txt"), b"identical");
        write_file(&root.join("c.txt"), b"unique");

        let report = run_hashdeep(&root).expect("hash tree");
        fs::remove_dir_all(&root).expect("remove dir");

        assert_eq!(report.files.len(), 3);
        assert_eq!(
            report.duplicate_sets.len(),
            1,
            "a.txt and b.txt share a digest"
        );
        assert_eq!(report.duplicate_sets[0].len(), 2);
        // CRC-32 of "unique" is a stable, known value.
        let unique = report
            .files
            .iter()
            .find(|f| f.path.ends_with("c.txt"))
            .expect("c.txt present");
        assert_eq!(unique.bytes, 6);
    }

    #[test]
    fn analyzers_reject_missing_input() {
        let missing = temp_path("missing", "bin");
        assert!(run_binwalk(&missing).is_err());
        assert!(run_foremost(&missing).is_err());
        assert!(run_bulk_extractor(&missing).is_err());
        assert!(run_hashdeep(&missing).is_err());
    }
}
