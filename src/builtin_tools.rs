use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const AUTOPSY_MAX_FILES: usize = 100_000;
const VOLATILITY_MIN_STRING_LENGTH: usize = 8;
const VOLATILITY_MAX_REPORTED_STRINGS: usize = 200;
const VOLATILITY_MAX_STRING_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceFile {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopsyReport {
    pub root: PathBuf,
    pub directories: usize,
    pub total_bytes: u64,
    pub files: Vec<EvidenceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryString {
    pub offset: u64,
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedSignature {
    pub kind: &'static str,
    pub occurrences: u64,
    pub first_offset: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VolatilityReport {
    pub image: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub shannon_entropy: f64,
    pub zero_bytes: u64,
    pub printable_bytes: u64,
    pub signatures: Vec<EmbeddedSignature>,
    pub strings_found: u64,
    pub strings: Vec<MemoryString>,
}

impl fmt::Display for AutopsyReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Autopsy Local Evidence Report")?;
        writeln!(formatter, "=============================")?;
        writeln!(formatter, "Implementation : Built-in substitute")?;
        writeln!(formatter, "Network used   : No")?;
        writeln!(formatter, "Evidence root  : {}", self.root.display())?;
        writeln!(formatter)?;
        writeln!(formatter, "Summary")?;
        writeln!(formatter, "-------")?;
        writeln!(formatter, "Directories    : {}", self.directories)?;
        writeln!(formatter, "Regular files  : {}", self.files.len())?;
        writeln!(formatter, "Total bytes    : {}", self.total_bytes)?;
        writeln!(formatter)?;
        writeln!(formatter, "Evidence Files")?;
        writeln!(formatter, "--------------")?;
        for (index, file) in self.files.iter().enumerate() {
            writeln!(
                formatter,
                "{}. {}\n   Size   : {} bytes\n   SHA-256: {}",
                index + 1,
                file.path.display(),
                file.bytes,
                file.sha256
            )?;
        }
        Ok(())
    }
}

impl fmt::Display for VolatilityReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Volatility Local Memory Report")?;
        writeln!(formatter, "==============================")?;
        writeln!(formatter, "Implementation : Built-in substitute")?;
        writeln!(formatter, "Network used   : No")?;
        writeln!(formatter, "Memory image   : {}", self.image.display())?;
        writeln!(formatter)?;
        writeln!(formatter, "Image Summary")?;
        writeln!(formatter, "-------------")?;
        writeln!(formatter, "Size           : {} bytes", self.bytes)?;
        writeln!(formatter, "SHA-256        : {}", self.sha256)?;
        writeln!(
            formatter,
            "Entropy        : {:.6} bits/byte",
            self.shannon_entropy
        )?;
        writeln!(formatter, "Zero bytes     : {}", self.zero_bytes)?;
        writeln!(formatter, "Printable bytes: {}", self.printable_bytes)?;
        writeln!(formatter)?;
        writeln!(formatter, "Embedded Signatures")?;
        writeln!(formatter, "-------------------")?;
        if self.signatures.is_empty() {
            writeln!(formatter, "None detected")?;
        } else {
            for signature in &self.signatures {
                writeln!(
                    formatter,
                    "{}: {} occurrence(s), first at byte offset {}",
                    signature.kind, signature.occurrences, signature.first_offset
                )?;
            }
        }
        writeln!(formatter)?;
        writeln!(formatter, "Printable Strings")?;
        writeln!(formatter, "-----------------")?;
        writeln!(formatter, "Total found     : {}", self.strings_found)?;
        writeln!(formatter, "Reported        : {}", self.strings.len())?;
        for (index, string) in self.strings.iter().enumerate() {
            let suffix = if string.truncated { " [truncated]" } else { "" };
            writeln!(
                formatter,
                "{}. offset {}: {}{}",
                index + 1,
                string.offset,
                string.text,
                suffix
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum BuiltInToolError {
    UnsupportedTool(String),
    InvalidInput(String),
    Io { path: PathBuf, source: io::Error },
    FileLimitExceeded { limit: usize },
    SizeOverflow,
    /// A native offline arsenal substitute failed (see [`crate::arsenal`]).
    Arsenal(String),
}

impl fmt::Display for BuiltInToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTool(name) => write!(formatter, "no built-in substitute for {name}"),
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::FileLimitExceeded { limit } => {
                write!(formatter, "evidence file limit exceeded: {limit}")
            }
            Self::SizeOverflow => formatter.write_str("evidence byte total overflowed"),
            Self::Arsenal(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for BuiltInToolError {}

#[must_use]
pub fn is_builtin_tool(name: &str) -> bool {
    matches!(
        name,
        "autopsy"
            | "volatility"
            | "wireshark"
            | "binwalk"
            | "foremost"
            | "bulk_extractor"
            | "hashdeep"
    ) || crate::arsenal::handles(name)
}

/// Runs the built-in substitute named `name` against `input` and renders
/// its report as a display string.
///
/// # Errors
///
/// Returns [`BuiltInToolError::UnsupportedTool`] if `name` has no built-in
/// substitute, or whatever error the underlying tool returns (invalid
/// input, I/O failure, or an internal limit being exceeded).
pub fn run_builtin_tool(name: &str, input: &Path) -> Result<String, BuiltInToolError> {
    match name {
        "autopsy" => Ok(run_autopsy(input)?.to_string()),
        "volatility" => Ok(run_volatility(input)?.to_string()),
        "wireshark" => Ok(crate::pcap::run_wireshark(input)?.to_string()),
        "binwalk" => Ok(crate::local_analyzers::run_binwalk(input)?.to_string()),
        "foremost" => Ok(crate::local_analyzers::run_foremost(input)?.to_string()),
        "bulk_extractor" => Ok(crate::local_analyzers::run_bulk_extractor(input)?.to_string()),
        "hashdeep" => Ok(crate::local_analyzers::run_hashdeep(input)?.to_string()),
        // Every other cataloged tool is served by a native, offline arsenal
        // substitute (see `crate::arsenal`). No network access, no external
        // binary is ever spawned.
        other => crate::arsenal::run(other, input)
            .map_err(|error| BuiltInToolError::Arsenal(error.to_string())),
    }
}

/// Inventories and hashes the evidence file or directory at `input`.
///
/// # Errors
///
/// Returns [`BuiltInToolError::InvalidInput`] if `input` is a symbolic link
/// or neither a regular file nor a directory, [`BuiltInToolError::Io`] on
/// any filesystem failure, and [`BuiltInToolError::FileLimitExceeded`] or
/// [`BuiltInToolError::SizeOverflow`] if the evidence set exceeds internal
/// bounds.
pub fn run_autopsy(input: &Path) -> Result<AutopsyReport, BuiltInToolError> {
    let input_metadata = fs::symlink_metadata(input).map_err(|source| BuiltInToolError::Io {
        path: input.to_path_buf(),
        source,
    })?;
    if input_metadata.file_type().is_symlink() {
        return Err(BuiltInToolError::InvalidInput(
            "evidence root must not be a symbolic link".to_string(),
        ));
    }

    let root = input
        .canonicalize()
        .map_err(|source| BuiltInToolError::Io {
            path: input.to_path_buf(),
            source,
        })?;
    let metadata = fs::symlink_metadata(&root).map_err(|source| BuiltInToolError::Io {
        path: root.clone(),
        source,
    })?;

    let mut report = AutopsyReport {
        root: root.clone(),
        directories: 0,
        total_bytes: 0,
        files: Vec::new(),
    };

    if metadata.is_file() {
        add_evidence_file(&root, &root, &metadata, &mut report)?;
    } else if metadata.is_dir() {
        walk_evidence(&root, &root, &mut report)?;
    } else {
        return Err(BuiltInToolError::InvalidInput(
            "evidence root must be a regular file or directory".to_string(),
        ));
    }

    report
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(report)
}

/// Analyzes the memory image or binary at `input`: hashes it, estimates
/// its byte entropy, detects embedded ELF/PE/ZIP signatures, and extracts
/// bounded printable strings.
///
/// # Errors
///
/// Returns [`BuiltInToolError::InvalidInput`] if `input` is a symbolic link
/// or not a regular file, [`BuiltInToolError::Io`] on any filesystem
/// failure, and [`BuiltInToolError::SizeOverflow`] if the image is larger
/// than `u64::MAX` bytes.
pub fn run_volatility(input: &Path) -> Result<VolatilityReport, BuiltInToolError> {
    let input_metadata = fs::symlink_metadata(input).map_err(|source| BuiltInToolError::Io {
        path: input.to_path_buf(),
        source,
    })?;
    if input_metadata.file_type().is_symlink() {
        return Err(BuiltInToolError::InvalidInput(
            "memory image must not be a symbolic link".to_string(),
        ));
    }
    if !input_metadata.is_file() {
        return Err(BuiltInToolError::InvalidInput(
            "memory image must be a regular file".to_string(),
        ));
    }

    let image = input
        .canonicalize()
        .map_err(|source| BuiltInToolError::Io {
            path: input.to_path_buf(),
            source,
        })?;
    let mut file = File::open(&image).map_err(|source| BuiltInToolError::Io {
        path: image.clone(),
        source,
    })?;
    let mut sha256 = Sha256::new();
    let mut frequencies = [0_u64; 256];
    let mut bytes = 0_u64;
    let mut strings = StringScan::new();
    let mut signatures = SignatureScan::new();
    // Heap-allocated: a 64KiB array on the stack trips clippy's
    // large-stack-arrays lint and needlessly grows every call frame.
    let mut buffer = vec![0_u8; 64 * 1024];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|source| BuiltInToolError::Io {
                path: image.clone(),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }
        sha256.update(&buffer[..bytes_read]);
        for &byte in &buffer[..bytes_read] {
            let offset = bytes;
            bytes = bytes.checked_add(1).ok_or(BuiltInToolError::SizeOverflow)?;
            frequencies[byte as usize] += 1;
            strings.observe(byte, offset);
            signatures.observe(byte, offset);
        }
    }
    strings.finish_current();

    Ok(VolatilityReport {
        image,
        bytes,
        sha256: sha256.finalize_hex(),
        shannon_entropy: shannon_entropy(&frequencies, bytes),
        zero_bytes: frequencies[0],
        printable_bytes: strings.printable_bytes,
        signatures: signatures.into_signatures(),
        strings_found: strings.found,
        strings: strings.reported,
    })
}

/// Incrementally finds printable-ASCII runs in a byte stream, matching the
/// same min-length/max-reported/max-length bounds as the original inline
/// scan in `run_volatility`.
struct StringScan {
    printable_bytes: u64,
    found: u64,
    reported: Vec<MemoryString>,
    start: u64,
    length: usize,
    bytes: Vec<u8>,
}

impl StringScan {
    fn new() -> Self {
        Self {
            printable_bytes: 0,
            found: 0,
            reported: Vec::new(),
            start: 0,
            length: 0,
            bytes: Vec::with_capacity(VOLATILITY_MAX_STRING_LENGTH),
        }
    }

    fn observe(&mut self, byte: u8, offset: u64) {
        if byte.is_ascii_graphic() || byte == b' ' {
            self.printable_bytes += 1;
            if self.length == 0 {
                self.start = offset;
            }
            self.length += 1;
            if self.bytes.len() < VOLATILITY_MAX_STRING_LENGTH {
                self.bytes.push(byte);
            }
        } else {
            self.finish_current();
        }
    }

    fn finish_current(&mut self) {
        if self.length >= VOLATILITY_MIN_STRING_LENGTH {
            self.found += 1;
            if self.reported.len() < VOLATILITY_MAX_REPORTED_STRINGS {
                self.reported.push(MemoryString {
                    offset: self.start,
                    text: String::from_utf8_lossy(&self.bytes).into_owned(),
                    truncated: self.length > self.bytes.len(),
                });
            }
        }
        self.bytes.clear();
        self.length = 0;
    }
}

/// Incrementally detects embedded MZ/ELF/ZIP signatures via a 4-byte rolling
/// window, matching the same detection logic as the original inline scan.
struct SignatureScan {
    rolling: [u8; 4],
    rolling_len: usize,
    mz: (u64, u64),
    elf: (u64, u64),
    zip: (u64, u64),
}

impl SignatureScan {
    const fn new() -> Self {
        Self {
            rolling: [0; 4],
            rolling_len: 0,
            mz: (0, 0),
            elf: (0, 0),
            zip: (0, 0),
        }
    }

    fn observe(&mut self, byte: u8, offset: u64) {
        if self.rolling_len < self.rolling.len() {
            self.rolling[self.rolling_len] = byte;
            self.rolling_len += 1;
        } else {
            self.rolling.copy_within(1.., 0);
            self.rolling[3] = byte;
        }
        if self.rolling_len >= 2 && self.rolling[self.rolling_len - 2..self.rolling_len] == *b"MZ" {
            Self::record_signature(&mut self.mz, offset - 1);
        }
        if self.rolling_len == 4 {
            if self.rolling == *b"\x7fELF" {
                Self::record_signature(&mut self.elf, offset - 3);
            }
            if self.rolling == *b"PK\x03\x04" {
                Self::record_signature(&mut self.zip, offset - 3);
            }
        }
    }

    fn into_signatures(self) -> Vec<EmbeddedSignature> {
        let mut signatures = Vec::new();
        Self::append_signature(&mut signatures, "PE/COFF MZ", self.mz);
        Self::append_signature(&mut signatures, "ELF", self.elf);
        Self::append_signature(&mut signatures, "ZIP", self.zip);
        signatures
    }

    const fn record_signature(signature: &mut (u64, u64), offset: u64) {
        if signature.0 == 0 {
            signature.1 = offset;
        }
        signature.0 += 1;
    }

    fn append_signature(
        signatures: &mut Vec<EmbeddedSignature>,
        kind: &'static str,
        signature: (u64, u64),
    ) {
        if signature.0 > 0 {
            signatures.push(EmbeddedSignature {
                kind,
                occurrences: signature.0,
                first_offset: signature.1,
            });
        }
    }
}

// Byte counts are bounded by the size of a local file/memory image; the
// precision loss from converting to f64 for an entropy estimate only
// matters above 2^52 bytes, far beyond anything this tool will ever read.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn shannon_entropy(frequencies: &[u64; 256], bytes: u64) -> f64 {
    if bytes == 0 {
        return 0.0;
    }
    frequencies
        .iter()
        .filter(|frequency| **frequency > 0)
        .map(|frequency| {
            let probability = *frequency as f64 / bytes as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn walk_evidence(
    root: &Path,
    directory: &Path,
    report: &mut AutopsyReport,
) -> Result<(), BuiltInToolError> {
    report.directories += 1;
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
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk_evidence(root, &path, report)?;
        } else if metadata.is_file() {
            add_evidence_file(root, &path, &metadata, report)?;
        }
    }

    Ok(())
}

fn add_evidence_file(
    root: &Path,
    path: &Path,
    metadata: &fs::Metadata,
    report: &mut AutopsyReport,
) -> Result<(), BuiltInToolError> {
    if report.files.len() >= AUTOPSY_MAX_FILES {
        return Err(BuiltInToolError::FileLimitExceeded {
            limit: AUTOPSY_MAX_FILES,
        });
    }
    report.total_bytes = report
        .total_bytes
        .checked_add(metadata.len())
        .ok_or(BuiltInToolError::SizeOverflow)?;
    let relative_path = if root == path {
        path.file_name()
            .map_or_else(|| path.to_path_buf(), PathBuf::from)
    } else {
        path.strip_prefix(root).map(PathBuf::from).map_err(|_| {
            BuiltInToolError::InvalidInput(format!(
                "{} escaped evidence root {}",
                path.display(),
                root.display()
            ))
        })?
    };
    report.files.push(EvidenceFile {
        path: relative_path,
        bytes: metadata.len(),
        sha256: sha256_file(path)?,
    });
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, BuiltInToolError> {
    let mut file = File::open(path).map_err(|source| BuiltInToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|source| BuiltInToolError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }
        sha256.update(&buffer[..bytes_read]);
    }
    Ok(sha256.finalize_hex())
}

pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    bit_len: u64,
}

impl Sha256 {
    pub(crate) const fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.bit_len = self
            .bit_len
            .wrapping_add((input.len() as u64).wrapping_mul(8));
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            let copied = needed.min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_len += copied;
            input = &input[copied..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.transform(&block);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            self.transform(&input[..64]);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    pub(crate) fn finalize_hex(mut self) -> String {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.transform(&block);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&self.bit_len.to_be_bytes());
        let block = self.buffer;
        self.transform(&block);

        let mut hex = String::with_capacity(self.state.len() * 8);
        for word in &self.state {
            let _ = write!(hex, "{word:08x}");
        }
        hex
    }

    // Variable names (a-h, s0/s1, k, w) mirror FIPS 180-4 section 6.2.2
    // directly; renaming them would make this harder to check against the
    // spec, not easier. The 64-round compression loop and its constant
    // table are why this exceeds the line-count lint; splitting it up
    // would fragment one contiguous algorithm step across functions.
    #[allow(clippy::many_single_char_names, clippy::too_many_lines)]
    fn transform(&mut self, block: &[u8]) {
        const K: [u32; 64] = [
            0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5,
            0x3956_c25b,
            0x59f1_11f1,
            0x923f_82a4,
            0xab1c_5ed5,
            0xd807_aa98,
            0x1283_5b01,
            0x2431_85be,
            0x550c_7dc3,
            0x72be_5d74,
            0x80de_b1fe,
            0x9bdc_06a7,
            0xc19b_f174,
            0xe49b_69c1,
            0xefbe_4786,
            0x0fc1_9dc6,
            0x240c_a1cc,
            0x2de9_2c6f,
            0x4a74_84aa,
            0x5cb0_a9dc,
            0x76f9_88da,
            0x983e_5152,
            0xa831_c66d,
            0xb003_27c8,
            0xbf59_7fc7,
            0xc6e0_0bf3,
            0xd5a7_9147,
            0x06ca_6351,
            0x1429_2967,
            0x27b7_0a85,
            0x2e1b_2138,
            0x4d2c_6dfc,
            0x5338_0d13,
            0x650a_7354,
            0x766a_0abb,
            0x81c2_c92e,
            0x9272_2c85,
            0xa2bf_e8a1,
            0xa81a_664b,
            0xc24b_8b70,
            0xc76c_51a3,
            0xd192_e819,
            0xd699_0624,
            0xf40e_3585,
            0x106a_a070,
            0x19a4_c116,
            0x1e37_6c08,
            0x2748_774c,
            0x34b0_bcb5,
            0x391c_0cb3,
            0x4ed8_aa4a,
            0x5b9c_ca4f,
            0x682e_6ff3,
            0x748f_82ee,
            0x78a5_636f,
            0x84c8_7814,
            0x8cc7_0208,
            0x90be_fffa,
            0xa450_6ceb,
            0xbef9_a3f7,
            0xc671_78f2,
        ];
        let mut words = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).take(16).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha256_matches_standard_digest() {
        let mut sha256 = Sha256::new();
        sha256.update(b"abc");
        assert_eq!(
            sha256.finalize_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_matches_empty_string_vector() {
        let sha256 = Sha256::new();
        assert_eq!(
            sha256.finalize_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_matches_one_million_a_vector() {
        let mut sha256 = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            sha256.update(&chunk);
        }
        assert_eq!(
            sha256.finalize_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn autopsy_reports_real_file_content() {
        let root =
            std::env::temp_dir().join(format!("security-agent-autopsy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create evidence directory");
        let file_path = root.join("evidence.bin");
        let mut file = File::create(&file_path).expect("create evidence file");
        file.write_all(b"abc").expect("write evidence");

        let report = run_autopsy(&root).expect("analyze evidence");

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.total_bytes, 3);
        assert_eq!(
            report.files[0].sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::remove_dir_all(root).expect("remove evidence directory");
    }

    #[cfg(unix)]
    #[test]
    fn autopsy_rejects_symbolic_link_root() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "security-agent-autopsy-symlink-{}",
            std::process::id()
        ));
        let target = root.with_extension("target");
        let _ = fs::remove_file(&root);
        let _ = fs::remove_file(&target);
        File::create(&target).expect("create evidence target");
        symlink(&target, &root).expect("create evidence symlink");

        let result = run_autopsy(&root);

        assert!(matches!(result, Err(BuiltInToolError::InvalidInput(_))));
        fs::remove_file(root).expect("remove evidence symlink");
        fs::remove_file(target).expect("remove evidence target");
    }

    #[test]
    fn volatility_analyzes_real_executable() {
        let executable = std::env::current_exe().expect("resolve current executable");

        let report = run_volatility(&executable).expect("analyze current executable");

        assert!(report.bytes > 0);
        assert_eq!(report.sha256.len(), 64);
        assert!(report.shannon_entropy > 0.0);
        assert!(report.printable_bytes > 0);
        assert!(report.strings_found > 0);
        #[cfg(target_os = "linux")]
        assert!(
            report
                .signatures
                .iter()
                .any(|signature| signature.kind == "ELF")
        );
    }
}
