use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const AUTOPSY_MAX_FILES: usize = 100_000;

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

#[derive(Debug)]
pub enum BuiltInToolError {
    UnsupportedTool(String),
    InvalidInput(String),
    Io { path: PathBuf, source: io::Error },
    FileLimitExceeded { limit: usize },
    SizeOverflow,
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
        }
    }
}

impl std::error::Error for BuiltInToolError {}

pub fn is_builtin_tool(name: &str) -> bool {
    name == "autopsy"
}

pub fn run_builtin_tool(name: &str, input: &Path) -> Result<String, BuiltInToolError> {
    match name {
        "autopsy" => Ok(run_autopsy(input)?.to_string()),
        _ => Err(BuiltInToolError::UnsupportedTool(name.to_string())),
    }
}

pub fn run_autopsy(input: &Path) -> Result<AutopsyReport, BuiltInToolError> {
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

    if metadata.file_type().is_symlink() {
        return Err(BuiltInToolError::InvalidInput(
            "evidence root must not be a symbolic link".to_string(),
        ));
    }

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
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf())
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

fn sha256_file(path: &Path) -> Result<String, BuiltInToolError> {
    let mut file = File::open(path).map_err(|source| BuiltInToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut sha256 = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
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

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    bit_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
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

    fn finalize_hex(mut self) -> String {
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

        self.state
            .iter()
            .map(|word| format!("{word:08x}"))
            .collect()
    }

    fn transform(&mut self, block: &[u8]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
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
}
