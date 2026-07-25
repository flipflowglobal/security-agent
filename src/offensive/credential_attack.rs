//! Credential attack tools — hash analysis, password strength assessment,
//! wordlist generation, and brute-force pattern analysis.
//!
//! All implementations are pure Rust with zero external dependencies.

use std::fmt;

// ─── Hash Analysis ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HashAnalysis {
    pub hash: String,
    pub hash_type: String,
    pub length: usize,
    pub is_cracked_pattern: bool,
    pub format_info: String,
    pub john_format: String,
    pub hashcat_mode: Option<u32>,
}

impl fmt::Display for HashAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Hash Analysis")?;
        writeln!(f, "=============")?;
        writeln!(f, "Hash        : {}", truncate_str(&self.hash, 64))?;
        writeln!(f, "Type        : {}", self.hash_type)?;
        writeln!(f, "Length      : {} chars", self.length)?;
        writeln!(f, "Format      : {}", self.format_info)?;
        writeln!(f, "John format : {}", self.john_format)?;
        if let Some(mode) = self.hashcat_mode {
            writeln!(f, "Hashcat mode: {mode}")?;
        }
        Ok(())
    }
}

fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}

/// Identify hash type by length, character set, and prefix patterns.
pub fn identify_hash(hash: &str) -> HashAnalysis {
    let hash = hash.trim();
    let len = hash.len();

    let (hash_type, format_info, john_format, hashcat_mode): (&str, &str, &str, Option<u32>) = match len {
        // MD5 variants
        32 if hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            if hash.starts_with("$1$") {
                ("MD5-crypt", "Unix $1$ MD5 password hash", "md5crypt", Some(500))
            } else {
                ("MD5", "MD5 hex digest (128-bit)", "raw-md5", Some(0))
            }
        }
        // MD5 with prefix
        _ if hash.starts_with("$1$") => {
            ("MD5-crypt", "Unix $1$ MD5 password hash", "md5crypt", Some(500))
        }
        // SHA-1 variants
        40 if hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            ("SHA-1", "SHA-1 hex digest (160-bit)", "raw-sha1", Some(100))
        }
        _ if hash.starts_with("{SHA}") => {
            ("SHA-1 (NetWare)", "Base64-encoded SHA-1", "nsldaps", Some(101))
        }
        // SHA-256 variants
        64 if hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            ("SHA-256", "SHA-256 hex digest (256-bit)", "raw-sha256", Some(1400))
        }
        _ if hash.starts_with("$5$") => {
            ("SHA-256-crypt", "Unix $5$ SHA-256 password hash", "sha256crypt", Some(7400))
        }
        _ if hash.starts_with("$sha256$") => {
            ("SHA-256 (dotnet)", "ASP.NET SHA-256 hash", "sha256", Some(1400))
        }
        // SHA-512 variants
        128 if hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            ("SHA-512", "SHA-512 hex digest (512-bit)", "raw-sha512", Some(1700))
        }
        _ if hash.starts_with("$6$") => {
            ("SHA-512-crypt", "Unix $6$ SHA-512 password hash", "sha512crypt", Some(1800))
        }
        // bcrypt — allocate format strings before the branch
        _ if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") => {
            if hash.starts_with("$2y$") {
                ("bcrypt (2y)", "bcrypt variant 2y", "bcrypt", Some(3200))
            } else if hash.starts_with("$2b$") {
                ("bcrypt (2b)", "bcrypt variant 2b", "bcrypt", Some(3200))
            } else {
                ("bcrypt (2a)", "bcrypt variant 2a", "bcrypt", Some(3200))
            }
        }
        // scrypt
        _ if hash.starts_with("$7$") => {
            ("scrypt", "Unix $7$ scrypt hash", "scrypt", Some(8900))
        }
        // Argon2
        _ if hash.starts_with("$argon2id$") => {
            ("argon2id", "Argon2id — memory-hard KDF", "argon2", None)
        }
        _ if hash.starts_with("$argon2i$") => {
            ("argon2i", "Argon2i — memory-hard KDF", "argon2", None)
        }
        _ if hash.starts_with("$argon2d$") => {
            ("argon2d", "Argon2d — memory-hard KDF", "argon2", None)
        }
        _ if hash.starts_with("$argon2") => {
            ("argon2", "Argon2 — memory-hard KDF", "argon2", None)
        }
        // NTLM
        32 if hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            ("NTLM (assumed)", "32-char hex — likely NTLM or MD5", "nt", Some(1000))
        }
        // LM
        32 if hash.chars().all(|c| c.is_ascii_uppercase()) => {
            ("LM (assumed)", "32-char uppercase hex — likely LM hash", "lm", Some(3000))
        }
        // MySQL
        41 if hash.starts_with('*') && hash[1..].chars().all(|c| c.is_ascii_hexdigit()) => {
            ("MySQL 4.1+", "MySQL 4.1+ password hash (* prefixed)", "mysql-sha1", Some(300))
        }
        // MSSQL
        _ if hash.starts_with("0x0100") && len == 54 => {
            ("MSSQL 2005", "Microsoft SQL Server 2005 hash", "mssql05", Some(131))
        }
        _ if hash.starts_with("0x0100") && len == 94 => {
            ("MSSQL 2008+", "Microsoft SQL Server 2008+ hash", "mssql12", Some(1731))
        }
        // Oracle
        _ if hash.starts_with("S:") && len == 50 => {
            ("Oracle 11g", "Oracle 11g password hash", "oracle11", Some(112))
        }
        _ if hash.starts_with("T:") && len == 50 => {
            ("Oracle 12c", "Oracle 12c password hash", "oracle12", None)
        }
        // Kerberos
        _ if hash.starts_with("$krb5tgs$23$*") => {
            ("Kerberos TGS-REP", "Kerberos TGS-REP (AS-REP Roastable)", "krb5tgs", Some(13100))
        }
        _ if hash.starts_with("$krb5tgs$23$") => {
            ("Kerberos TGS-REP", "Kerberos TGS-REP (Kerberoastable)", "krb5tgs", Some(13100))
        }
        _ if hash.starts_with("$krb5asrep$23$") => {
            ("Kerberos AS-REP", "Kerberos AS-REP (AS-REP Roastable)", "krb5asrep", Some(18200))
        }
        // NetNTLM
        _ if hash.starts_with("admin::") || (hash.contains(':') && len > 30 && len < 200) => {
            ("NetNTLMv1/v2", "NTLM authentication capture hash", "netntlmv2", Some(5600))
        }
        // PHP
        _ if hash.starts_with("$P$") || hash.starts_with("$H$") => {
            ("phpBB3", "phpBB3 password hash", "phpass", Some(400))
        }
        // WordPress
        _ if hash.starts_with("$P$B") => {
            ("WordPress (phpass)", "WordPress phpass hash", "phpass", Some(400))
        }
        // Django
        _ if hash.starts_with("sha1$") => {
            ("Django SHA1", "Django SHA1 password hash", "django", None)
        }
        // Drupal
        _ if hash.starts_with("$S$") => {
            ("Drupal 7+", "Drupal 7+ password hash (SHA-512)", "drupal7", Some(7900))
        }
        // Passlib
        _ if hash.starts_with("$pbkdf2-") => {
            ("PBKDF2", "PBKDF2 password hash", "pbkdf2", None)
        }
        _ => {
            ("Unknown", "Unrecognized hash format", "raw", None)
        }
    };

    HashAnalysis {
        hash: hash.to_string(),
        hash_type: hash_type.to_string(),
        length: len,
        is_cracked_pattern: false,
        format_info: format_info.to_string(),
        john_format: john_format.to_string(),
        hashcat_mode,
    }
}

// ─── Password Strength Analysis ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PasswordStrength {
    pub password_length: usize,
    pub has_uppercase: bool,
    pub has_lowercase: bool,
    pub has_digits: bool,
    pub has_symbols: bool,
    pub has_unicode: bool,
    pub entropy_bits: f64,
    pub strength_rating: String,
    pub crack_time_estimate: String,
    pub weaknesses: Vec<String>,
}

impl fmt::Display for PasswordStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Password Strength Analysis")?;
        writeln!(f, "=========================")?;
        writeln!(f, "Length      : {}", self.password_length)?;
        writeln!(f, "Uppercase   : {}", self.has_uppercase)?;
        writeln!(f, "Lowercase   : {}", self.has_lowercase)?;
        writeln!(f, "Digits      : {}", self.has_digits)?;
        writeln!(f, "Symbols     : {}", self.has_symbols)?;
        writeln!(f, "Unicode     : {}", self.has_unicode)?;
        writeln!(f, "Entropy     : {:.1} bits", self.entropy_bits)?;
        writeln!(f, "Rating      : {}", self.strength_rating)?;
        writeln!(f, "Est. crack  : {}", self.crack_time_estimate)?;
        if !self.weaknesses.is_empty() {
            writeln!(f, "Weaknesses")?;
            for w in &self.weaknesses {
                writeln!(f, "  - {w}")?;
            }
        }
        Ok(())
    }
}

/// Analyze password strength and estimate crack resistance.
pub fn analyze_password_strength(password: &str) -> PasswordStrength {
    let len = password.len();
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digits = password.chars().any(|c| c.is_ascii_digit());
    let has_symbols = password.chars().any(|c| !c.is_ascii_alphanumeric());
    let has_unicode = password.chars().any(|c| !c.is_ascii());

    // Calculate charset size
    let charset_size: u64 = (if has_lowercase { 26 } else { 0 })
        + (if has_uppercase { 26 } else { 0 })
        + (if has_digits { 10 } else { 0 })
        + (if has_symbols { 33 } else { 0 })
        + (if has_unicode { 100_000 } else { 0 });

    let charset_size = charset_size.max(1);
    let entropy_bits = (len as f64) * (charset_size as f64).log2();

    // Check for common patterns
    let mut weaknesses = Vec::new();

    // Common password patterns
    let lower = password.to_lowercase();
    let common_patterns = [
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "login",
        "abc123", "111111", "mustang", "access", "shadow",
        "iloveyou", "trustno1", "batman", "passw0rd", "hello",
    ];
    for pattern in &common_patterns {
        if lower.contains(pattern) {
            weaknesses.push(format!("Contains common pattern: {pattern}"));
        }
    }

    // Sequential characters
    if password.chars().collect::<Vec<_>>().windows(3).any(|w| {
        w[0] as u8 + 1 == w[1] as u8 && w[1] as u8 + 1 == w[2] as u8
    }) {
        weaknesses.push("Contains sequential characters (abc, 123, etc.)".to_string());
    }

    // Repeated characters
    if password.chars().collect::<Vec<_>>().windows(3).all(|w| w[0] == w[1] && w[1] == w[2]) {
        weaknesses.push("Contains repeated characters (aaa, 111, etc.)".to_string());
    }

    // Keyboard patterns
    let keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx"];
    for pattern in &keyboard_patterns {
        if lower.contains(pattern) {
            weaknesses.push(format!("Contains keyboard pattern: {pattern}"));
        }
    }

    // Short length
    if len < 8 {
        weaknesses.push("Too short (less than 8 characters)".to_string());
    }

    // Only one character type
    let types_used = [has_uppercase, has_lowercase, has_digits, has_symbols]
        .iter()
        .filter(|&&x| x)
        .count();
    if types_used == 1 {
        weaknesses.push("Uses only one character type".to_string());
    }

    // Estimate crack time (10 billion guesses/sec — modern GPU cluster)
    let combinations = (charset_size as f64).powi(len as i32);
    let seconds = combinations / 10_000_000_000.0;
    let crack_time = format_crack_time(seconds);

    let strength_rating = match entropy_bits as u32 {
        0..=28 => "Very Weak",
        29..=35 => "Weak",
        36..=59 => "Fair",
        60..=127 => "Strong",
        _ => "Very Strong",
    };

    PasswordStrength {
        password_length: len,
        has_uppercase,
        has_lowercase,
        has_digits,
        has_symbols,
        has_unicode,
        entropy_bits,
        strength_rating: strength_rating.to_string(),
        crack_time_estimate: crack_time,
        weaknesses,
    }
}

fn format_crack_time(seconds: f64) -> String {
    if seconds < 0.001 {
        "Instant".to_string()
    } else if seconds < 1.0 {
        format!("{:.2} seconds", seconds)
    } else if seconds < 60.0 {
        format!("{:.1} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds < 31_536_000.0 {
        format!("{:.1} days", seconds / 86400.0)
    } else if seconds < 31_536_000.0 * 1000.0 {
        format!("{:.1} years", seconds / 31_536_000.0)
    } else if seconds < 31_536_000.0 * 1_000_000.0 {
        format!("{:.1} thousand years", seconds / (31_536_000.0 * 1000.0))
    } else if seconds < 31_536_000.0 * 1_000_000_000.0 {
        format!("{:.1} million years", seconds / (31_536_000.0 * 1_000_000.0))
    } else {
        "Heat death of the universe+".to_string()
    }
}

// ─── Wordlist Generation ─────────────────────────────────────────────────────

/// Generate a targeted wordlist based on information gathered about a target.
pub fn generate_targeted_wordlist(
    target_name: &str,
    company_name: Option<&str>,
    year: Option<&str>,
    extra_words: &[&str],
) -> Vec<String> {
    let mut wordlist = Vec::new();
    let year = year.unwrap_or("2026");

    // Base words from target
    let lower = target_name.to_lowercase();
    let upper = target_name.to_uppercase();
    let base_words: Vec<&str> = vec![
        target_name,
        &lower,
        &upper,
    ];

    // Common password suffixes
    let suffixes = [
        "!", "1", "12", "123", "1234", "12345", "123456", "!",
        "Pass", "pass", "Pass1", "pass1", "Pass!", "pass!",
        "2024", "2025", "2026",
    ];

    // Common patterns
    let patterns = [
        "{word}",
        "{word}{year}",
        "{word}!",
        "{word}{year}!",
        "{word}@123",
        "{word}#123",
        "{word}$123",
        "Welcome1",
        "Welcome{word}",
        "P@ss{word}",
        "{word}P@ss",
        "{word}2026!",
    ];

    for base in &base_words {
        for pattern in &patterns {
            let password = pattern
                .replace("{word}", base)
                .replace("{year}", year);
            wordlist.push(password);
        }
    }

    // Add company name variations if provided
    if let Some(company) = company_name {
        let lowered = company.to_lowercase();
        let company_words: Vec<&str> = vec![
            company,
            &lowered,
        ];
        for base in &company_words {
            for suffix in &suffixes {
                wordlist.push(format!("{base}{suffix}"));
            }
        }
    }

    // Add extra words
    for word in extra_words {
        wordlist.push(word.to_string());
        wordlist.push(format!("{word}123"));
        wordlist.push(format!("{word}!"));
        wordlist.push(format!("{word}2026"));
    }

    // Deduplicate
    wordlist.sort();
    wordlist.dedup();

    wordlist
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_md5_hash() {
        let analysis = identify_hash("5d41402abc4b2a76b9719d911017c592");
        assert_eq!(analysis.hash_type, "MD5");
        assert_eq!(analysis.hashcat_mode, Some(0));
    }

    #[test]
    fn identify_sha256_hash() {
        let analysis = identify_hash("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(analysis.hash_type, "SHA-256");
        assert_eq!(analysis.hashcat_mode, Some(1400));
    }

    #[test]
    fn identify_bcrypt_hash() {
        let analysis = identify_hash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");
        assert!(analysis.hash_type.contains("bcrypt"));
        assert_eq!(analysis.hashcat_mode, Some(3200));
    }

    #[test]
    fn identify_ntlm_hash() {
        let analysis = identify_hash("a4f49c406510bdcbab6c78d5e1e0e720");
        assert!(analysis.hash_type.contains("NTLM"));
    }

    #[test]
    fn identify_kerberos_hash() {
        let analysis = identify_hash("$krb5tgs$23$*user$realm$spn*$abc123");
        assert!(analysis.hash_type.contains("Kerberos"));
    }

    #[test]
    fn identify_mysql_hash() {
        let analysis = identify_hash("*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9");
        assert_eq!(analysis.hash_type, "MySQL 4.1+");
    }

    #[test]
    fn weak_password_detected() {
        let strength = analyze_password_strength("password");
        assert_eq!(strength.strength_rating, "Very Weak");
        assert!(!strength.weaknesses.is_empty());
    }

    #[test]
    fn strong_password_detected() {
        let strength = analyze_password_strength("X9#mK2$vL8nQ4@jR7!wZ");
        assert_eq!(strength.strength_rating, "Strong");
    }

    #[test]
    fn sequential_pattern_detected() {
        let strength = analyze_password_strength("abcdef123");
        assert!(strength.weaknesses.iter().any(|w| w.contains("sequential")));
    }

    #[test]
    fn keyboard_pattern_detected() {
        let strength = analyze_password_strength("qwerty123");
        assert!(strength.weaknesses.iter().any(|w| w.contains("keyboard")));
    }

    #[test]
    fn wordlist_generation_produces_results() {
        let words = generate_targeted_wordlist("testcorp", Some("TestCorp"), Some("2026"), &["admin"]);
        assert!(!words.is_empty());
        assert!(words.iter().any(|w| w.contains("testcorp")));
        assert!(words.iter().any(|w| w.contains("2026")));
    }
}
