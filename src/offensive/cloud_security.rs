//! Cloud security misconfiguration detection for AWS, GCP, and Azure.
//!
//! Provides offline analysis of cloud IAM policies, storage configurations,
//! network security groups, and other cloud resources for common security
//! misconfigurations.

use std::fmt;

// ============================================================================
// Severity & Common Types
// ============================================================================

/// Finding severity levels aligned with CVSS ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Informational => write!(f, "INFORMATIONAL"),
        }
    }
}

// ============================================================================
// AWS Findings
// ============================================================================

/// A single AWS security finding.
#[derive(Debug, Clone)]
pub struct AwsFinding {
    pub service: String,
    pub resource: String,
    pub misconfiguration: String,
    pub severity: Severity,
    pub cwe: String,
    pub compliance: Vec<String>,
    pub remediation: String,
}

impl fmt::Display for AwsFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {}", self.severity, self.misconfiguration)?;
        writeln!(f, "  Service: {}", self.service)?;
        writeln!(f, "  Resource: {}", self.resource)?;
        writeln!(f, "  CWE: {}", self.cwe)?;
        if !self.compliance.is_empty() {
            writeln!(f, "  Compliance: {}", self.compliance.join(", "))?;
        }
        writeln!(f, "  Remediation: {}", self.remediation)
    }
}

/// Analyze an AWS IAM policy document for misconfigurations.
///
/// Input should be the JSON policy body (inline or attached policy).
pub fn analyze_iam_policy(policy: &str) -> Vec<AwsFinding> {
    let mut findings = Vec::new();

    // Check for wildcard Action
    if policy.contains(r#""Action": "*""#) || policy.contains(r#""Action":"*""#) {
        findings.push(AwsFinding {
            service: "IAM".into(),
            resource: "Policy".into(),
            misconfiguration: "IAM policy grants wildcard Action (*)".into(),
            severity: Severity::Critical,
            cwe: "CWE-269".into(),
            compliance: vec!["CIS AWS 1.16".into(), "NIST AC-6".into()],
            remediation: "Replace wildcard Action with specific required actions.".into(),
        });
    }

    // Check for wildcard Resource
    if policy.contains(r#""Resource": "*""#) || policy.contains(r#""Resource":"*""#) {
        findings.push(AwsFinding {
            service: "IAM".into(),
            resource: "Policy".into(),
            misconfiguration: "IAM policy grants access to all resources (Resource: *)".into(),
            severity: Severity::High,
            cwe: "CWE-269".into(),
            compliance: vec!["CIS AWS 1.16".into()],
            remediation: "Scope Resource to specific ARNs.".into(),
        });
    }

    // Check for AdministratorAccess
    if policy.contains("AdministratorAccess") {
        findings.push(AwsFinding {
            service: "IAM".into(),
            resource: "Policy".into(),
            misconfiguration: "AdministratorAccess managed policy is attached".into(),
            severity: Severity::Critical,
            cwe: "CWE-269".into(),
            compliance: vec!["CIS AWS 1.16".into(), "NIST AC-6(1)".into()],
            remediation: "Replace with least-privilege policies for the specific role.".into(),
        });
    }

    // Check for IAM user creation permissions
    if policy.contains("iam:CreateUser") || policy.contains("iam:CreateLoginProfile") {
        findings.push(AwsFinding {
            service: "IAM".into(),
            resource: "Policy".into(),
            misconfiguration: "Policy allows IAM user or login profile creation".into(),
            severity: Severity::Medium,
            cwe: "CWE-269".into(),
            compliance: vec!["CIS AWS 1.13".into()],
            remediation: "Use IAM roles instead of long-lived users.".into(),
        });
    }

    // Check for root account access
    if policy.contains(r#""Principal": "arn:aws:iam::root""#)
        || policy.contains(r#""Principal":"arn:aws:iam::root""#)
    {
        findings.push(AwsFinding {
            service: "IAM".into(),
            resource: "Policy".into(),
            misconfiguration: "Policy grants access to the root account".into(),
            severity: Severity::Critical,
            cwe: "CWE-250".into(),
            compliance: vec!["CIS AWS 1.7".into()],
            remediation: "Remove root account from policy principals.".into(),
        });
    }

    // Check for STS:AssumeRole with wildcard principal
    if policy.contains("sts:AssumeRole")
        && (policy.contains(r#""Principal": "*""#) || policy.contains(r#""Principal":"*""#))
    {
        findings.push(AwsFinding {
            service: "IAM".into(),
            resource: "Role Trust Policy".into(),
            misconfiguration: "Role trust policy allows assume-role from any principal".into(),
            severity: Severity::Critical,
            cwe: "CWE-284".into(),
            compliance: vec!["CIS AWS 1.10".into()],
            remediation: "Restrict Principal to specific trusted AWS accounts or services.".into(),
        });
    }

    findings
}

/// Analyze an AWS S3 bucket policy for public access misconfigurations.
pub fn analyze_s3_policy(policy: &str) -> Vec<AwsFinding> {
    let mut findings = Vec::new();

    // Check for public read access
    if policy.contains(r#""Effect": "Allow""#)
        && (policy.contains(r#""Principal": "*""#) || policy.contains(r#""Principal":"*""#))
        && (policy.contains("s3:GetObject") || policy.contains("s3:ListBucket"))
    {
        findings.push(AwsFinding {
            service: "S3".into(),
            resource: "Bucket Policy".into(),
            misconfiguration: "S3 bucket policy grants public read access".into(),
            severity: Severity::Critical,
            cwe: "CWE-284".into(),
            compliance: vec!["CIS AWS 2.1.1".into()],
            remediation: "Remove public Principal or restrict to specific IAM principals.".into(),
        });
    }

    // Check for public write access
    if policy.contains("s3:PutObject")
        && (policy.contains(r#""Principal": "*""#) || policy.contains(r#""Principal":"*""#))
    {
        findings.push(AwsFinding {
            service: "S3".into(),
            resource: "Bucket Policy".into(),
            misconfiguration: "S3 bucket policy grants public write access".into(),
            severity: Severity::Critical,
            cwe: "CWE-284".into(),
            compliance: vec!["CIS AWS 2.1.2".into()],
            remediation: "Remove public write access from the bucket policy.".into(),
        });
    }

    // Check for missing TLS enforcement
    if !policy.contains("aws:SecureTransport") {
        findings.push(AwsFinding {
            service: "S3".into(),
            resource: "Bucket Policy".into(),
            misconfiguration: "S3 bucket policy does not enforce TLS (aws:SecureTransport)".into(),
            severity: Severity::Medium,
            cwe: "CWE-319".into(),
            compliance: vec!["CIS AWS 2.1.1".into()],
            remediation: "Add a condition requiring aws:SecureTransport = true.".into(),
        });
    }

    findings
}

/// Analyze an AWS security group for overly permissive rules.
///
/// Input should be a JSON representation of security group rules (IpPermissions).
pub fn analyze_security_group(sg_rules: &str) -> Vec<AwsFinding> {
    let mut findings = Vec::new();

    // Check for 0.0.0.0/0 ingress on sensitive ports
    let sensitive_ports: Vec<(&str, &str)> = vec![
        ("22", "SSH"),
        ("3389", "RDP"),
        ("3306", "MySQL"),
        ("5432", "PostgreSQL"),
        ("6379", "Redis"),
        ("27017", "MongoDB"),
        ("1433", "MS SQL"),
        ("9200", "Elasticsearch"),
        ("2375", "Docker"),
        ("2376", "Docker TLS"),
        ("11211", "Memcached"),
    ];

    for (port, service_name) in &sensitive_ports {
        // Check if 0.0.0.0/0 is mentioned near this port number
        if sg_rules.contains(port)
            && sg_rules.contains("0.0.0.0/0")
            && sg_rules.contains("IpPermissions")
        {
            findings.push(AwsFinding {
                service: "EC2".into(),
                resource: "Security Group".into(),
                misconfiguration: format!(
                    "Security group allows {service_name} (port {port}) from 0.0.0.0/0"
                ),
                severity: Severity::Critical,
                cwe: "CWE-284".into(),
                compliance: vec!["CIS AWS 5.2".into(), "PCI DSS 1.2.1".into()],
                remediation: format!(
                    "Restrict port {port} access to known IP ranges or bastion hosts."
                ),
            });
        }
    }

    // Check for all-traffic open
    if sg_rules.contains(r#""IpProtocol": "-1""#) && sg_rules.contains("0.0.0.0/0") {
        findings.push(AwsFinding {
            service: "EC2".into(),
            resource: "Security Group".into(),
            misconfiguration: "Security group allows all traffic (protocol -1) from 0.0.0.0/0"
                .into(),
            severity: Severity::Critical,
            cwe: "CWE-284".into(),
            compliance: vec!["CIS AWS 5.2".into()],
            remediation: "Remove the all-traffic rule and restrict to required ports/protocols."
                .into(),
        });
    }

    findings
}

// ============================================================================
// GCP Findings
// ============================================================================

/// A single GCP security finding.
#[derive(Debug, Clone)]
pub struct GcpFinding {
    pub service: String,
    pub misconfiguration: String,
    pub severity: Severity,
    pub cwe: String,
    pub remediation: String,
}

impl fmt::Display for GcpFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {}", self.severity, self.misconfiguration)?;
        writeln!(f, "  Service: {}", self.service)?;
        writeln!(f, "  CWE: {}", self.cwe)?;
        writeln!(f, "  Remediation: {}", self.remediation)
    }
}

/// Analyze a GCP IAM policy for misconfigurations.
pub fn analyze_gcp_iam(policy: &str) -> Vec<GcpFinding> {
    let mut findings = Vec::new();

    // Check for allUsers binding
    if policy.contains("allUsers") {
        findings.push(GcpFinding {
            service: "IAM".into(),
            misconfiguration: "GCP IAM policy binds to allUsers (anonymous access)".into(),
            severity: Severity::Critical,
            cwe: "CWE-284".into(),
            remediation: "Remove allUsers binding and use specific service accounts or groups."
                .into(),
        });
    }

    // Check for allAuthenticatedUsers binding
    if policy.contains("allAuthenticatedUsers") {
        findings.push(GcpFinding {
            service: "IAM".into(),
            misconfiguration: "GCP IAM policy binds to allAuthenticatedUsers".into(),
            severity: Severity::High,
            cwe: "CWE-284".into(),
            remediation:
                "Replace with specific service accounts or Google Groups instead.".into(),
        });
    }

    // Check for owner role
    if policy.contains("roles/owner") {
        findings.push(GcpFinding {
            service: "IAM".into(),
            misconfiguration: "GCP IAM policy grants roles/owner (full project control)".into(),
            severity: Severity::Critical,
            cwe: "CWE-269".into(),
            remediation: "Replace with roles/editor or specific predefined/custom roles.".into(),
        });
    }

    // Check for service account key creation permission
    if policy.contains("iam.serviceAccounts.keys.create") {
        findings.push(GcpFinding {
            service: "IAM".into(),
            misconfiguration:
                "GCP IAM policy grants iam.serviceAccounts.keys.create permission".into(),
            severity: Severity::High,
            cwe: "CWE-798".into(),
            remediation:
                "Remove this permission; use Workload Identity Federation instead.".into(),
        });
    }

    // Check for overly broad service account impersonation
    if policy.contains("iam.serviceAccounts.getAccessToken") && policy.contains("*") {
        findings.push(GcpFinding {
            service: "IAM".into(),
            misconfiguration:
                "GCP IAM policy grants getAccessToken for wildcard service accounts".into(),
            severity: Severity::High,
            cwe: "CWE-284".into(),
            remediation:
                "Restrict impersonation to specific service accounts needed for the role.".into(),
        });
    }

    findings
}

/// Analyze a GCP firewall rules definition for misconfigurations.
pub fn analyze_gcp_firewall(rules: &str) -> Vec<GcpFinding> {
    let mut findings = Vec::new();

    // Check for 0.0.0.0/0 source range
    if rules.contains("0.0.0.0/0") {
        findings.push(GcpFinding {
            service: "Compute".into(),
            misconfiguration: "GCP firewall rule allows traffic from 0.0.0.0/0".into(),
            severity: Severity::High,
            cwe: "CWE-284".into(),
            remediation: "Restrict sourceRanges to specific CIDRs.".into(),
        });
    }

    // Check for all-protocol rule
    if rules.contains(r#""IPProtocol": "all""#) || rules.contains(r#""IPProtocol":"all""#) {
        findings.push(GcpFinding {
            service: "Compute".into(),
            misconfiguration: "GCP firewall rule allows all protocols".into(),
            severity: Severity::High,
            cwe: "CWE-284".into(),
            remediation: "Restrict to specific required protocols.".into(),
        });
    }

    // Check for unrestricted egress
    if rules.contains(r#""direction": "EGRESS""#) && rules.contains("0.0.0.0/0") {
        findings.push(GcpFinding {
            service: "Compute".into(),
            misconfiguration: "GCP firewall rule allows unrestricted egress to 0.0.0.0/0"
                .into(),
            severity: Severity::Medium,
            cwe: "CWE-319".into(),
            remediation: "Restrict egress to known destinations.".into(),
        });
    }

    findings
}

// ============================================================================
// Azure Findings
// ============================================================================

/// A single Azure security finding.
#[derive(Debug, Clone)]
pub struct AzureFinding {
    pub service: String,
    pub misconfiguration: String,
    pub severity: Severity,
    pub cwe: String,
    pub remediation: String,
}

impl fmt::Display for AzureFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {}", self.severity, self.misconfiguration)?;
        writeln!(f, "  Service: {}", self.service)?;
        writeln!(f, "  CWE: {}", self.cwe)?;
        writeln!(f, "  Remediation: {}", self.remediation)
    }
}

/// Analyze an Azure role assignment for overly privileged access.
pub fn analyze_azure_role(assignment: &str) -> Vec<AzureFinding> {
    let mut findings = Vec::new();

    // Check for Owner role
    if assignment.contains("Owner") || assignment.contains("8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
    {
        findings.push(AzureFinding {
            service: "Authorization".into(),
            misconfiguration: "Azure role assignment grants Owner role".into(),
            severity: Severity::Critical,
            cwe: "CWE-269".into(),
            remediation: "Replace with Contributor or a custom role with minimum required permissions.".into(),
        });
    }

    // Check for Contributor role
    if assignment.contains("Contributor")
        || assignment.contains("b24988ac-6180-42a0-ab88-20f7382dd24c")
    {
        findings.push(AzureFinding {
            service: "Authorization".into(),
            misconfiguration: "Azure role assignment grants Contributor role".into(),
            severity: Severity::High,
            cwe: "CWE-269".into(),
            remediation: "Evaluate if a more restrictive role can be used.".into(),
        });
    }

    // Check for User Access Administrator
    if assignment.contains("User Access Administrator")
        || assignment.contains("18d7d88d-d35e-4fb5-a5c3-7773c20a72d9")
    {
        findings.push(AzureFinding {
            service: "Authorization".into(),
            misconfiguration:
                "Azure role assignment grants User Access Administrator permissions".into(),
            severity: Severity::High,
            cwe: "CWE-269".into(),
            remediation: "Remove unless explicitly required for identity management tasks.".into(),
        });
    }

    // Check for subscription-level assignments
    if assignment.contains("subscriptions") && (assignment.contains("Owner") || assignment.contains("Contributor")) {
        findings.push(AzureFinding {
            service: "Authorization".into(),
            misconfiguration: "Broad role assigned at subscription level".into(),
            severity: Severity::Critical,
            cwe: "CWE-269".into(),
            remediation: "Assign roles at resource group level instead.".into(),
        });
    }

    findings
}

/// Analyze an Azure Network Security Group (NSG) for overly permissive rules.
pub fn analyze_azure_nsg(nsg_rules: &str) -> Vec<AzureFinding> {
    let mut findings = Vec::new();

    // Check for wildcard source address prefix
    if nsg_rules.contains(r#""sourceAddressPrefix": "*""#)
        || nsg_rules.contains(r#""sourceAddressPrefix":"*""#)
        || nsg_rules.contains(r#""sourceAddressPrefix": "*" "#)
    {
        findings.push(AzureFinding {
            service: "Network".into(),
            misconfiguration: "Azure NSG rule allows traffic from any source (*)".into(),
            severity: Severity::Critical,
            cwe: "CWE-284".into(),
            remediation: "Restrict sourceAddressPrefix to specific IPs or service tags.".into(),
        });
    }

    // Check for allow-all inbound
    if nsg_rules.contains(r#""access": "Allow""#) && nsg_rules.contains(r#""direction": "Inbound""#)
        && (nsg_rules.contains(r#""destinationPortRange": "*""#) || nsg_rules.contains(r#""protocol": "*""#))
    {
        findings.push(AzureFinding {
            service: "Network".into(),
            misconfiguration: "Azure NSG allows all inbound traffic".into(),
            severity: Severity::Critical,
            cwe: "CWE-284".into(),
            remediation:
                "Restrict destination port ranges and protocols to required values.".into(),
        });
    }

    // Check for SSH/RDP open to the world
    let open_ports: Vec<(&str, &str)> = vec![("22", "SSH"), ("3389", "RDP")];
    for (port, name) in &open_ports {
        if nsg_rules.contains(port) && nsg_rules.contains("*") {
            findings.push(AzureFinding {
                service: "Network".into(),
                misconfiguration: format!(
                    "Azure NSG rule exposes {name} (port {port}) to the internet"
                ),
                severity: Severity::Critical,
                cwe: "CWE-284".into(),
                remediation: format!("Restrict {name} access to known management IPs."),
            });
        }
    }

    findings
}

// ============================================================================
// Unified Report
// ============================================================================

/// A unified cloud security report aggregating findings across providers.
#[derive(Debug)]
pub struct CloudSecurityReport {
    pub aws_findings: Vec<AwsFinding>,
    pub gcp_findings: Vec<GcpFinding>,
    pub azure_findings: Vec<AzureFinding>,
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
}

impl CloudSecurityReport {
    /// Create an empty report.
    pub fn new() -> Self {
        Self {
            aws_findings: Vec::new(),
            gcp_findings: Vec::new(),
            azure_findings: Vec::new(),
            total_critical: 0,
            total_high: 0,
            total_medium: 0,
            total_low: 0,
        }
    }

    /// Add AWS findings to the report, updating severity counts.
    pub fn add_aws(&mut self, findings: Vec<AwsFinding>) {
        for f in &findings {
            match f.severity {
                Severity::Critical => self.total_critical += 1,
                Severity::High => self.total_high += 1,
                Severity::Medium => self.total_medium += 1,
                Severity::Low | Severity::Informational => self.total_low += 1,
            }
        }
        self.aws_findings.extend(findings);
    }

    /// Add GCP findings to the report, updating severity counts.
    pub fn add_gcp(&mut self, findings: Vec<GcpFinding>) {
        for f in &findings {
            match f.severity {
                Severity::Critical => self.total_critical += 1,
                Severity::High => self.total_high += 1,
                Severity::Medium => self.total_medium += 1,
                Severity::Low | Severity::Informational => self.total_low += 1,
            }
        }
        self.gcp_findings.extend(findings);
    }

    /// Add Azure findings to the report, updating severity counts.
    pub fn add_azure(&mut self, findings: Vec<AzureFinding>) {
        for f in &findings {
            match f.severity {
                Severity::Critical => self.total_critical += 1,
                Severity::High => self.total_high += 1,
                Severity::Medium => self.total_medium += 1,
                Severity::Low | Severity::Informational => self.total_low += 1,
            }
        }
        self.azure_findings.extend(findings);
    }

    /// Total number of findings across all providers.
    pub fn total_findings(&self) -> usize {
        self.aws_findings.len() + self.gcp_findings.len() + self.azure_findings.len()
    }
}

impl fmt::Display for CloudSecurityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Cloud Security Report ===")?;
        writeln!(
            f,
            "Findings: {} total ({} critical, {} high, {} medium, {} low)",
            self.total_findings(),
            self.total_critical,
            self.total_high,
            self.total_medium,
            self.total_low
        )?;
        writeln!(f)?;

        if !self.aws_findings.is_empty() {
            writeln!(f, "--- AWS Findings ---")?;
            for finding in &self.aws_findings {
                writeln!(f, "{finding}")?;
            }
            writeln!(f)?;
        }

        if !self.gcp_findings.is_empty() {
            writeln!(f, "--- GCP Findings ---")?;
            for finding in &self.gcp_findings {
                writeln!(f, "{finding}")?;
            }
            writeln!(f)?;
        }

        if !self.azure_findings.is_empty() {
            writeln!(f, "--- Azure Findings ---")?;
            for finding in &self.azure_findings {
                writeln!(f, "{finding}")?;
            }
        }

        Ok(())
    }
}

/// Generate a unified report from raw cloud configuration JSON dumps.
///
/// Pass `None` for any provider you don't want to analyze.
pub fn generate_cloud_report(
    aws_iam: Option<&str>,
    aws_s3: Option<&str>,
    aws_sg: Option<&str>,
    gcp_iam: Option<&str>,
    gcp_fw: Option<&str>,
    azure_role: Option<&str>,
    azure_nsg: Option<&str>,
) -> CloudSecurityReport {
    let mut report = CloudSecurityReport::new();

    if let Some(policy) = aws_iam {
        report.add_aws(analyze_iam_policy(policy));
    }
    if let Some(policy) = aws_s3 {
        report.add_aws(analyze_s3_policy(policy));
    }
    if let Some(sg) = aws_sg {
        report.add_aws(analyze_security_group(sg));
    }
    if let Some(policy) = gcp_iam {
        report.add_gcp(analyze_gcp_iam(policy));
    }
    if let Some(fw) = gcp_fw {
        report.add_gcp(analyze_gcp_firewall(fw));
    }
    if let Some(role) = azure_role {
        report.add_azure(analyze_azure_role(role));
    }
    if let Some(nsg) = azure_nsg {
        report.add_azure(analyze_azure_nsg(nsg));
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_wildcard_iam_action() {
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::*"}]}"#;
        let findings = analyze_iam_policy(policy);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.misconfiguration.contains("wildcard Action")));
    }

    #[test]
    fn test_detect_admin_access_policy() {
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}],"AttachedPolicies":[{"PolicyName":"AdministratorAccess"}]}"#;
        let findings = analyze_iam_policy(policy);
        assert!(findings.iter().any(|f| f.misconfiguration.contains("AdministratorAccess")));
    }

    #[test]
    fn test_detect_public_s3_bucket() {
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"}]}"#;
        let findings = analyze_s3_policy(policy);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.misconfiguration.contains("public read")));
    }

    #[test]
    fn test_detect_gcp_allusers() {
        let policy = r#"{"bindings":[{"role":"roles/viewer","members":["allUsers"]}]}"#;
        let findings = analyze_gcp_iam(policy);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.misconfiguration.contains("allUsers")));
    }

    #[test]
    fn test_detect_azure_owner_role() {
        let assignment = r#"{"roleDefinitionId":"/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657","principalId":"user1"}"#;
        let findings = analyze_azure_role(assignment);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.misconfiguration.contains("Owner")));
    }

    #[test]
    fn test_cloud_report_counts_severities() {
        let report = generate_cloud_report(
            Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#),
            None, None, None, None, None, None,
        );
        assert!(report.total_critical > 0);
        assert_eq!(report.total_findings(), report.aws_findings.len());
    }

    #[test]
    fn test_empty_report() {
        let report = generate_cloud_report(None, None, None, None, None, None, None);
        assert_eq!(report.total_findings(), 0);
    }
}