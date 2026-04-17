use serde::{Deserialize, Serialize};

/// Severity level for a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Immediate remediation is required.
    Critical,
    /// High-risk finding that should fail protected workflows.
    High,
    /// Medium-risk finding that should be addressed soon.
    Medium,
    /// Low-risk hardening opportunity.
    Low,
    /// Informational note.
    Info,
}

/// A single security issue detected by an analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Repository-relative file path.
    pub file_path: String,
    /// One-based line number.
    pub line: usize,
    /// One-based column number.
    pub column: usize,
    /// Stable rule identifier.
    pub rule_id: String,
    /// Finding severity.
    pub severity: Severity,
    /// Concise finding message.
    pub message: String,
    /// Source context around the offending line.
    pub snippet: String,
    /// CWE identifier associated with the issue.
    pub cwe_id: String,
}

/// Source location attached to a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingLocation {
    /// Repository-relative file path.
    pub file_path: String,
    /// One-based line number.
    pub line: usize,
    /// One-based column number.
    pub column: usize,
}

impl FindingLocation {
    /// Creates a finding location.
    pub fn new(file_path: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            file_path: file_path.into(),
            line,
            column,
        }
    }
}

impl Finding {
    /// Creates a finding with normalized source location and context.
    pub fn new(
        location: FindingLocation,
        rule_id: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        snippet: impl Into<String>,
        cwe_id: impl Into<String>,
    ) -> Self {
        Self {
            file_path: location.file_path,
            line: location.line,
            column: location.column,
            rule_id: rule_id.into(),
            severity,
            message: message.into(),
            snippet: snippet.into(),
            cwe_id: cwe_id.into(),
        }
    }
}
