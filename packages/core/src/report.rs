use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::analyzer::Analyzer;
use crate::finding::Finding;
use crate::scoring::compute_score;
use crate::source::SourceFile;

/// JSON input accepted by the native engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInput {
    /// Repository in `owner/repo` form.
    pub repo: String,
    /// Commit SHA or ref being scanned.
    pub commit: String,
    /// Source files to scan.
    pub files: Vec<SourceFileInput>,
}

/// Serializable source file input for the native engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFileInput {
    /// Repository-relative path.
    pub path: String,
    /// Optional language hint.
    pub language: Option<String>,
    /// Full source content.
    pub content: String,
}

impl From<SourceFileInput> for SourceFile {
    fn from(input: SourceFileInput) -> Self {
        Self::new(input.path, input.language.as_deref(), input.content)
    }
}

/// Complete scan report emitted by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Repository in `owner/repo` form.
    pub repo: String,
    /// Commit SHA or ref that was scanned.
    pub commit: String,
    /// UTC timestamp in ISO 8601 format.
    pub scanned_at: String,
    /// Numeric security score from 0 to 100.
    pub score: u8,
    /// Findings detected by all analyzers.
    pub findings: Vec<Finding>,
    /// Scan statistics.
    pub stats: ScanStats,
}

/// Aggregate scan statistics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScanStats {
    /// Number of files scanned.
    pub files_scanned: usize,
    /// Total lines scanned.
    pub lines_scanned: usize,
    /// Engine runtime in milliseconds.
    pub duration_ms: u64,
}

/// Runs analyzers against the provided sources and returns a report.
pub fn scan_sources(
    repo: impl Into<String>,
    commit: impl Into<String>,
    files: &[SourceFile],
    analyzers: &[Box<dyn Analyzer>],
) -> ScanReport {
    let started_at = Instant::now();
    let findings = files
        .iter()
        .flat_map(|file| {
            analyzers
                .iter()
                .flat_map(|analyzer| analyzer.analyze(file))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let lines_scanned = files.iter().map(SourceFile::line_count).sum();
    let score = compute_score(&findings);
    let duration_ms = started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    ScanReport {
        repo: repo.into(),
        commit: commit.into(),
        scanned_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        score,
        findings,
        stats: ScanStats {
            files_scanned: files.len(),
            lines_scanned,
            duration_ms,
        },
    }
}
