use crate::finding::Finding;
use crate::source::SourceFile;

/// Analysis unit that inspects one source file and returns zero or more findings.
pub trait Analyzer: Send + Sync {
    /// Stable human-readable analyzer name.
    fn name(&self) -> &'static str;

    /// Analyzes a single source file.
    fn analyze(&self, file: &SourceFile) -> Vec<Finding>;
}
