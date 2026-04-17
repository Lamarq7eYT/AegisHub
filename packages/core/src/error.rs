use thiserror::Error;

/// Result alias used by the AegisHub core engine.
pub type Result<T> = std::result::Result<T, AegisError>;

/// Error type for recoverable core engine failures.
#[derive(Debug, Error)]
pub enum AegisError {
    /// A regular expression rule failed to compile.
    #[error("failed to compile analyzer rule `{rule_id}`: {source}")]
    Regex {
        /// Identifier of the analyzer rule that failed.
        rule_id: &'static str,
        /// Original regex compilation error.
        source: regex::Error,
    },

    /// JSON input or output could not be parsed or serialized.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Standard input could not be read.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
