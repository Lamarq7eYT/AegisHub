#![deny(clippy::all)]
#![deny(unsafe_code)]

pub mod analyzer;
pub mod analyzers;
pub mod error;
pub mod finding;
pub mod report;
pub mod scoring;
pub mod source;

pub use analyzer::Analyzer;
pub use analyzers::secrets::SecretsAnalyzer;
pub use error::{AegisError, Result};
pub use finding::{Finding, FindingLocation, Severity};
pub use report::{scan_sources, ScanInput, ScanReport, ScanStats, SourceFileInput};
pub use scoring::compute_score;
pub use source::SourceFile;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Builds the default analyzer set for the current engine milestone.
pub fn default_analyzers() -> Result<Vec<Box<dyn Analyzer>>> {
    Ok(vec![Box::new(SecretsAnalyzer::try_new()?)])
}

/// Scans a single source buffer and returns a report.
pub fn scan_content_native(source: &str, language: &str) -> Result<ScanReport> {
    let file = SourceFile::new("memory://source", Some(language), source);
    let analyzers = default_analyzers()?;

    Ok(scan_sources(
        "memory/source",
        "in-memory",
        &[file],
        analyzers.as_slice(),
    ))
}

/// Scans one in-memory source file from JavaScript when compiled to WASM.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn scan_content(source: &str, language: &str) -> std::result::Result<JsValue, JsValue> {
    let report = scan_content_native(source, language)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;

    serde_wasm_bindgen::to_value(&report).map_err(|error| JsValue::from_str(&error.to_string()))
}
