use std::io::{self, Read};

use aegishub_core::{default_analyzers, scan_sources, Result, ScanInput, SourceFile};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let scan_input = serde_json::from_str::<ScanInput>(&input)?;
    let files = scan_input
        .files
        .into_iter()
        .map(SourceFile::from)
        .collect::<Vec<_>>();
    let analyzers = default_analyzers()?;
    let report = scan_sources(
        scan_input.repo,
        scan_input.commit,
        files.as_slice(),
        analyzers.as_slice(),
    );

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
