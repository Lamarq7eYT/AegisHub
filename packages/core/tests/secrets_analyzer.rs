use aegishub_core::{scan_content_native, Analyzer, SecretsAnalyzer, Severity, SourceFile};

fn synthetic_aws_key() -> String {
    [
        "AK",
        "IA",
        &deterministic_secret_chars(16, CharSet::UppercaseAndDigits),
    ]
    .concat()
}

fn synthetic_github_token() -> String {
    ["gh", "p_", &deterministic_secret_chars(36, CharSet::Mixed)].concat()
}

fn synthetic_stripe_key() -> String {
    [
        "sk",
        "_live_",
        &deterministic_secret_chars(24, CharSet::Mixed),
    ]
    .concat()
}

fn synthetic_google_key() -> String {
    [
        "AI",
        "za",
        &deterministic_secret_chars(35, CharSet::UrlSafe),
    ]
    .concat()
}

fn synthetic_jwt() -> String {
    [
        "ey",
        "J",
        &deterministic_secret_chars(34, CharSet::UrlSafe),
        ".",
        "ey",
        &deterministic_secret_chars(48, CharSet::UrlSafe),
        ".",
        &deterministic_secret_chars(43, CharSet::UrlSafe),
    ]
    .concat()
}

fn synthetic_private_key_header() -> String {
    ["-----BEGIN ", "OPENSSH ", "PRIVATE KEY-----"].concat()
}

fn synthetic_password_assignment() -> String {
    ["password", " = ", "\"", "correct-horse-value", "\""].concat()
}

fn synthetic_high_entropy_value() -> String {
    deterministic_secret_chars(48, CharSet::Mixed)
}

enum CharSet {
    Mixed,
    UppercaseAndDigits,
    UrlSafe,
}

fn deterministic_secret_chars(length: usize, charset: CharSet) -> String {
    (0..length)
        .map(|index| {
            let value = ((index * 17 + 11) % 62) as u8;
            match charset {
                CharSet::Mixed => match value {
                    0..=9 => char::from(b'0' + value),
                    10..=35 => char::from(b'A' + value - 10),
                    _ => char::from(b'a' + value - 36),
                },
                CharSet::UppercaseAndDigits => match value % 36 {
                    0..=9 => char::from(b'0' + (value % 36)),
                    rest => char::from(b'A' + rest - 10),
                },
                CharSet::UrlSafe => match value {
                    0..=9 => char::from(b'0' + value),
                    10..=35 => char::from(b'A' + value - 10),
                    36..=61 => char::from(b'a' + value - 36),
                    _ => '_',
                },
            }
        })
        .collect()
}

fn positive_fixture() -> String {
    include_str!("fixtures/secrets_positive.template")
        .replace("__AWS_ACCESS_KEY__", &synthetic_aws_key())
        .replace("__GITHUB_TOKEN__", &synthetic_github_token())
        .replace("__STRIPE_SECRET_KEY__", &synthetic_stripe_key())
        .replace("__GOOGLE_API_KEY__", &synthetic_google_key())
        .replace("__JWT_TOKEN__", &synthetic_jwt())
        .replace(
            "__SSH_PRIVATE_KEY_HEADER__",
            &synthetic_private_key_header(),
        )
        .replace("__PASSWORD_ASSIGNMENT__", &synthetic_password_assignment())
        .replace("__HIGH_ENTROPY_VALUE__", &synthetic_high_entropy_value())
}

fn rule_ids_for(source: &str) -> Vec<String> {
    let analyzer = SecretsAnalyzer::try_new().expect("secrets analyzer should compile");
    let file = SourceFile::new("fixtures/example.js", Some("javascript"), source);

    analyzer
        .analyze(&file)
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

#[test]
fn detects_pattern_based_secret_rules_from_fixture() {
    let rule_ids = rule_ids_for(&positive_fixture());

    assert!(rule_ids.contains(&"secret.aws.access_key".to_owned()));
    assert!(rule_ids.contains(&"secret.github.token".to_owned()));
    assert!(rule_ids.contains(&"secret.stripe.live_key".to_owned()));
    assert!(rule_ids.contains(&"secret.google.api_key".to_owned()));
    assert!(rule_ids.contains(&"secret.jwt".to_owned()));
    assert!(rule_ids.contains(&"secret.ssh_private_key".to_owned()));
    assert!(rule_ids.contains(&"secret.generic.assignment".to_owned()));
}

#[test]
fn detects_high_entropy_string_literals() {
    let rule_ids = rule_ids_for(&positive_fixture());

    assert!(rule_ids.contains(&"secret.high_entropy_string".to_owned()));
}

#[test]
fn includes_location_severity_cwe_and_context() {
    let analyzer = SecretsAnalyzer::try_new().expect("secrets analyzer should compile");
    let file = SourceFile::new("src/config.js", Some("javascript"), positive_fixture());
    let findings = analyzer.analyze(&file);
    let aws_finding = findings
        .iter()
        .find(|finding| finding.rule_id == "secret.aws.access_key")
        .expect("fixture should contain an AWS key finding");

    assert_eq!(aws_finding.file_path, "src/config.js");
    assert_eq!(aws_finding.line, 1);
    assert_eq!(aws_finding.severity, Severity::Critical);
    assert_eq!(aws_finding.cwe_id, "CWE-798");
    assert!(aws_finding.snippet.contains("cloudKey"));
}

#[test]
fn does_not_flag_clean_public_configuration_fixture() {
    let source = include_str!("fixtures/secrets_negative_config.txt");

    assert!(rule_ids_for(source).is_empty());
}

#[test]
fn does_not_flag_clean_documentation_fixture() {
    let source = include_str!("fixtures/secrets_negative_docs.txt");

    assert!(rule_ids_for(source).is_empty());
}

#[test]
fn does_not_flag_environment_variable_usage_fixture() {
    let source = include_str!("fixtures/secrets_negative_code.txt");

    assert!(rule_ids_for(source).is_empty());
}

#[test]
fn scan_content_native_returns_report_with_score() {
    let report =
        scan_content_native(&positive_fixture(), "javascript").expect("scan should complete");

    assert_eq!(report.repo, "memory/source");
    assert_eq!(report.stats.files_scanned, 1);
    assert!(!report.findings.is_empty());
    assert!(report.score < 100);
}
