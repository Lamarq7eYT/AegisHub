use regex::Regex;

use crate::analyzer::Analyzer;
use crate::error::{AegisError, Result};
use crate::finding::{Finding, FindingLocation, Severity};
use crate::source::SourceFile;

const ENTROPY_THRESHOLD: f64 = 4.5;
const ENTROPY_MIN_LENGTH: usize = 20;
const SNIPPET_RADIUS: usize = 2;

/// Analyzer that detects hardcoded secrets using regex rules and string entropy.
pub struct SecretsAnalyzer {
    rules: Vec<SecretRule>,
}

struct SecretRule {
    id: &'static str,
    regex: Regex,
    severity: Severity,
    message: &'static str,
    cwe_id: &'static str,
}

struct StringLiteral {
    value: String,
    start: usize,
}

impl SecretsAnalyzer {
    /// Builds a secrets analyzer with all built-in detection rules.
    pub fn try_new() -> Result<Self> {
        let rule_specs = [
            RuleSpec {
                id: "secret.aws.access_key",
                pattern: r"AKIA[0-9A-Z]{16}",
                severity: Severity::Critical,
                message: "Hardcoded AWS access key detected",
                cwe_id: "CWE-798",
            },
            RuleSpec {
                id: "secret.github.token",
                pattern: r"ghp_[A-Za-z0-9]{36}",
                severity: Severity::Critical,
                message: "Hardcoded GitHub personal access token detected",
                cwe_id: "CWE-798",
            },
            RuleSpec {
                id: "secret.stripe.live_key",
                pattern: r"sk_live_[0-9A-Za-z]{24}",
                severity: Severity::Critical,
                message: "Hardcoded Stripe live secret key detected",
                cwe_id: "CWE-798",
            },
            RuleSpec {
                id: "secret.google.api_key",
                pattern: r"AIza[0-9A-Za-z_-]{35}",
                severity: Severity::High,
                message: "Hardcoded Google API key detected",
                cwe_id: "CWE-798",
            },
            RuleSpec {
                id: "secret.jwt",
                pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                severity: Severity::High,
                message: "Hardcoded JWT-like token detected",
                cwe_id: "CWE-798",
            },
            RuleSpec {
                id: "secret.ssh_private_key",
                pattern: r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                severity: Severity::Critical,
                message: "Hardcoded SSH private key header detected",
                cwe_id: "CWE-321",
            },
            RuleSpec {
                id: "secret.generic.assignment",
                pattern: r#"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*["'][^"'\r\n]{8,}["']"#,
                severity: Severity::High,
                message: "Potential hardcoded secret assignment detected",
                cwe_id: "CWE-798",
            },
        ];

        let mut rules = Vec::with_capacity(rule_specs.len());

        for spec in rule_specs {
            let regex = Regex::new(spec.pattern).map_err(|source| AegisError::Regex {
                rule_id: spec.id,
                source,
            })?;

            rules.push(SecretRule {
                id: spec.id,
                regex,
                severity: spec.severity,
                message: spec.message,
                cwe_id: spec.cwe_id,
            });
        }

        Ok(Self { rules })
    }

    fn analyze_patterns(&self, file: &SourceFile) -> Vec<Finding> {
        self.rules
            .iter()
            .flat_map(|rule| {
                rule.regex.find_iter(file.content()).map(|matched| {
                    let location = file.line_col(matched.start());

                    Finding::new(
                        FindingLocation::new(file.path(), location.line, location.column),
                        rule.id,
                        rule.severity,
                        rule.message,
                        file.snippet_around(location.line, SNIPPET_RADIUS),
                        rule.cwe_id,
                    )
                })
            })
            .collect()
    }

    fn analyze_entropy(&self, file: &SourceFile) -> Vec<Finding> {
        extract_string_literals(file.content())
            .into_iter()
            .filter(|literal| literal.value.chars().count() > ENTROPY_MIN_LENGTH)
            .filter(|literal| !is_entropy_allowlisted(&literal.value))
            .filter(|literal| shannon_entropy(&literal.value) > ENTROPY_THRESHOLD)
            .map(|literal| {
                let location = file.line_col(literal.start);

                Finding::new(
                    FindingLocation::new(file.path(), location.line, location.column),
                    "secret.high_entropy_string",
                    Severity::Medium,
                    "High-entropy string literal may contain a secret",
                    file.snippet_around(location.line, SNIPPET_RADIUS),
                    "CWE-798",
                )
            })
            .collect()
    }
}

impl Analyzer for SecretsAnalyzer {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn analyze(&self, file: &SourceFile) -> Vec<Finding> {
        let mut findings = self.analyze_patterns(file);
        findings.extend(self.analyze_entropy(file));
        findings.sort_by(|left, right| {
            left.line
                .cmp(&right.line)
                .then(left.column.cmp(&right.column))
                .then(left.rule_id.cmp(&right.rule_id))
        });
        findings
    }
}

struct RuleSpec {
    id: &'static str,
    pattern: &'static str,
    severity: Severity,
    message: &'static str,
    cwe_id: &'static str,
}

fn extract_string_literals(content: &str) -> Vec<StringLiteral> {
    let mut literals = Vec::new();
    let mut chars = content.char_indices().peekable();

    while let Some((start, current)) = chars.next() {
        if !matches!(current, '"' | '\'' | '`') {
            continue;
        }

        let quote = current;
        let mut escaped = false;
        let mut value = String::new();
        let value_start = start + quote.len_utf8();

        for (_, next) in chars.by_ref() {
            if escaped {
                value.push(next);
                escaped = false;
                continue;
            }

            if next == '\\' {
                escaped = true;
                continue;
            }

            if next == quote {
                literals.push(StringLiteral {
                    value,
                    start: value_start,
                });
                break;
            }

            value.push(next);
        }
    }

    literals
}

fn shannon_entropy(value: &str) -> f64 {
    let mut frequencies = [0_usize; 256];
    let mut total = 0_usize;

    for byte in value.bytes() {
        frequencies[usize::from(byte)] += 1;
        total += 1;
    }

    if total == 0 {
        return 0.0;
    }

    frequencies
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / total as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn is_entropy_allowlisted(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let allowlisted_terms = [
        "example",
        "localhost",
        "not-a-secret",
        "not_a_secret",
        "placeholder",
        "sample",
        "test-fixture",
        "documentation",
    ];

    if normalized.chars().any(char::is_whitespace) {
        return true;
    }

    allowlisted_terms
        .iter()
        .any(|term| normalized.contains(term))
}

#[cfg(test)]
mod tests {
    use super::{extract_string_literals, is_entropy_allowlisted, shannon_entropy};

    #[test]
    fn extracts_single_double_and_template_literals() {
        let literals =
            extract_string_literals(r#"const a = "alpha"; const b = 'beta'; const c = `gamma`;"#);
        let values = literals
            .into_iter()
            .map(|literal| literal.value)
            .collect::<Vec<_>>();

        assert_eq!(values, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn entropy_is_higher_for_random_looking_values() {
        let repeated = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa");
        let varied_value = (0..28)
            .map(|index| char::from(b'A' + ((index * 7) % 26) as u8))
            .collect::<String>();
        let varied = shannon_entropy(&varied_value);

        assert!(varied > repeated);
    }

    #[test]
    fn allowlists_obvious_documentation_values() {
        assert!(is_entropy_allowlisted("example-placeholder-value"));
        assert!(is_entropy_allowlisted("this contains multiple words"));
    }
}
