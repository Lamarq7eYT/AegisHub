use crate::finding::{Finding, Severity};

/// Computes a security score from findings.
///
/// The score starts at 100 and subtracts:
/// Critical: 25, High: 10, Medium: 5, Low: 2, Info: 0.
pub fn compute_score(findings: &[Finding]) -> u8 {
    let penalty = findings
        .iter()
        .map(|finding| match finding.severity {
            Severity::Critical => 25_u16,
            Severity::High => 10,
            Severity::Medium => 5,
            Severity::Low => 2,
            Severity::Info => 0,
        })
        .sum::<u16>();

    100_u16.saturating_sub(penalty) as u8
}

#[cfg(test)]
mod tests {
    use super::compute_score;
    use crate::finding::{Finding, FindingLocation, Severity};

    fn finding(severity: Severity) -> Finding {
        Finding::new(
            FindingLocation::new("src/app.js", 1, 1),
            "test.rule",
            severity,
            "test finding",
            "   1 | test",
            "CWE-000",
        )
    }

    #[test]
    fn starts_at_one_hundred_for_clean_reports() {
        assert_eq!(compute_score(&[]), 100);
    }

    #[test]
    fn subtracts_expected_penalties() {
        let findings = vec![
            finding(Severity::Critical),
            finding(Severity::High),
            finding(Severity::Medium),
            finding(Severity::Low),
            finding(Severity::Info),
        ];

        assert_eq!(compute_score(&findings), 58);
    }

    #[test]
    fn floors_at_zero() {
        let findings = (0..10)
            .map(|_| finding(Severity::Critical))
            .collect::<Vec<_>>();

        assert_eq!(compute_score(&findings), 0);
    }
}
