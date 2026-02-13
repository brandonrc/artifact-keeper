//! Promotion policy service.
//!
//! Evaluates artifacts against security policies before promotion from staging to release.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;
use crate::models::sbom::PolicyAction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub passed: bool,
    pub action: PolicyAction,
    pub violations: Vec<PolicyViolation>,
    pub cve_summary: Option<CveSummary>,
    pub license_summary: Option<LicenseSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSummary {
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub total_count: i32,
    pub open_cves: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseSummary {
    pub licenses_found: Vec<String>,
    pub denied_licenses: Vec<String>,
    pub unknown_licenses: Vec<String>,
}

/// Evaluate CVE counts against a severity threshold, returning violations for
/// any severity level that exceeds the implied limit.
fn evaluate_cve_thresholds(
    summary: &CveSummary,
    max_severity: &str,
    block_on_fail: bool,
) -> Vec<PolicyViolation> {
    let (max_critical, max_high, max_medium) = match max_severity.to_lowercase().as_str() {
        "critical" => (0, i32::MAX, i32::MAX),
        "high" => (0, 0, i32::MAX),
        "medium" | "low" => (0, 0, 0),
        _ => (0, 0, i32::MAX),
    };

    let checks: &[(&str, i32, i32)] = &[
        ("critical", summary.critical_count, max_critical),
        ("high", summary.high_count, max_high),
        ("medium", summary.medium_count, max_medium),
    ];

    checks
        .iter()
        .filter(|(_, count, max)| count > max)
        .map(|(severity, count, max)| PolicyViolation {
            rule: "cve-severity-threshold".to_string(),
            severity: severity.to_string(),
            message: format!(
                "Found {} {} vulnerabilities (max allowed: {})",
                count,
                if *severity == "high" {
                    "high severity"
                } else {
                    severity
                },
                max
            ),
            details: Some(serde_json::json!({
                "count": count,
                "max_allowed": max,
                "block_on_fail": block_on_fail
            })),
        })
        .collect()
}

/// Evaluate licenses found in an SBOM against a license policy, returning
/// violations for denied or unrecognized licenses.
fn evaluate_license_policy(
    summary: &LicenseSummary,
    policy: &LicensePolicyConfig,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    let mut denied_found = Vec::new();
    let mut unknown_found = Vec::new();

    for license in &summary.licenses_found {
        let normalized = license.to_uppercase();

        if policy
            .denied_licenses
            .iter()
            .any(|d| d.to_uppercase() == normalized)
        {
            denied_found.push(license.clone());
            continue;
        }

        if !policy.allowed_licenses.is_empty()
            && !policy
                .allowed_licenses
                .iter()
                .any(|a| a.to_uppercase() == normalized)
            && !policy.allow_unknown
        {
            unknown_found.push(license.clone());
        }
    }

    if !denied_found.is_empty() {
        violations.push(PolicyViolation {
            rule: "license-compliance".to_string(),
            severity: match policy.action {
                PolicyAction::Block => "critical".to_string(),
                PolicyAction::Warn => "medium".to_string(),
                PolicyAction::Allow => "low".to_string(),
            },
            message: format!(
                "Found {} denied licenses: {}",
                denied_found.len(),
                denied_found.join(", ")
            ),
            details: Some(serde_json::json!({
                "denied_licenses": denied_found,
                "policy_name": policy.name
            })),
        });
    }

    if !unknown_found.is_empty() {
        violations.push(PolicyViolation {
            rule: "license-compliance".to_string(),
            severity: "medium".to_string(),
            message: format!(
                "Found {} licenses not in allowed list: {}",
                unknown_found.len(),
                unknown_found.join(", ")
            ),
            details: Some(serde_json::json!({
                "unknown_licenses": unknown_found,
                "policy_name": policy.name
            })),
        });
    }

    violations
}

pub struct PromotionPolicyService {
    db: PgPool,
}

impl PromotionPolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn evaluate_artifact(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
    ) -> Result<PolicyEvaluationResult> {
        let mut violations = Vec::new();
        let mut action = PolicyAction::Allow;

        let cve_summary = self.get_cve_summary(artifact_id).await?;
        let license_summary = self.get_license_summary(artifact_id).await?;
        let scan_policy = self.get_scan_policy(repository_id).await?;
        let license_policy = self.get_license_policy(repository_id).await?;

        if let Some(ref summary) = cve_summary {
            if let Some(ref policy) = scan_policy {
                let cve_violations =
                    evaluate_cve_thresholds(summary, &policy.max_severity, policy.block_on_fail);

                for v in cve_violations {
                    if v.severity == "critical" || v.severity == "high" {
                        action = PolicyAction::Block;
                    } else if action != PolicyAction::Block {
                        action = PolicyAction::Warn;
                    }
                    violations.push(v);
                }
            } else if summary.critical_count > 0 {
                // Default policy: block on any critical CVEs
                action = PolicyAction::Block;
                violations.push(PolicyViolation {
                    rule: "default-cve-policy".to_string(),
                    severity: "critical".to_string(),
                    message: format!(
                        "Artifact has {} critical vulnerabilities",
                        summary.critical_count
                    ),
                    details: Some(serde_json::json!({
                        "cves": summary.open_cves
                    })),
                });
            }
        }

        if let Some(ref summary) = license_summary {
            if let Some(ref policy) = license_policy {
                let license_violations = evaluate_license_policy(summary, policy);

                for v in license_violations {
                    match policy.action {
                        PolicyAction::Block => action = PolicyAction::Block,
                        PolicyAction::Warn if action != PolicyAction::Block => {
                            action = PolicyAction::Warn
                        }
                        _ => {}
                    }
                    violations.push(v);
                }
            }
        }

        let passed = violations.is_empty();

        Ok(PolicyEvaluationResult {
            passed,
            action,
            violations,
            cve_summary,
            license_summary,
        })
    }

    async fn get_cve_summary(&self, artifact_id: Uuid) -> Result<Option<CveSummary>> {
        let scan = sqlx::query!(
            r#"
            SELECT
                critical_count, high_count, medium_count, low_count, findings_count
            FROM scan_results
            WHERE artifact_id = $1 AND status = 'completed'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            artifact_id
        )
        .fetch_optional(&self.db)
        .await?;

        let Some(scan) = scan else {
            return Ok(None);
        };

        let cves: Vec<String> = sqlx::query_scalar!(
            r#"SELECT DISTINCT cve_id as "cve_id!" FROM cve_history WHERE artifact_id = $1 AND status = 'open' AND cve_id IS NOT NULL"#,
            artifact_id
        )
        .fetch_all(&self.db)
        .await?;

        Ok(Some(CveSummary {
            critical_count: scan.critical_count,
            high_count: scan.high_count,
            medium_count: scan.medium_count,
            low_count: scan.low_count,
            total_count: scan.findings_count,
            open_cves: cves,
        }))
    }

    async fn get_license_summary(&self, artifact_id: Uuid) -> Result<Option<LicenseSummary>> {
        let sbom = sqlx::query!(
            r#"
            SELECT licenses
            FROM sbom_documents
            WHERE artifact_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            artifact_id
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(sbom.map(|s| LicenseSummary {
            licenses_found: s.licenses.unwrap_or_default(),
            denied_licenses: vec![],
            unknown_licenses: vec![],
        }))
    }

    async fn get_scan_policy(&self, repository_id: Uuid) -> Result<Option<ScanPolicyConfig>> {
        let policy = sqlx::query!(
            r#"
            SELECT id, name, max_severity, block_unscanned, block_on_fail, is_enabled
            FROM scan_policies
            WHERE (repository_id = $1 OR repository_id IS NULL) AND is_enabled = true
            ORDER BY repository_id DESC NULLS LAST
            LIMIT 1
            "#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(policy.map(|p| ScanPolicyConfig {
            _id: p.id,
            _name: p.name,
            max_severity: p.max_severity,
            _block_unscanned: p.block_unscanned,
            block_on_fail: p.block_on_fail,
        }))
    }

    async fn get_license_policy(&self, repository_id: Uuid) -> Result<Option<LicensePolicyConfig>> {
        let policy = sqlx::query!(
            r#"
            SELECT id, name, allowed_licenses, denied_licenses, allow_unknown, action, is_enabled
            FROM license_policies
            WHERE (repository_id = $1 OR repository_id IS NULL) AND is_enabled = true
            ORDER BY repository_id DESC NULLS LAST
            LIMIT 1
            "#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(policy.map(|p| LicensePolicyConfig {
            _id: p.id,
            name: p.name,
            allowed_licenses: p.allowed_licenses.unwrap_or_default(),
            denied_licenses: p.denied_licenses.unwrap_or_default(),
            allow_unknown: p.allow_unknown,
            action: PolicyAction::parse(&p.action).unwrap_or(PolicyAction::Warn),
        }))
    }
}

#[derive(Debug, Clone)]
struct ScanPolicyConfig {
    _id: Uuid,
    _name: String,
    max_severity: String,
    _block_unscanned: bool,
    block_on_fail: bool,
}

#[derive(Debug, Clone)]
struct LicensePolicyConfig {
    _id: Uuid,
    name: String,
    allowed_licenses: Vec<String>,
    denied_licenses: Vec<String>,
    allow_unknown: bool,
    action: PolicyAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // evaluate_cve_thresholds tests
    // =======================================================================

    #[test]
    fn test_cve_threshold_evaluation() {
        let summary = CveSummary {
            critical_count: 2,
            high_count: 5,
            medium_count: 10,
            low_count: 20,
            total_count: 37,
            open_cves: vec!["CVE-2024-1234".to_string()],
        };

        let violations = evaluate_cve_thresholds(&summary, "high", true);
        assert_eq!(violations.len(), 2);

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_cve_threshold_medium_blocks_all_three() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 2,
            medium_count: 3,
            low_count: 0,
            total_count: 6,
            open_cves: vec![],
        };

        // medium/low threshold: max_critical=0, max_high=0, max_medium=0
        let violations = evaluate_cve_thresholds(&summary, "medium", true);
        assert_eq!(violations.len(), 3);

        let severities: Vec<&str> = violations.iter().map(|v| v.severity.as_str()).collect();
        assert!(severities.contains(&"critical"));
        assert!(severities.contains(&"high"));
        assert!(severities.contains(&"medium"));
    }

    #[test]
    fn test_cve_threshold_low_same_as_medium() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
            low_count: 10,
            total_count: 13,
            open_cves: vec![],
        };

        // "low" maps to same thresholds as "medium": (0, 0, 0)
        let violations = evaluate_cve_thresholds(&summary, "low", false);
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn test_cve_threshold_unknown_severity_defaults() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 1,
            medium_count: 0,
            low_count: 0,
            total_count: 2,
            open_cves: vec![],
        };

        // Unknown max_severity string defaults to (0, 0, i32::MAX)
        let violations = evaluate_cve_thresholds(&summary, "foobar", true);
        // critical=1 > max_critical=0 => violation
        // high=1 > max_high=0 => violation
        // medium=0 <= i32::MAX => no violation
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn test_cve_threshold_no_violations_when_clean() {
        let summary = CveSummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 5,
            total_count: 5,
            open_cves: vec![],
        };

        // critical threshold: only critical > 0 fails
        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert!(violations.is_empty());

        // high threshold: critical=0 ok, high=0 ok
        let violations = evaluate_cve_thresholds(&summary, "high", true);
        assert!(violations.is_empty());

        // medium threshold: critical=0 ok, high=0 ok, medium=0 ok
        let violations = evaluate_cve_thresholds(&summary, "medium", false);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_cve_threshold_case_insensitive() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 1,
            open_cves: vec![],
        };

        // The function uses .to_lowercase() on max_severity
        let violations = evaluate_cve_thresholds(&summary, "CRITICAL", true);
        assert_eq!(violations.len(), 1);

        let violations = evaluate_cve_thresholds(&summary, "Critical", true);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_cve_threshold_violation_details_include_block_on_fail() {
        let summary = CveSummary {
            critical_count: 5,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 5,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations.len(), 1);
        let details = violations[0].details.as_ref().unwrap();
        assert_eq!(details["count"], 5);
        assert_eq!(details["max_allowed"], 0);
        assert_eq!(details["block_on_fail"], true);

        let violations = evaluate_cve_thresholds(&summary, "critical", false);
        let details = violations[0].details.as_ref().unwrap();
        assert_eq!(details["block_on_fail"], false);
    }

    #[test]
    fn test_cve_threshold_violation_rule_name() {
        let summary = CveSummary {
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 1,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations[0].rule, "cve-severity-threshold");
        assert_eq!(violations[0].severity, "critical");
    }

    #[test]
    fn test_cve_threshold_high_message_formatting() {
        let summary = CveSummary {
            critical_count: 0,
            high_count: 3,
            medium_count: 0,
            low_count: 0,
            total_count: 3,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "high", true);
        assert_eq!(violations.len(), 1);
        // "high" severity gets special message formatting "high severity"
        assert!(violations[0].message.contains("high severity"));
    }

    #[test]
    fn test_cve_threshold_critical_message_formatting() {
        let summary = CveSummary {
            critical_count: 2,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 2,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert_eq!(violations.len(), 1);
        // "critical" does not get the "high severity" special formatting
        assert!(violations[0].message.contains("critical"));
        assert!(!violations[0].message.contains("critical severity"));
    }

    #[test]
    fn test_cve_threshold_critical_only_checks_critical() {
        // "critical" threshold: (0, i32::MAX, i32::MAX)
        // Only critical CVEs cause violations
        let summary = CveSummary {
            critical_count: 0,
            high_count: 100,
            medium_count: 200,
            low_count: 300,
            total_count: 600,
            open_cves: vec![],
        };

        let violations = evaluate_cve_thresholds(&summary, "critical", true);
        assert!(violations.is_empty());
    }

    // =======================================================================
    // evaluate_license_policy tests
    // =======================================================================

    #[test]
    fn test_license_policy_evaluation() {
        let summary = LicenseSummary {
            licenses_found: vec![
                "MIT".to_string(),
                "GPL-3.0".to_string(),
                "Apache-2.0".to_string(),
            ],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "test-policy".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("GPL-3.0"));
    }

    #[test]
    fn test_license_policy_no_violations_all_allowed() {
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "permissive".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            allow_unknown: false,
            action: PolicyAction::Allow,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_license_policy_denied_takes_precedence_over_allowed() {
        // MIT is in both allowed and denied lists; denied should win
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "contradictory".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["MIT".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "license-compliance");
        assert!(violations[0].message.contains("denied"));
    }

    #[test]
    fn test_license_policy_unknown_license_not_in_allowed_list() {
        let summary = LicenseSummary {
            licenses_found: vec!["BSD-3-Clause".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "strict".to_string(),
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec![],
            allow_unknown: false,
            action: PolicyAction::Warn,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("not in allowed list"));
        assert!(violations[0].message.contains("BSD-3-Clause"));
        assert_eq!(violations[0].severity, "medium");
    }

    #[test]
    fn test_license_policy_allow_unknown_permits_unlisted() {
        let summary = LicenseSummary {
            licenses_found: vec!["BSD-3-Clause".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "lenient".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec![],
            allow_unknown: true,
            action: PolicyAction::Warn,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_license_policy_empty_allowed_list_skips_unknown_check() {
        // When allowed_licenses is empty, the code has a guard:
        // !policy.allowed_licenses.is_empty() && ...
        // So no unknown violation should be produced.
        let summary = LicenseSummary {
            licenses_found: vec!["WhateverLicense".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "no-allowed-list".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec![],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_license_policy_case_insensitive_matching() {
        let summary = LicenseSummary {
            licenses_found: vec!["mit".to_string(), "gpl-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "case-test".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        // "mit" matches "MIT" via to_uppercase(), "gpl-3.0" matches "GPL-3.0"
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("denied"));
    }

    #[test]
    fn test_license_policy_severity_maps_to_action() {
        let summary = LicenseSummary {
            licenses_found: vec!["AGPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        // Block action => "critical" severity
        let policy_block = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "block-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };
        let violations = evaluate_license_policy(&summary, &policy_block);
        assert_eq!(violations[0].severity, "critical");

        // Warn action => "medium" severity
        let policy_warn = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "warn-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Warn,
        };
        let violations = evaluate_license_policy(&summary, &policy_warn);
        assert_eq!(violations[0].severity, "medium");

        // Allow action => "low" severity
        let policy_allow = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "allow-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Allow,
        };
        let violations = evaluate_license_policy(&summary, &policy_allow);
        assert_eq!(violations[0].severity, "low");
    }

    #[test]
    fn test_license_policy_details_include_policy_name() {
        let summary = LicenseSummary {
            licenses_found: vec!["GPL-3.0".to_string()],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "corporate-policy".to_string(),
            allowed_licenses: vec![],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        let details = violations[0].details.as_ref().unwrap();
        assert_eq!(details["policy_name"], "corporate-policy");
        let denied = details["denied_licenses"].as_array().unwrap();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0], "GPL-3.0");
    }

    #[test]
    fn test_license_policy_multiple_denied_and_unknown() {
        let summary = LicenseSummary {
            licenses_found: vec![
                "MIT".to_string(),
                "GPL-3.0".to_string(),
                "AGPL-3.0".to_string(),
                "WTFPL".to_string(),
                "Unlicense".to_string(),
            ],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "multi".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        // 2 denied licenses => 1 denied violation
        // WTFPL and Unlicense not in allowed list => 1 unknown violation
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].rule, "license-compliance");
        assert!(violations[0].message.contains("2 denied"));
        assert_eq!(violations[1].rule, "license-compliance");
        assert!(violations[1]
            .message
            .contains("2 licenses not in allowed list"));
    }

    #[test]
    fn test_license_policy_no_licenses_found() {
        let summary = LicenseSummary {
            licenses_found: vec![],
            denied_licenses: vec![],
            unknown_licenses: vec![],
        };

        let policy = LicensePolicyConfig {
            _id: Uuid::new_v4(),
            name: "empty".to_string(),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: PolicyAction::Block,
        };

        let violations = evaluate_license_policy(&summary, &policy);
        assert!(violations.is_empty());
    }

    // =======================================================================
    // Data model serialization tests
    // =======================================================================

    #[test]
    fn test_policy_violation_serialization() {
        let violation = PolicyViolation {
            rule: "cve-severity-threshold".to_string(),
            severity: "critical".to_string(),
            message: "Found 5 critical vulnerabilities".to_string(),
            details: Some(serde_json::json!({"count": 5})),
        };

        let json = serde_json::to_value(&violation).unwrap();
        assert_eq!(json["rule"], "cve-severity-threshold");
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["details"]["count"], 5);
    }

    #[test]
    fn test_policy_violation_without_details() {
        let violation = PolicyViolation {
            rule: "test-rule".to_string(),
            severity: "low".to_string(),
            message: "test".to_string(),
            details: None,
        };

        let json = serde_json::to_value(&violation).unwrap();
        assert!(json["details"].is_null());
    }

    #[test]
    fn test_policy_evaluation_result_passed() {
        let result = PolicyEvaluationResult {
            passed: true,
            action: PolicyAction::Allow,
            violations: vec![],
            cve_summary: None,
            license_summary: None,
        };

        assert!(result.passed);
        assert!(result.violations.is_empty());
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["passed"], true);
    }

    #[test]
    fn test_policy_evaluation_result_failed() {
        let result = PolicyEvaluationResult {
            passed: false,
            action: PolicyAction::Block,
            violations: vec![PolicyViolation {
                rule: "cve-severity-threshold".to_string(),
                severity: "critical".to_string(),
                message: "Found critical CVEs".to_string(),
                details: None,
            }],
            cve_summary: Some(CveSummary {
                critical_count: 3,
                high_count: 1,
                medium_count: 0,
                low_count: 0,
                total_count: 4,
                open_cves: vec!["CVE-2024-0001".to_string()],
            }),
            license_summary: None,
        };

        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.cve_summary.as_ref().unwrap().critical_count, 3);
    }

    #[test]
    fn test_cve_summary_serialization_roundtrip() {
        let summary = CveSummary {
            critical_count: 2,
            high_count: 5,
            medium_count: 10,
            low_count: 20,
            total_count: 37,
            open_cves: vec!["CVE-2024-1234".to_string(), "CVE-2024-5678".to_string()],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: CveSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.critical_count, 2);
        assert_eq!(parsed.high_count, 5);
        assert_eq!(parsed.medium_count, 10);
        assert_eq!(parsed.low_count, 20);
        assert_eq!(parsed.total_count, 37);
        assert_eq!(parsed.open_cves.len(), 2);
    }

    #[test]
    fn test_license_summary_serialization_roundtrip() {
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            unknown_licenses: vec!["CustomLicense".to_string()],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: LicenseSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.licenses_found.len(), 2);
        assert_eq!(parsed.denied_licenses.len(), 1);
        assert_eq!(parsed.unknown_licenses.len(), 1);
    }

    #[test]
    fn test_policy_action_serialization() {
        let result = PolicyEvaluationResult {
            passed: true,
            action: PolicyAction::Warn,
            violations: vec![],
            cve_summary: None,
            license_summary: None,
        };

        let json = serde_json::to_value(&result).unwrap();
        // PolicyAction should serialize to its string form
        assert!(json["action"].is_string());
    }
}
