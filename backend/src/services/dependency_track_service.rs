//! Dependency-Track integration service.
//!
//! Provides API client for OWASP Dependency-Track to upload SBOMs,
//! retrieve vulnerability findings, and manage policy violations.
//!
//! ## Configuration
//!
//! ```bash
//! DEPENDENCY_TRACK_URL=http://localhost:8092
//! DEPENDENCY_TRACK_API_KEY=your-api-key
//! DEPENDENCY_TRACK_ENABLED=true
//! ```
//!
//! ## API Reference
//!
//! See: https://docs.dependencytrack.org/integrations/rest-api/

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};
use utoipa::ToSchema;

use crate::error::{AppError, Result};

/// Dependency-Track service configuration
#[derive(Debug, Clone)]
pub struct DependencyTrackConfig {
    /// Base URL of the Dependency-Track API server
    pub base_url: String,
    /// API key for authentication (X-Api-Key header)
    pub api_key: String,
    /// Whether integration is enabled
    pub enabled: bool,
}

impl DependencyTrackConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("DEPENDENCY_TRACK_ENABLED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        if !enabled {
            return None;
        }

        let base_url = std::env::var("DEPENDENCY_TRACK_URL").ok()?;
        let api_key = std::env::var("DEPENDENCY_TRACK_API_KEY").ok()?;

        Some(Self {
            base_url,
            api_key,
            enabled,
        })
    }
}

/// Dependency-Track API client
pub struct DependencyTrackService {
    client: Client,
    config: DependencyTrackConfig,
}

/// Dependency-Track project representation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtProject {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "lastBomImport")]
    pub last_bom_import: Option<i64>,
    #[serde(rename = "lastBomImportFormat")]
    pub last_bom_import_format: Option<String>,
}

/// Request to create a new project
#[derive(Debug, Serialize)]
struct CreateProjectRequest {
    name: String,
    version: Option<String>,
    description: Option<String>,
}

/// BOM upload response
#[derive(Debug, Deserialize)]
pub struct BomUploadResponse {
    pub token: String,
}

/// BOM processing status
#[derive(Debug, Deserialize)]
pub struct BomProcessingStatus {
    pub processing: bool,
}

/// Vulnerability finding from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtFinding {
    pub component: DtComponent,
    pub vulnerability: DtVulnerability,
    pub analysis: Option<DtAnalysis>,
    pub attribution: Option<DtAttribution>,
}

/// Component affected by a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtComponent {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
    pub group: Option<String>,
    pub purl: Option<String>,
}

/// Vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtVulnerability {
    pub uuid: String,
    #[serde(rename = "vulnId")]
    pub vuln_id: String,
    pub source: String,
    pub severity: String,
    pub title: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "cvssV3BaseScore")]
    pub cvss_v3_base_score: Option<f64>,
    pub cwe: Option<DtCwe>,
}

/// CWE reference
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtCwe {
    #[serde(rename = "cweId")]
    pub cwe_id: i32,
    pub name: String,
}

/// Analysis state for a finding
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtAnalysis {
    pub state: Option<String>,
    pub justification: Option<String>,
    pub response: Option<String>,
    pub details: Option<String>,
    #[serde(rename = "isSuppressed")]
    pub is_suppressed: bool,
}

/// Attribution info
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtAttribution {
    #[serde(rename = "analyzerIdentity")]
    pub analyzer_identity: Option<String>,
    #[serde(rename = "attributedOn")]
    pub attributed_on: Option<i64>,
}

/// Policy violation from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicyViolation {
    pub uuid: String,
    #[serde(rename = "type")]
    pub violation_type: String,
    pub component: DtComponent,
    #[serde(rename = "policyCondition")]
    pub policy_condition: DtPolicyCondition,
}

/// Policy condition that was violated
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicyCondition {
    pub uuid: String,
    pub subject: String,
    pub operator: String,
    pub value: String,
    pub policy: DtPolicy,
}

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicy {
    pub uuid: String,
    pub name: String,
    #[serde(rename = "violationState")]
    pub violation_state: String,
}

/// Project-level metrics from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtProjectMetrics {
    #[serde(default)]
    pub critical: i64,
    #[serde(default)]
    pub high: i64,
    #[serde(default)]
    pub medium: i64,
    #[serde(default)]
    pub low: i64,
    #[serde(default)]
    pub unassigned: i64,
    #[serde(default)]
    pub vulnerabilities: Option<i64>,
    #[serde(default, rename = "findingsTotal")]
    pub findings_total: i64,
    #[serde(default, rename = "findingsAudited")]
    pub findings_audited: i64,
    #[serde(default, rename = "findingsUnaudited")]
    pub findings_unaudited: i64,
    #[serde(default)]
    pub suppressions: i64,
    #[serde(default, rename = "inheritedRiskScore")]
    pub inherited_risk_score: f64,
    #[serde(default, rename = "policyViolationsFail")]
    pub policy_violations_fail: i64,
    #[serde(default, rename = "policyViolationsWarn")]
    pub policy_violations_warn: i64,
    #[serde(default, rename = "policyViolationsInfo")]
    pub policy_violations_info: i64,
    #[serde(default, rename = "policyViolationsTotal")]
    pub policy_violations_total: i64,
    #[serde(rename = "firstOccurrence")]
    pub first_occurrence: Option<i64>,
    #[serde(rename = "lastOccurrence")]
    pub last_occurrence: Option<i64>,
}

/// Portfolio-level metrics from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPortfolioMetrics {
    #[serde(default)]
    pub critical: i64,
    #[serde(default)]
    pub high: i64,
    #[serde(default)]
    pub medium: i64,
    #[serde(default)]
    pub low: i64,
    #[serde(default)]
    pub unassigned: i64,
    #[serde(default)]
    pub vulnerabilities: Option<i64>,
    #[serde(default, rename = "findingsTotal")]
    pub findings_total: i64,
    #[serde(default, rename = "findingsAudited")]
    pub findings_audited: i64,
    #[serde(default, rename = "findingsUnaudited")]
    pub findings_unaudited: i64,
    #[serde(default)]
    pub suppressions: i64,
    #[serde(default, rename = "inheritedRiskScore")]
    pub inherited_risk_score: f64,
    #[serde(default, rename = "policyViolationsFail")]
    pub policy_violations_fail: i64,
    #[serde(default, rename = "policyViolationsWarn")]
    pub policy_violations_warn: i64,
    #[serde(default, rename = "policyViolationsInfo")]
    pub policy_violations_info: i64,
    #[serde(default, rename = "policyViolationsTotal")]
    pub policy_violations_total: i64,
    #[serde(default)]
    pub projects: i64,
}

/// Full component representation from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtComponentFull {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
    pub group: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    #[serde(rename = "resolvedLicense")]
    pub resolved_license: Option<DtLicense>,
    #[serde(rename = "isInternal")]
    pub is_internal: Option<bool>,
}

/// License information from Dependency-Track
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtLicense {
    pub uuid: Option<String>,
    #[serde(rename = "licenseId")]
    pub license_id: Option<String>,
    pub name: String,
}

/// Full policy representation with conditions and projects
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicyFull {
    pub uuid: String,
    pub name: String,
    #[serde(rename = "violationState")]
    pub violation_state: String,
    #[serde(rename = "includeChildren")]
    pub include_children: Option<bool>,
    #[serde(rename = "policyConditions")]
    pub policy_conditions: Vec<DtPolicyConditionFull>,
    pub projects: Vec<DtProject>,
    #[schema(value_type = Vec<Object>)]
    pub tags: Vec<serde_json::Value>,
}

/// Full policy condition with all fields
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtPolicyConditionFull {
    pub uuid: String,
    pub subject: String,
    pub operator: String,
    pub value: String,
}

/// Request to update analysis state for a finding
#[derive(Debug, Serialize, ToSchema)]
pub struct UpdateAnalysisRequest {
    pub project: String,
    pub component: String,
    pub vulnerability: String,
    #[serde(rename = "analysisState")]
    pub analysis_state: String,
    #[serde(
        rename = "analysisJustification",
        skip_serializing_if = "Option::is_none"
    )]
    pub analysis_justification: Option<String>,
    #[serde(rename = "analysisDetails", skip_serializing_if = "Option::is_none")]
    pub analysis_details: Option<String>,
    #[serde(rename = "isSuppressed")]
    pub is_suppressed: bool,
}

/// Response from analysis update
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DtAnalysisResponse {
    #[serde(rename = "analysisState")]
    pub analysis_state: String,
    #[serde(rename = "analysisJustification")]
    pub analysis_justification: Option<String>,
    #[serde(rename = "analysisDetails")]
    pub analysis_details: Option<String>,
    #[serde(rename = "isSuppressed")]
    pub is_suppressed: bool,
}

impl DependencyTrackService {
    /// Create a new Dependency-Track service
    pub fn new(config: DependencyTrackConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        info!(
            url = %config.base_url,
            "Dependency-Track integration initialized"
        );

        Ok(Self { client, config })
    }

    /// Create from environment variables, returns None if not enabled
    pub fn from_env() -> Option<Result<Self>> {
        DependencyTrackConfig::from_env().map(Self::new)
    }

    /// Check if the service is available
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/api/version", self.config.base_url);

        match self.client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!(error = %e, "Dependency-Track health check failed");
                Ok(false)
            }
        }
    }

    /// Get or create a project for a repository
    pub async fn get_or_create_project(
        &self,
        name: &str,
        version: Option<&str>,
        description: Option<&str>,
    ) -> Result<DtProject> {
        // First try to find existing project
        if let Some(project) = self.find_project(name, version).await? {
            return Ok(project);
        }

        // Create new project
        self.create_project(name, version, description).await
    }

    /// Find a project by name and version
    pub async fn find_project(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<DtProject>> {
        let url = match version {
            Some(v) => format!(
                "{}/api/v1/project/lookup?name={}&version={}",
                self.config.base_url,
                urlencoding::encode(name),
                urlencoding::encode(v)
            ),
            None => format!(
                "{}/api/v1/project/lookup?name={}",
                self.config.base_url,
                urlencoding::encode(name)
            ),
        };

        let response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT API request failed: {}", e)))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT project lookup failed: {} - {}",
                status, body
            )));
        }

        let project: DtProject = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse DT project: {}", e)))?;

        Ok(Some(project))
    }

    /// Create a new project
    pub async fn create_project(
        &self,
        name: &str,
        version: Option<&str>,
        description: Option<&str>,
    ) -> Result<DtProject> {
        let url = format!("{}/api/v1/project", self.config.base_url);

        let request = CreateProjectRequest {
            name: name.to_string(),
            version: version.map(String::from),
            description: description.map(String::from),
        };

        let response: reqwest::Response = self
            .client
            .put(&url)
            .header("X-Api-Key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT create project failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT create project failed: {} - {}",
                status, body
            )));
        }

        let project = response
            .json::<DtProject>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse DT project: {}", e)))?;

        info!(
            project_uuid = %project.uuid,
            project_name = %project.name,
            "Created Dependency-Track project"
        );

        Ok(project)
    }

    /// Upload an SBOM (CycloneDX format) to a project
    pub async fn upload_sbom(
        &self,
        project_uuid: &str,
        sbom_content: &str,
    ) -> Result<BomUploadResponse> {
        let url = format!("{}/api/v1/bom", self.config.base_url);

        // DT expects base64-encoded BOM
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encoded_bom = STANDARD.encode(sbom_content);

        let body = serde_json::json!({
            "project": project_uuid,
            "bom": encoded_bom
        });

        let response: reqwest::Response = self
            .client
            .put(&url)
            .header("X-Api-Key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT BOM upload failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT BOM upload failed: {} - {}",
                status, body
            )));
        }

        let result = response.json::<BomUploadResponse>().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse BOM upload response: {}", e))
        })?;

        debug!(
            project_uuid = %project_uuid,
            token = %result.token,
            "Uploaded SBOM to Dependency-Track"
        );

        Ok(result)
    }

    /// Check if BOM processing is complete
    pub async fn is_bom_processing(&self, token: &str) -> Result<bool> {
        let url = format!("{}/api/v1/bom/token/{}", self.config.base_url, token);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT BOM status check failed: {}", e)))?;

        if !response.status().is_success() {
            // Token not found or expired means processing is complete
            return Ok(false);
        }

        let status = response
            .json::<BomProcessingStatus>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse BOM status: {}", e)))?;

        Ok(status.processing)
    }

    /// Wait for BOM processing to complete (with timeout)
    pub async fn wait_for_bom_processing(&self, token: &str, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(2);

        while start.elapsed() < timeout {
            if !self.is_bom_processing(token).await? {
                return Ok(());
            }
            tokio::time::sleep(poll_interval).await;
        }

        Err(AppError::Internal("BOM processing timeout".to_string()))
    }

    /// Get vulnerability findings for a project
    pub async fn get_findings(&self, project_uuid: &str) -> Result<Vec<DtFinding>> {
        let url = format!(
            "{}/api/v1/finding/project/{}",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get findings failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get findings failed: {} - {}",
                status, body
            )));
        }

        let findings = response
            .json::<Vec<DtFinding>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse findings: {}", e)))?;

        debug!(
            project_uuid = %project_uuid,
            count = findings.len(),
            "Retrieved vulnerability findings from Dependency-Track"
        );

        Ok(findings)
    }

    /// Get policy violations for a project
    pub async fn get_policy_violations(
        &self,
        project_uuid: &str,
    ) -> Result<Vec<DtPolicyViolation>> {
        let url = format!(
            "{}/api/v1/violation/project/{}",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get violations failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get violations failed: {} - {}",
                status, body
            )));
        }

        let violations = response
            .json::<Vec<DtPolicyViolation>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse violations: {}", e)))?;

        debug!(
            project_uuid = %project_uuid,
            count = violations.len(),
            "Retrieved policy violations from Dependency-Track"
        );

        Ok(violations)
    }

    /// Get all projects
    pub async fn list_projects(&self) -> Result<Vec<DtProject>> {
        let url = format!("{}/api/v1/project", self.config.base_url);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT list projects failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT list projects failed: {} - {}",
                status, body
            )));
        }

        let projects = response
            .json::<Vec<DtProject>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse projects: {}", e)))?;

        Ok(projects)
    }

    /// Delete a project
    pub async fn delete_project(&self, project_uuid: &str) -> Result<()> {
        let url = format!("{}/api/v1/project/{}", self.config.base_url, project_uuid);

        let response: reqwest::Response = self
            .client
            .delete(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT delete project failed: {}", e)))?;

        if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT delete project failed: {} - {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Get current metrics for a project
    pub async fn get_project_metrics(&self, project_uuid: &str) -> Result<DtProjectMetrics> {
        let url = format!(
            "{}/api/v1/metrics/project/{}/current",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get project metrics failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get project metrics failed: {} - {}",
                status, body
            )));
        }

        let metrics = response
            .json::<DtProjectMetrics>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse project metrics: {}", e)))?;

        Ok(metrics)
    }

    /// Get project metrics history for a number of days
    pub async fn get_project_metrics_history(
        &self,
        project_uuid: &str,
        days: u32,
    ) -> Result<Vec<DtProjectMetrics>> {
        let url = format!(
            "{}/api/v1/metrics/project/{}/days/{}",
            self.config.base_url, project_uuid, days
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("DT get project metrics history failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get project metrics history failed: {} - {}",
                status, body
            )));
        }

        let metrics = response
            .json::<Vec<DtProjectMetrics>>()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to parse project metrics history: {}", e))
            })?;

        Ok(metrics)
    }

    /// Get current portfolio-wide metrics
    pub async fn get_portfolio_metrics(&self) -> Result<DtPortfolioMetrics> {
        let url = format!("{}/api/v1/metrics/portfolio/current", self.config.base_url);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get portfolio metrics failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get portfolio metrics failed: {} - {}",
                status, body
            )));
        }

        let metrics = response
            .json::<DtPortfolioMetrics>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse portfolio metrics: {}", e)))?;

        Ok(metrics)
    }

    /// Refresh metrics for a project (fire-and-forget)
    pub async fn refresh_project_metrics(&self, project_uuid: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/metrics/project/{}/refresh",
            self.config.base_url, project_uuid
        );

        let response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await;

        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(
                        project_uuid = %project_uuid,
                        status = %resp.status(),
                        "DT refresh project metrics returned non-success status"
                    );
                }
            }
            Err(e) => {
                warn!(
                    project_uuid = %project_uuid,
                    error = %e,
                    "DT refresh project metrics request failed"
                );
            }
        }

        Ok(())
    }

    /// Update analysis state for a finding
    #[allow(clippy::too_many_arguments)]
    pub async fn update_analysis(
        &self,
        project_uuid: &str,
        component_uuid: &str,
        vulnerability_uuid: &str,
        state: &str,
        justification: Option<&str>,
        details: Option<&str>,
        suppressed: bool,
    ) -> Result<DtAnalysisResponse> {
        let url = format!("{}/api/v1/analysis", self.config.base_url);

        let request = UpdateAnalysisRequest {
            project: project_uuid.to_string(),
            component: component_uuid.to_string(),
            vulnerability: vulnerability_uuid.to_string(),
            analysis_state: state.to_string(),
            analysis_justification: justification.map(String::from),
            analysis_details: details.map(String::from),
            is_suppressed: suppressed,
        };

        let response: reqwest::Response = self
            .client
            .put(&url)
            .header("X-Api-Key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT update analysis failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT update analysis failed: {} - {}",
                status, body
            )));
        }

        let analysis = response
            .json::<DtAnalysisResponse>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse analysis response: {}", e)))?;

        Ok(analysis)
    }

    /// Get all policies
    pub async fn get_policies(&self) -> Result<Vec<DtPolicyFull>> {
        let url = format!("{}/api/v1/policy", self.config.base_url);

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get policies failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get policies failed: {} - {}",
                status, body
            )));
        }

        let policies = response
            .json::<Vec<DtPolicyFull>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse policies: {}", e)))?;

        Ok(policies)
    }

    /// Get components for a project
    pub async fn get_components(&self, project_uuid: &str) -> Result<Vec<DtComponentFull>> {
        let url = format!(
            "{}/api/v1/component/project/{}",
            self.config.base_url, project_uuid
        );

        let response: reqwest::Response = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DT get components failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DT get components failed: {} - {}",
                status, body
            )));
        }

        let components = response
            .json::<Vec<DtComponentFull>>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse components: {}", e)))?;

        Ok(components)
    }

    /// Get the base URL of the Dependency-Track instance
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Check if the integration is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env_disabled() {
        // When DEPENDENCY_TRACK_ENABLED is not set, should return None
        // SAFETY: Test-only, single-threaded access to env vars
        unsafe { std::env::remove_var("DEPENDENCY_TRACK_ENABLED") };
        assert!(DependencyTrackConfig::from_env().is_none());
    }

    #[test]
    fn test_dt_finding_deserialize() {
        let json = r#"{
            "component": {
                "uuid": "test-uuid",
                "name": "lodash",
                "version": "4.17.0",
                "group": null,
                "purl": "pkg:npm/lodash@4.17.0"
            },
            "vulnerability": {
                "uuid": "vuln-uuid",
                "vulnId": "CVE-2021-23337",
                "source": "NVD",
                "severity": "HIGH",
                "title": "Prototype Pollution",
                "description": "Test description",
                "cvssV3BaseScore": 7.5,
                "cwe": {
                    "cweId": 1321,
                    "name": "Improperly Controlled Modification"
                }
            },
            "analysis": null,
            "attribution": null
        }"#;

        let finding: DtFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.vulnerability.vuln_id, "CVE-2021-23337");
        assert_eq!(finding.vulnerability.severity, "HIGH");
        assert_eq!(finding.component.name, "lodash");
    }

    #[test]
    fn test_dt_policy_violation_deserialize() {
        let json = r#"{
            "uuid": "violation-uuid",
            "type": "LICENSE",
            "component": {
                "uuid": "comp-uuid",
                "name": "gpl-lib",
                "version": "1.0.0",
                "group": null,
                "purl": null
            },
            "policyCondition": {
                "uuid": "cond-uuid",
                "subject": "LICENSE",
                "operator": "IS",
                "value": "GPL-3.0",
                "policy": {
                    "uuid": "policy-uuid",
                    "name": "No GPL",
                    "violationState": "FAIL"
                }
            }
        }"#;

        let violation: DtPolicyViolation = serde_json::from_str(json).unwrap();
        assert_eq!(violation.violation_type, "LICENSE");
        assert_eq!(violation.policy_condition.policy.name, "No GPL");
    }

    #[test]
    fn test_dt_project_metrics_deserialize() {
        let json = r#"{
            "critical": 2,
            "high": 5,
            "medium": 12,
            "low": 3,
            "unassigned": 0,
            "vulnerabilities": 22,
            "findingsTotal": 22,
            "findingsAudited": 4,
            "findingsUnaudited": 18,
            "suppressions": 1,
            "inheritedRiskScore": 42.5,
            "policyViolationsFail": 1,
            "policyViolationsWarn": 2,
            "policyViolationsInfo": 0,
            "policyViolationsTotal": 3,
            "firstOccurrence": 1700000000000,
            "lastOccurrence": 1700100000000
        }"#;

        let metrics: DtProjectMetrics = serde_json::from_str(json).unwrap();
        assert_eq!(metrics.critical, 2);
        assert_eq!(metrics.high, 5);
        assert_eq!(metrics.medium, 12);
        assert_eq!(metrics.low, 3);
        assert_eq!(metrics.unassigned, 0);
        assert_eq!(metrics.vulnerabilities, Some(22));
        assert_eq!(metrics.findings_total, 22);
        assert_eq!(metrics.findings_audited, 4);
        assert_eq!(metrics.findings_unaudited, 18);
        assert_eq!(metrics.suppressions, 1);
        assert!((metrics.inherited_risk_score - 42.5).abs() < f64::EPSILON);
        assert_eq!(metrics.policy_violations_fail, 1);
        assert_eq!(metrics.policy_violations_warn, 2);
        assert_eq!(metrics.policy_violations_info, 0);
        assert_eq!(metrics.policy_violations_total, 3);
        assert_eq!(metrics.first_occurrence, Some(1700000000000));
        assert_eq!(metrics.last_occurrence, Some(1700100000000));
    }

    #[test]
    fn test_dt_component_full_deserialize() {
        let json = r#"{
            "uuid": "comp-uuid-123",
            "name": "express",
            "version": "4.18.2",
            "group": "npm",
            "purl": "pkg:npm/express@4.18.2",
            "cpe": null,
            "resolvedLicense": {
                "uuid": "license-uuid",
                "licenseId": "MIT",
                "name": "MIT License"
            },
            "isInternal": false
        }"#;

        let component: DtComponentFull = serde_json::from_str(json).unwrap();
        assert_eq!(component.uuid, "comp-uuid-123");
        assert_eq!(component.name, "express");
        assert_eq!(component.version, Some("4.18.2".to_string()));
        assert_eq!(component.group, Some("npm".to_string()));
        assert_eq!(component.purl, Some("pkg:npm/express@4.18.2".to_string()));
        assert_eq!(component.cpe, None);
        assert!(component.resolved_license.is_some());
        let license = component.resolved_license.unwrap();
        assert_eq!(license.license_id, Some("MIT".to_string()));
        assert_eq!(license.name, "MIT License");
        assert_eq!(component.is_internal, Some(false));
    }

    // -----------------------------------------------------------------------
    // DtProject serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_project_deserialize_full() {
        let json = r#"{
            "uuid": "proj-uuid-1",
            "name": "my-project",
            "version": "1.0.0",
            "description": "Test project",
            "lastBomImport": 1700000000000,
            "lastBomImportFormat": "CycloneDX 1.4"
        }"#;
        let project: DtProject = serde_json::from_str(json).unwrap();
        assert_eq!(project.uuid, "proj-uuid-1");
        assert_eq!(project.name, "my-project");
        assert_eq!(project.version, Some("1.0.0".to_string()));
        assert_eq!(project.description, Some("Test project".to_string()));
        assert_eq!(project.last_bom_import, Some(1700000000000));
        assert_eq!(
            project.last_bom_import_format,
            Some("CycloneDX 1.4".to_string())
        );
    }

    #[test]
    fn test_dt_project_deserialize_minimal() {
        let json = r#"{
            "uuid": "proj-uuid-2",
            "name": "minimal-project",
            "version": null,
            "description": null,
            "lastBomImport": null,
            "lastBomImportFormat": null
        }"#;
        let project: DtProject = serde_json::from_str(json).unwrap();
        assert_eq!(project.uuid, "proj-uuid-2");
        assert_eq!(project.name, "minimal-project");
        assert!(project.version.is_none());
        assert!(project.description.is_none());
        assert!(project.last_bom_import.is_none());
    }

    #[test]
    fn test_dt_project_serialize_roundtrip() {
        let project = DtProject {
            uuid: "uuid-1".to_string(),
            name: "test".to_string(),
            version: Some("2.0".to_string()),
            description: None,
            last_bom_import: Some(12345),
            last_bom_import_format: None,
        };
        let json = serde_json::to_string(&project).unwrap();
        let deserialized: DtProject = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.uuid, project.uuid);
        assert_eq!(deserialized.name, project.name);
        assert_eq!(deserialized.version, project.version);
    }

    // -----------------------------------------------------------------------
    // BomUploadResponse
    // -----------------------------------------------------------------------

    #[test]
    fn test_bom_upload_response_deserialize() {
        let json = r#"{"token": "bom-token-abc123"}"#;
        let response: BomUploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.token, "bom-token-abc123");
    }

    // -----------------------------------------------------------------------
    // BomProcessingStatus
    // -----------------------------------------------------------------------

    #[test]
    fn test_bom_processing_status_deserialize_true() {
        let json = r#"{"processing": true}"#;
        let status: BomProcessingStatus = serde_json::from_str(json).unwrap();
        assert!(status.processing);
    }

    #[test]
    fn test_bom_processing_status_deserialize_false() {
        let json = r#"{"processing": false}"#;
        let status: BomProcessingStatus = serde_json::from_str(json).unwrap();
        assert!(!status.processing);
    }

    // -----------------------------------------------------------------------
    // DtFinding - additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_finding_with_analysis_and_attribution() {
        let json = r#"{
            "component": {
                "uuid": "comp-1",
                "name": "my-lib",
                "version": "1.0.0",
                "group": null,
                "purl": null
            },
            "vulnerability": {
                "uuid": "vuln-1",
                "vulnId": "CVE-2024-0001",
                "source": "NVD",
                "severity": "CRITICAL",
                "title": "Critical RCE",
                "description": "Remote code execution",
                "cvssV3BaseScore": 9.8,
                "cwe": {
                    "cweId": 94,
                    "name": "Code Injection"
                }
            },
            "analysis": {
                "state": "NOT_AFFECTED",
                "justification": "Code not reachable",
                "response": "will_not_fix",
                "details": "Confirmed not reachable in our usage",
                "isSuppressed": true
            },
            "attribution": {
                "analyzerIdentity": "INTERNAL_ANALYZER",
                "attributedOn": 1700000000000
            }
        }"#;

        let finding: DtFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.vulnerability.severity, "CRITICAL");
        assert_eq!(
            finding.vulnerability.cvss_v3_base_score,
            Some(9.8)
        );
        let analysis = finding.analysis.unwrap();
        assert_eq!(analysis.state, Some("NOT_AFFECTED".to_string()));
        assert!(analysis.is_suppressed);
        let attribution = finding.attribution.unwrap();
        assert_eq!(
            attribution.analyzer_identity,
            Some("INTERNAL_ANALYZER".to_string())
        );
    }

    #[test]
    fn test_dt_finding_serialize_roundtrip() {
        let finding = DtFinding {
            component: DtComponent {
                uuid: "c1".to_string(),
                name: "pkg".to_string(),
                version: Some("1.0".to_string()),
                group: None,
                purl: Some("pkg:npm/pkg@1.0".to_string()),
            },
            vulnerability: DtVulnerability {
                uuid: "v1".to_string(),
                vuln_id: "CVE-2024-0002".to_string(),
                source: "NVD".to_string(),
                severity: "HIGH".to_string(),
                title: Some("Test".to_string()),
                description: None,
                cvss_v3_base_score: Some(7.5),
                cwe: None,
            },
            analysis: None,
            attribution: None,
        };

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: DtFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.vulnerability.vuln_id, "CVE-2024-0002");
        assert_eq!(deserialized.component.name, "pkg");
    }

    // -----------------------------------------------------------------------
    // DtProjectMetrics - defaults and partial data
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_project_metrics_defaults() {
        // Minimal JSON with defaults
        let json = r#"{}"#;
        let metrics: DtProjectMetrics = serde_json::from_str(json).unwrap();
        assert_eq!(metrics.critical, 0);
        assert_eq!(metrics.high, 0);
        assert_eq!(metrics.medium, 0);
        assert_eq!(metrics.low, 0);
        assert_eq!(metrics.unassigned, 0);
        assert_eq!(metrics.vulnerabilities, None);
        assert_eq!(metrics.findings_total, 0);
        assert_eq!(metrics.findings_audited, 0);
        assert_eq!(metrics.findings_unaudited, 0);
        assert_eq!(metrics.suppressions, 0);
        assert!((metrics.inherited_risk_score - 0.0).abs() < f64::EPSILON);
        assert_eq!(metrics.policy_violations_fail, 0);
        assert_eq!(metrics.policy_violations_warn, 0);
        assert_eq!(metrics.policy_violations_info, 0);
        assert_eq!(metrics.policy_violations_total, 0);
        assert!(metrics.first_occurrence.is_none());
        assert!(metrics.last_occurrence.is_none());
    }

    #[test]
    fn test_dt_project_metrics_serialize_roundtrip() {
        let metrics = DtProjectMetrics {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            unassigned: 5,
            vulnerabilities: Some(15),
            findings_total: 15,
            findings_audited: 10,
            findings_unaudited: 5,
            suppressions: 2,
            inherited_risk_score: 25.5,
            policy_violations_fail: 1,
            policy_violations_warn: 0,
            policy_violations_info: 3,
            policy_violations_total: 4,
            first_occurrence: Some(1000),
            last_occurrence: Some(2000),
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: DtProjectMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.critical, 1);
        assert_eq!(deserialized.high, 2);
        assert_eq!(deserialized.vulnerabilities, Some(15));
        assert!((deserialized.inherited_risk_score - 25.5).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // DtPortfolioMetrics
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_portfolio_metrics_deserialize() {
        let json = r#"{
            "critical": 10,
            "high": 20,
            "medium": 30,
            "low": 40,
            "unassigned": 5,
            "vulnerabilities": 105,
            "findingsTotal": 105,
            "findingsAudited": 50,
            "findingsUnaudited": 55,
            "suppressions": 10,
            "inheritedRiskScore": 123.45,
            "policyViolationsFail": 5,
            "policyViolationsWarn": 8,
            "policyViolationsInfo": 12,
            "policyViolationsTotal": 25,
            "projects": 42
        }"#;

        let metrics: DtPortfolioMetrics = serde_json::from_str(json).unwrap();
        assert_eq!(metrics.critical, 10);
        assert_eq!(metrics.high, 20);
        assert_eq!(metrics.medium, 30);
        assert_eq!(metrics.low, 40);
        assert_eq!(metrics.projects, 42);
        assert_eq!(metrics.policy_violations_total, 25);
        assert!((metrics.inherited_risk_score - 123.45).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dt_portfolio_metrics_defaults() {
        let json = r#"{}"#;
        let metrics: DtPortfolioMetrics = serde_json::from_str(json).unwrap();
        assert_eq!(metrics.critical, 0);
        assert_eq!(metrics.projects, 0);
        assert_eq!(metrics.findings_total, 0);
    }

    #[test]
    fn test_dt_portfolio_metrics_serialize_roundtrip() {
        let metrics = DtPortfolioMetrics {
            critical: 3,
            high: 5,
            medium: 10,
            low: 2,
            unassigned: 0,
            vulnerabilities: Some(20),
            findings_total: 20,
            findings_audited: 15,
            findings_unaudited: 5,
            suppressions: 1,
            inherited_risk_score: 55.0,
            policy_violations_fail: 2,
            policy_violations_warn: 1,
            policy_violations_info: 0,
            policy_violations_total: 3,
            projects: 10,
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: DtPortfolioMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.critical, 3);
        assert_eq!(deserialized.projects, 10);
    }

    // -----------------------------------------------------------------------
    // DtPolicyFull
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_policy_full_deserialize() {
        let json = r#"{
            "uuid": "policy-uuid-1",
            "name": "License Policy",
            "violationState": "FAIL",
            "includeChildren": true,
            "policyConditions": [
                {
                    "uuid": "cond-uuid-1",
                    "subject": "LICENSE",
                    "operator": "IS",
                    "value": "GPL-3.0"
                }
            ],
            "projects": [
                {
                    "uuid": "proj-uuid-1",
                    "name": "my-project",
                    "version": "1.0",
                    "description": null,
                    "lastBomImport": null,
                    "lastBomImportFormat": null
                }
            ],
            "tags": [{"name": "security"}]
        }"#;

        let policy: DtPolicyFull = serde_json::from_str(json).unwrap();
        assert_eq!(policy.uuid, "policy-uuid-1");
        assert_eq!(policy.name, "License Policy");
        assert_eq!(policy.violation_state, "FAIL");
        assert_eq!(policy.include_children, Some(true));
        assert_eq!(policy.policy_conditions.len(), 1);
        assert_eq!(policy.policy_conditions[0].subject, "LICENSE");
        assert_eq!(policy.projects.len(), 1);
        assert_eq!(policy.projects[0].name, "my-project");
        assert_eq!(policy.tags.len(), 1);
    }

    #[test]
    fn test_dt_policy_full_empty_conditions_and_projects() {
        let json = r#"{
            "uuid": "policy-uuid-2",
            "name": "Empty Policy",
            "violationState": "WARN",
            "includeChildren": null,
            "policyConditions": [],
            "projects": [],
            "tags": []
        }"#;

        let policy: DtPolicyFull = serde_json::from_str(json).unwrap();
        assert!(policy.policy_conditions.is_empty());
        assert!(policy.projects.is_empty());
        assert!(policy.tags.is_empty());
        assert!(policy.include_children.is_none());
    }

    // -----------------------------------------------------------------------
    // DtAnalysis
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_analysis_deserialize() {
        let json = r#"{
            "state": "NOT_AFFECTED",
            "justification": "Code not reachable",
            "response": "will_not_fix",
            "details": "Detailed explanation here",
            "isSuppressed": false
        }"#;
        let analysis: DtAnalysis = serde_json::from_str(json).unwrap();
        assert_eq!(analysis.state, Some("NOT_AFFECTED".to_string()));
        assert_eq!(analysis.justification, Some("Code not reachable".to_string()));
        assert!(!analysis.is_suppressed);
    }

    #[test]
    fn test_dt_analysis_minimal() {
        let json = r#"{"isSuppressed": true}"#;
        let analysis: DtAnalysis = serde_json::from_str(json).unwrap();
        assert!(analysis.state.is_none());
        assert!(analysis.justification.is_none());
        assert!(analysis.response.is_none());
        assert!(analysis.details.is_none());
        assert!(analysis.is_suppressed);
    }

    // -----------------------------------------------------------------------
    // DtAnalysisResponse
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_analysis_response_deserialize() {
        let json = r#"{
            "analysisState": "EXPLOITABLE",
            "analysisJustification": null,
            "analysisDetails": "We are affected",
            "isSuppressed": false
        }"#;
        let response: DtAnalysisResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.analysis_state, "EXPLOITABLE");
        assert!(response.analysis_justification.is_none());
        assert_eq!(response.analysis_details, Some("We are affected".to_string()));
        assert!(!response.is_suppressed);
    }

    #[test]
    fn test_dt_analysis_response_serialize_roundtrip() {
        let response = DtAnalysisResponse {
            analysis_state: "IN_TRIAGE".to_string(),
            analysis_justification: Some("Under review".to_string()),
            analysis_details: None,
            is_suppressed: false,
        };
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: DtAnalysisResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.analysis_state, "IN_TRIAGE");
    }

    // -----------------------------------------------------------------------
    // UpdateAnalysisRequest serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_analysis_request_serialize() {
        let request = UpdateAnalysisRequest {
            project: "proj-uuid".to_string(),
            component: "comp-uuid".to_string(),
            vulnerability: "vuln-uuid".to_string(),
            analysis_state: "NOT_AFFECTED".to_string(),
            analysis_justification: Some("Protected by WAF".to_string()),
            analysis_details: None,
            is_suppressed: true,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["project"], "proj-uuid");
        assert_eq!(json["component"], "comp-uuid");
        assert_eq!(json["vulnerability"], "vuln-uuid");
        assert_eq!(json["analysisState"], "NOT_AFFECTED");
        assert_eq!(json["analysisJustification"], "Protected by WAF");
        // analysisDetails should be skipped (skip_serializing_if = None)
        assert!(json.get("analysisDetails").is_none());
        assert_eq!(json["isSuppressed"], true);
    }

    #[test]
    fn test_update_analysis_request_serialize_all_fields() {
        let request = UpdateAnalysisRequest {
            project: "p".to_string(),
            component: "c".to_string(),
            vulnerability: "v".to_string(),
            analysis_state: "EXPLOITABLE".to_string(),
            analysis_justification: Some("justification".to_string()),
            analysis_details: Some("details here".to_string()),
            is_suppressed: false,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["analysisDetails"], "details here");
        assert_eq!(json["isSuppressed"], false);
    }

    #[test]
    fn test_update_analysis_request_serialize_no_optional_fields() {
        let request = UpdateAnalysisRequest {
            project: "p".to_string(),
            component: "c".to_string(),
            vulnerability: "v".to_string(),
            analysis_state: "IN_TRIAGE".to_string(),
            analysis_justification: None,
            analysis_details: None,
            is_suppressed: false,
        };
        let json = serde_json::to_value(&request).unwrap();
        // Both optional fields should be absent
        assert!(json.get("analysisJustification").is_none());
        assert!(json.get("analysisDetails").is_none());
    }

    // -----------------------------------------------------------------------
    // CreateProjectRequest serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_project_request_serialize() {
        let request = CreateProjectRequest {
            name: "my-project".to_string(),
            version: Some("1.0.0".to_string()),
            description: Some("Test project".to_string()),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "my-project");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["description"], "Test project");
    }

    #[test]
    fn test_create_project_request_serialize_minimal() {
        let request = CreateProjectRequest {
            name: "minimal".to_string(),
            version: None,
            description: None,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["name"], "minimal");
        assert!(json["version"].is_null());
    }

    // -----------------------------------------------------------------------
    // DtComponent serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_component_serialize_roundtrip() {
        let component = DtComponent {
            uuid: "c1".to_string(),
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            group: Some("npm".to_string()),
            purl: Some("pkg:npm/lodash@4.17.21".to_string()),
        };
        let json = serde_json::to_string(&component).unwrap();
        let deserialized: DtComponent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "lodash");
        assert_eq!(deserialized.purl, Some("pkg:npm/lodash@4.17.21".to_string()));
    }

    #[test]
    fn test_dt_component_minimal() {
        let json = r#"{"uuid": "c2", "name": "minimal"}"#;
        let component: DtComponent = serde_json::from_str(json).unwrap();
        assert_eq!(component.uuid, "c2");
        assert_eq!(component.name, "minimal");
        assert!(component.version.is_none());
        assert!(component.group.is_none());
        assert!(component.purl.is_none());
    }

    // -----------------------------------------------------------------------
    // DtComponentFull - additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_component_full_no_license() {
        let json = r#"{
            "uuid": "comp-no-license",
            "name": "unlicensed-lib",
            "version": null,
            "group": null,
            "purl": null,
            "cpe": "cpe:/a:vendor:product:1.0",
            "resolvedLicense": null,
            "isInternal": true
        }"#;
        let component: DtComponentFull = serde_json::from_str(json).unwrap();
        assert!(component.resolved_license.is_none());
        assert_eq!(component.is_internal, Some(true));
        assert_eq!(
            component.cpe,
            Some("cpe:/a:vendor:product:1.0".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // DtLicense
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_license_serialize_roundtrip() {
        let license = DtLicense {
            uuid: Some("lic-uuid".to_string()),
            license_id: Some("Apache-2.0".to_string()),
            name: "Apache License 2.0".to_string(),
        };
        let json = serde_json::to_string(&license).unwrap();
        let deserialized: DtLicense = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.license_id, Some("Apache-2.0".to_string()));
        assert_eq!(deserialized.name, "Apache License 2.0");
    }

    // -----------------------------------------------------------------------
    // DtCwe
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_cwe_serialize_roundtrip() {
        let cwe = DtCwe {
            cwe_id: 79,
            name: "Cross-site Scripting".to_string(),
        };
        let json = serde_json::to_string(&cwe).unwrap();
        let deserialized: DtCwe = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cwe_id, 79);
        assert_eq!(deserialized.name, "Cross-site Scripting");
    }

    // -----------------------------------------------------------------------
    // DtAttribution
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_attribution_serialize_roundtrip() {
        let attribution = DtAttribution {
            analyzer_identity: Some("TRIVY".to_string()),
            attributed_on: Some(1700000000000),
        };
        let json = serde_json::to_string(&attribution).unwrap();
        let deserialized: DtAttribution = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.analyzer_identity,
            Some("TRIVY".to_string())
        );
        assert_eq!(deserialized.attributed_on, Some(1700000000000));
    }

    #[test]
    fn test_dt_attribution_minimal() {
        let json = r#"{}"#;
        let attribution: DtAttribution = serde_json::from_str(json).unwrap();
        assert!(attribution.analyzer_identity.is_none());
        assert!(attribution.attributed_on.is_none());
    }

    // -----------------------------------------------------------------------
    // DtPolicyViolation - additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_policy_violation_serialize_roundtrip() {
        let violation = DtPolicyViolation {
            uuid: "viol-1".to_string(),
            violation_type: "SECURITY".to_string(),
            component: DtComponent {
                uuid: "comp-1".to_string(),
                name: "vulnerable-lib".to_string(),
                version: Some("0.9".to_string()),
                group: None,
                purl: None,
            },
            policy_condition: DtPolicyCondition {
                uuid: "cond-1".to_string(),
                subject: "SEVERITY".to_string(),
                operator: "IS".to_string(),
                value: "CRITICAL".to_string(),
                policy: DtPolicy {
                    uuid: "pol-1".to_string(),
                    name: "Block Critical".to_string(),
                    violation_state: "FAIL".to_string(),
                },
            },
        };

        let json = serde_json::to_string(&violation).unwrap();
        let deserialized: DtPolicyViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.violation_type, "SECURITY");
        assert_eq!(deserialized.component.name, "vulnerable-lib");
        assert_eq!(deserialized.policy_condition.policy.name, "Block Critical");
    }

    // -----------------------------------------------------------------------
    // DtVulnerability
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_vulnerability_serialize_roundtrip() {
        let vuln = DtVulnerability {
            uuid: "v1".to_string(),
            vuln_id: "CVE-2024-12345".to_string(),
            source: "NVD".to_string(),
            severity: "CRITICAL".to_string(),
            title: Some("Buffer overflow".to_string()),
            description: Some("A buffer overflow in...".to_string()),
            cvss_v3_base_score: Some(9.8),
            cwe: Some(DtCwe {
                cwe_id: 120,
                name: "Buffer Overflow".to_string(),
            }),
        };

        let json = serde_json::to_string(&vuln).unwrap();
        let deserialized: DtVulnerability = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.vuln_id, "CVE-2024-12345");
        assert_eq!(deserialized.cvss_v3_base_score, Some(9.8));
        assert!(deserialized.cwe.is_some());
    }

    #[test]
    fn test_dt_vulnerability_minimal() {
        let json = r#"{
            "uuid": "v2",
            "vulnId": "OSV-2024-001",
            "source": "OSV",
            "severity": "LOW"
        }"#;
        let vuln: DtVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.vuln_id, "OSV-2024-001");
        assert!(vuln.title.is_none());
        assert!(vuln.description.is_none());
        assert!(vuln.cvss_v3_base_score.is_none());
        assert!(vuln.cwe.is_none());
    }

    // -----------------------------------------------------------------------
    // DependencyTrackConfig construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_track_config_construction() {
        let config = DependencyTrackConfig {
            base_url: "http://localhost:8092".to_string(),
            api_key: "test-api-key".to_string(),
            enabled: true,
        };
        assert_eq!(config.base_url, "http://localhost:8092");
        assert_eq!(config.api_key, "test-api-key");
        assert!(config.enabled);
    }

    #[test]
    fn test_dependency_track_config_clone() {
        let config = DependencyTrackConfig {
            base_url: "http://dt.example.com".to_string(),
            api_key: "key-123".to_string(),
            enabled: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.base_url, "http://dt.example.com");
        assert_eq!(cloned.api_key, "key-123");
        assert!(!cloned.enabled);
    }

    #[test]
    fn test_dependency_track_config_debug() {
        let config = DependencyTrackConfig {
            base_url: "http://localhost:8092".to_string(),
            api_key: "key".to_string(),
            enabled: true,
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("DependencyTrackConfig"));
        assert!(debug_str.contains("localhost"));
    }

    // -----------------------------------------------------------------------
    // DtPolicyCondition and DtPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_policy_condition_serialize_roundtrip() {
        let condition = DtPolicyCondition {
            uuid: "cond-1".to_string(),
            subject: "LICENSE_GROUP".to_string(),
            operator: "IS_NOT".to_string(),
            value: "Permissive".to_string(),
            policy: DtPolicy {
                uuid: "pol-1".to_string(),
                name: "No Copyleft".to_string(),
                violation_state: "WARN".to_string(),
            },
        };
        let json = serde_json::to_string(&condition).unwrap();
        let deserialized: DtPolicyCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.subject, "LICENSE_GROUP");
        assert_eq!(deserialized.policy.name, "No Copyleft");
    }

    // -----------------------------------------------------------------------
    // DtPolicyConditionFull
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_policy_condition_full_serialize_roundtrip() {
        let condition = DtPolicyConditionFull {
            uuid: "cond-full-1".to_string(),
            subject: "COORDINATES".to_string(),
            operator: "MATCHES".to_string(),
            value: "org.apache.*".to_string(),
        };
        let json = serde_json::to_string(&condition).unwrap();
        let deserialized: DtPolicyConditionFull = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.uuid, "cond-full-1");
        assert_eq!(deserialized.value, "org.apache.*");
    }
}
