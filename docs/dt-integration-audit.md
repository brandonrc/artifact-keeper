# Dependency-Track Integration Audit

Audit of OWASP Dependency-Track (DT) v4.11.4 REST API mapped against
artifact-keeper custom SBOM, CVE, license, and policy code.

Generated: 2026-02-06

---

## Table of Contents

- [A. DT Endpoints That Replace Our Code](#a-dt-endpoints-that-replace-our-code)
- [B. Our Code With No DT Equivalent](#b-our-code-with-no-dt-equivalent)
- [C. Data Transformation Needed](#c-data-transformation-needed)
- [D. Recommendation](#d-recommendation)

---

## A. DT Endpoints That Replace Our Code

### A1. Vulnerability Findings (replaces CVE history + scan findings)

| Our code | DT replacement |
|----------|---------------|
| `sbom_service.rs::record_cve()` | Automatic -- DT populates findings on BOM ingest via `PUT /api/v1/bom` |
| `sbom_service.rs::get_cve_history(artifact_id)` | `GET /api/v1/finding/project/{uuid}` returns `[Finding]` with component, vulnerability, analysis, and attribution |
| `sbom_service.rs::get_cve_trends(repo_id)` | `GET /api/v1/metrics/project/{uuid}/current` returns `ProjectMetrics` (critical/high/medium/low counts, findingsTotal, findingsAudited, policyViolations*). Historical: `GET /api/v1/metrics/project/{uuid}/days/{days}` |
| `sbom_service.rs::update_cve_status()` (open/fixed/acknowledged/false_positive) | `PUT /api/v1/analysis` with body `{project, component, vulnerability, analysisState, analysisJustification, isSuppressed}`. DT states: NOT_SET, EXPLOITABLE, IN_TRIAGE, FALSE_POSITIVE, NOT_AFFECTED, RESOLVED |
| `scan_result_service.rs::create_findings()` | Not needed -- DT creates findings automatically when analyzing components after BOM upload |
| `scan_result_service.rs::list_findings()` | `GET /api/v1/finding/project/{uuid}?suppressed=false&source=NVD` with pagination headers |
| `scan_result_service.rs::acknowledge_finding()` | `PUT /api/v1/analysis` with `isSuppressed: true` and `analysisState` |
| `scan_result_service.rs::get_dashboard_summary()` | `GET /api/v1/metrics/portfolio/current` returns `PortfolioMetrics` with all severity counts, project counts, policy violation breakdowns |
| `scan_result_service.rs::recalculate_score()` | `GET /api/v1/metrics/project/{uuid}/refresh` triggers recalculation; DT maintains `inheritedRiskScore` per project |
| gRPC `CveHistoryService::get_cve_history` | Same as above -- `GET /api/v1/finding/project/{uuid}` |
| gRPC `CveHistoryService::get_cve_trends` | Same as above -- `GET /api/v1/metrics/project/{uuid}/current` + `/days/{days}` |
| gRPC `CveHistoryService::update_cve_status` | Same as above -- `PUT /api/v1/analysis` |

**Files affected:**
- `backend/src/services/sbom_service.rs` -- lines 224-404 (CVE history section)
- `backend/src/services/scan_result_service.rs` -- lines 292-596 (findings + scores)
- `backend/src/grpc/sbom_server.rs` -- lines 261-371 (CveHistoryGrpcServer)
- `backend/src/api/handlers/sbom.rs` -- lines 424-461 (CVE handlers)

**DB tables replaceable:**
- `cve_history` -- DT manages finding/analysis lifecycle internally
- `repo_security_scores` -- replaced by DT ProjectMetrics / PortfolioMetrics

### A2. License Policy Enforcement (replaces license_policies + check_compliance)

| Our code | DT replacement |
|----------|---------------|
| `sbom_service.rs::get_license_policy()` | `GET /api/v1/policy` + `GET /api/v1/policy/{uuid}` -- DT policies support LICENSE subject with IS/IS_NOT operators |
| `sbom_service.rs::check_license_compliance()` | Automatic -- DT evaluates policies on BOM ingest. Results via `GET /api/v1/violation/project/{uuid}` filtered by `type=LICENSE` |
| `sbom_service.rs::upsert_license_policy()` | `PUT /api/v1/policy` to create + `PUT /api/v1/policy/{uuid}/condition` with `{subject: "LICENSE", operator: "IS", value: "GPL-3.0"}`. DT also supports license groups: `PUT /api/v1/licenseGroup` to create a group, then reference the group in a policy condition with `subject: "LICENSE_GROUP"` |
| REST `POST /sbom/license-policies` | Replaced by DT policy CRUD (`PUT/POST/DELETE /api/v1/policy`) |
| REST `POST /sbom/check-compliance` | Replaced by `GET /api/v1/violation/project/{uuid}` -- returns violations already evaluated |
| gRPC `SecurityPolicyService::*` | All four RPCs (get/upsert/delete/list license policies) replaced by DT policy API |

**Files affected:**
- `backend/src/services/sbom_service.rs` -- lines 406-490 (license policy section)
- `backend/src/grpc/sbom_server.rs` -- lines 373-501 (SecurityPolicyGrpcServer)
- `backend/src/api/handlers/sbom.rs` -- lines 463-561 (license policy + compliance handlers)

**DB tables replaceable:**
- `license_policies` -- DT manages policies, conditions, and license groups natively

**DT advantages over our implementation:**
- License groups with risk weighting (e.g., "Copyleft" group = high risk)
- Policy conditions support operators: IS, IS_NOT, MATCHES, NO_MATCH, CONTAINS_ALL, CONTAINS_ANY
- Policy violation states: FAIL, WARN, INFO (maps to our block/warn/allow)
- Violations automatically re-evaluated when components change
- SPDX license ID normalization built in

### A3. SBOM Upload & BOM Processing (replaces part of generate_sbom flow)

| Our code | DT replacement |
|----------|---------------|
| `dependency_track_service.rs::upload_sbom()` | `PUT /api/v1/bom` (already implemented -- this IS the DT client) |
| `dependency_track_service.rs::is_bom_processing()` | `GET /api/v1/bom/token/{uuid}` (already implemented) |
| `dependency_track_service.rs::get_or_create_project()` | `PUT /api/v1/bom` with `autoCreate=true` + `projectName` + `projectVersion` -- eliminates the two-step lookup-then-create |

**Note:** Our `dependency_track_service.rs` is already a well-structured DT client. It covers 7 of the DT endpoints. The migration is about removing the *parallel* implementations in `sbom_service.rs` that duplicate what DT does.

### A4. Component Inventory (replaces sbom_components table queries)

| Our code | DT replacement |
|----------|---------------|
| `sbom_service.rs::get_sbom_components(sbom_id)` | `GET /api/v1/component/project/{uuid}` -- richer data including resolved license, repository metadata, metrics, dependency graph |
| REST `GET /sbom/:id/components` | `GET /api/v1/component/project/{uuid}?onlyDirect=true` with pagination |
| gRPC `SbomService::get_sbom_components` | Same DT endpoint |

**DT advantages:**
- Component identity resolution (purl, cpe, swidTagId)
- Internal component identification
- Repository metadata (latest version available)
- Per-component vulnerability metrics
- Dependency graph traversal via `GET /api/v1/component/project/{projectUuid}/dependencyGraph/{componentUuids}`

### A5. Policy-Gated Downloads (replaces policy_service.rs)

| Our code | DT replacement |
|----------|---------------|
| `policy_service.rs::evaluate_artifact()` | Query DT: `GET /api/v1/violation/project/{uuid}` + check `violationState` (FAIL/WARN/INFO). If any FAIL violations exist, block the download |
| `policy_service.rs::create_policy()` | `PUT /api/v1/policy` with conditions for SEVERITY, LICENSE, etc. |
| `policy_service.rs::list_policies()` | `GET /api/v1/policy` |
| `policy_service.rs` scan_policies CRUD | DT policy CRUD covers this plus adds tag-based and project-scoped policy assignment |

**Files affected:**
- `backend/src/services/policy_service.rs` -- entire file (240 lines)

**DB tables replaceable:**
- `scan_policies` -- DT policies are more expressive (support conditions on SEVERITY, LICENSE, LICENSE_GROUP, PACKAGE_URL, CPE, SWID_TAGID, COMPONENT_HASH, VERSION_DISTANCE, AGE, COORDINATES, CWE, VULNERABILITY_ID)

---

## B. Our Code With No DT Equivalent (Keep)

### B1. SBOM Generation (CycloneDX + SPDX document creation)

| Our code | Why we keep it |
|----------|---------------|
| `sbom_service.rs::generate_sbom()` | DT consumes SBOMs but does not generate them. We produce CycloneDX 1.5 and SPDX 2.3 from scan results and artifact metadata. This is the entry point before uploading to DT. |
| `sbom_service.rs::generate_cyclonedx()` | CycloneDX document builder -- DT only exports existing BOMs, does not create new ones from raw dependency lists |
| `sbom_service.rs::generate_spdx()` | SPDX document builder -- DT has no SPDX generation |
| `sbom_service.rs::convert_sbom()` | Format conversion between CycloneDX and SPDX -- DT only exports CycloneDX |

**Note:** DT can export a project's BOM as CycloneDX via `GET /api/v1/bom/cyclonedx/project/{uuid}`, but this is a re-export of what was uploaded, not generation from scratch. Our generation from scan results remains necessary.

### B2. Vulnerability Scanning (Trivy, Grype, OpenSCAP, OSV.dev, GitHub Advisory)

| Our code | Why we keep it |
|----------|---------------|
| `scanner_service.rs` (entire file, ~1240 lines) | DT is a vulnerability *database* and *policy engine*, not a scanner. It relies on external tools (or its internal NVD/OSV mirrors) to match components to known CVEs. Our scanning pipeline (Trivy image scanner, Trivy FS scanner, Grype CLI, OpenSCAP, OSV.dev batch API, GitHub Advisory API) produces the raw findings that feed into both our DB and DT. |
| `trivy_fs_scanner.rs` | Filesystem vulnerability scanning for non-container artifacts |
| `grype_scanner.rs` | CLI-based Grype scanning |
| `image_scanner.rs` | Container image scanning via Trivy |
| `openscap_scanner.rs` | Compliance scanning (CIS benchmarks, STIG profiles) -- DT has no compliance equivalent |

**Key distinction:** Our scanners analyze artifact *content* (extract manifests, call Trivy/Grype). DT analyzes *components listed in a BOM*. The two are complementary: we scan -> generate SBOM -> upload to DT -> DT enriches with NVD/OSV data and enforces policies.

### B3. Scan Result Persistence & Deduplication

| Our code | Why we keep it |
|----------|---------------|
| `scan_result_service.rs::create_scan_result_with_checksum()` | Checksum-based scan dedup (skip re-scanning identical artifacts within 30-day TTL). DT has no equivalent -- it processes every BOM upload. |
| `scan_result_service.rs::copy_scan_results()` | Cross-artifact result reuse by content hash. DT has no content-addressable dedup. |
| `scan_result_service.rs::complete_scan() / fail_scan()` | Scanner lifecycle management (running/completed/failed states). DT only tracks BOM processing tokens. |

### B4. Authentication & Authorization

| Our code | Why we keep it |
|----------|---------------|
| Our JWT/OIDC/LDAP/SAML auth stack | DT has its own auth (API keys, OIDC, LDAP) but it serves a different user population. Our auth gates artifact access; DT auth gates security analysis. |
| Per-repository scan policies with user-scoped acknowledgments | DT policies are team-scoped, not user-scoped. Our `acknowledged_by` tracks which user accepted a risk. |

### B5. Repository & Artifact Management

| Our code | Why we keep it |
|----------|---------------|
| Repository CRUD, artifact upload/download/proxy, storage backends | DT is not an artifact registry. It has no concept of file storage, package proxying, or repository types (npm, PyPI, Maven, etc.) |

### B6. SBOM Document Storage & Metadata

| Our code | Why we keep it |
|----------|---------------|
| `sbom_documents` table (content, content_hash, format_version) | We store the actual SBOM JSON content for download/export. DT stores component data but the original document is only retrievable as a CycloneDX re-export, not the original uploaded content. |

### B7. Promotion Workflow Integration

| Our code | Why we keep it |
|----------|---------------|
| `promotion_policy_service.rs` | Staging/production promotion gates that check scan results, license compliance, and approval chains. DT violations can inform these gates but DT has no promotion workflow concept. |

### B8. gRPC `trigger_retroactive_scan` RPC

| Our code | Why we keep it |
|----------|---------------|
| `CveHistoryGrpcServer::trigger_retroactive_scan` | Queues bulk re-scan jobs across all artifacts. DT's equivalent is `POST /api/v1/finding/project/{uuid}/analyze` but only for a single project, and it only re-analyzes existing components (does not re-scan artifact content). |

---

## C. Data Transformation Needed

### C1. Project Identity Mapping

```
Our model:                          DT model:
  repository_id (UUID)      <-->      project.uuid (UUID)
  artifact_id (UUID)        <-->      (no direct equivalent)
  repository.name           <-->      project.name
  artifact.version          <-->      project.version
```

**Strategy:** Create a mapping table or use DT project tags/properties to store our `repository_id` and `artifact_id`. One DT project per (repository, version) pair.

### C2. Finding / CVE History Mapping

```
Our CveHistoryEntry:                DT Finding:
  cve_id                    <-->      vulnerability.vulnId
  severity                  <-->      vulnerability.severity (CRITICAL/HIGH/MEDIUM/LOW/INFO/UNASSIGNED)
  affected_component        <-->      component.name + component.group
  affected_version          <-->      component.version
  fixed_version             <-->      vulnerability.patchedVersions
  cvss_score                <-->      vulnerability.cvssV3BaseScore
  status (open/fixed/       <-->      analysis.analysisState (NOT_SET/EXPLOITABLE/
   acknowledged/false_pos)             IN_TRIAGE/FALSE_POSITIVE/NOT_AFFECTED/RESOLVED)
  first_detected_at         <-->      attribution.attributedOn
  acknowledged_by (user_id) <-->      (not available -- DT tracks by team, not individual user)
  acknowledged_reason       <-->      analysis.analysisDetails + analysisJustification
```

**Gaps:**
- DT does not track `first_detected_at` vs `last_detected_at` per finding -- it has `attribution.attributedOn` (when the vuln was first attributed to the component) but no "last seen" concept.
- DT does not record which individual user made an analysis decision (only audit log).
- Our `CveStatus::Fixed` maps to DT `RESOLVED`, but DT does not auto-transition to RESOLVED when a component is updated.

### C3. License Policy Mapping

```
Our LicensePolicy:                  DT Policy + PolicyCondition:
  name                      <-->      policy.name
  allowed_licenses          <-->      PolicyCondition(subject=LICENSE, operator=IS, value=MIT)
                                       + Policy.violationState=INFO (allow)
  denied_licenses           <-->      PolicyCondition(subject=LICENSE, operator=IS, value=GPL-3.0)
                                       + Policy.violationState=FAIL (deny)
  allow_unknown             <-->      No direct equivalent. Could use
                                       PolicyCondition(subject=LICENSE, operator=IS_NOT, value=*)
  action (allow/warn/block) <-->      policy.violationState (INFO/WARN/FAIL)
  repository_id scope       <-->      policy-to-project assignment
                                       POST /api/v1/policy/{policyUuid}/project/{projectUuid}
```

**Gaps:**
- Our allowlist model (deny everything not in the list) requires multiple policy conditions in DT or use of license groups.
- Our `allow_unknown` toggle has no DT equivalent. Must be modeled as a separate policy.

### C4. Scan Policy Mapping

```
Our ScanPolicy:                     DT Policy + PolicyCondition:
  max_severity              <-->      PolicyCondition(subject=SEVERITY, operator=IS, value=CRITICAL)
                                       + violationState=FAIL
  block_unscanned           <-->      No equivalent (DT only evaluates known components)
  block_on_fail             <-->      No equivalent (DT has no concept of scan failure)
```

**Gaps:**
- `block_unscanned` and `block_on_fail` are artifact-registry-specific policies. DT has no concept of "unscanned artifacts" since it only sees components from uploaded BOMs.

### C5. Security Score Mapping

```
Our RepoSecurityScore:              DT ProjectMetrics:
  score (0-100)             <-->      inheritedRiskScore (unbounded, higher = worse)
  grade (A-F)               <-->      (no equivalent -- compute from inheritedRiskScore)
  critical_count            <-->      critical
  high_count                <-->      high
  medium_count              <-->      medium
  low_count                 <-->      low
  acknowledged_count        <-->      suppressed
  total_findings            <-->      findingsTotal
  last_scan_at              <-->      lastOccurrence
```

**Gaps:**
- DT's `inheritedRiskScore` is unbounded and uses a different formula than our 0-100 score. We would need a translation layer or redefine scoring to use DT's model.
- DT does not have letter grades.

---

## D. Recommendation

### Phase 1: Delegate vulnerability enrichment to DT (Low risk, high value)

**What:** After our scanners produce an SBOM, upload it to DT and let DT:
- Correlate components to NVD/OSV/GitHub advisories
- Evaluate license and severity policies
- Compute project metrics

**How:**
1. Extend `dependency_track_service.rs` with missing methods: `get_project_metrics()`, `trigger_analysis()`, `get_violations()`, `create_policy_with_conditions()`.
2. In the post-scan pipeline (after `scanner_service.rs::scan_artifact` completes), upload the generated SBOM to DT using the existing `upload_sbom()` + `wait_for_bom_processing()`.
3. Fetch DT findings and metrics to populate our API responses.

**Safe to defer:** Do not remove our `cve_history` table yet. Keep it as a read-through cache of DT data.

**Effort:** ~2-3 days. Low risk because `dependency_track_service.rs` already exists and works.

### Phase 2: Replace CVE history tracking with DT (Medium risk)

**What:** Stop writing to `cve_history` and `repo_security_scores`. Instead, read from DT on demand.

**How:**
1. Change `GET /sbom/cve/history/:artifact_id` to proxy to `GET /api/v1/finding/project/{dt_project_uuid}` with data transformation.
2. Change `GET /sbom/cve/trends` to proxy to `GET /api/v1/metrics/project/{uuid}/days/30`.
3. Change `POST /sbom/cve/status/:id` to proxy to `PUT /api/v1/analysis`.
4. Build a mapping layer (our artifact_id -> DT project UUID). Store this in a `dt_project_mapping` table.
5. Update gRPC `CveHistoryService` to read from DT.
6. Add caching layer (Redis or in-memory) for DT metrics since they are expensive to refresh.

**What to keep:** The `acknowledged_by` user tracking. DT does not record individual users. Either:
- (a) Store acknowledgment metadata in our DB alongside DT's analysis state, or
- (b) Accept the limitation and rely on DT audit logs.

**Effort:** ~1 week. Medium risk because API consumers must be updated for slight schema differences.

### Phase 3: Replace license policies with DT policies (Medium risk)

**What:** Migrate `license_policies` table to DT policy engine.

**How:**
1. Create a DT policy migration tool that converts each `license_policies` row into a DT policy with conditions.
2. Map `denied_licenses` to `PolicyCondition(subject=LICENSE, operator=IS, value=X)` with `violationState=FAIL`.
3. Map `allowed_licenses` to a license group + `PolicyCondition(subject=LICENSE_GROUP, operator=IS_NOT)`.
4. Route `POST /sbom/check-compliance` to `GET /api/v1/violation/project/{uuid}`.
5. Route `POST/GET/DELETE /sbom/license-policies` to DT policy CRUD.

**Effort:** ~1 week. Medium risk because DT policy model is more expressive (may confuse users expecting the simple allow/deny model).

### Phase 4: Replace scan policies with DT policies (Low risk)

**What:** Migrate `scan_policies` table to DT.

**How:**
1. Map `max_severity` to `PolicyCondition(subject=SEVERITY, operator=IS, value=CRITICAL)`.
2. Keep `block_unscanned` and `block_on_fail` in our code (DT has no equivalent).
3. Use `GET /api/v1/violation/project/{uuid}` in `evaluate_artifact()` instead of querying `scan_findings` directly.

**Effort:** ~2-3 days. Low risk because the logic is straightforward.

### What NOT to migrate

| Component | Reason to keep |
|-----------|---------------|
| SBOM generation (`generate_cyclonedx`, `generate_spdx`) | DT consumes but does not produce SBOMs |
| Scanner pipeline (Trivy, Grype, OpenSCAP) | DT is not a scanner |
| Scan deduplication (checksum-based reuse) | DT has no content-addressable dedup |
| `block_unscanned` / `block_on_fail` policies | Registry-specific, no DT concept |
| Promotion workflow gates | Registry-specific workflow |
| User-scoped acknowledgments (`acknowledged_by`) | DT tracks by team, not user |
| SBOM document storage (`sbom_documents.content`) | DT re-exports differ from originals |
| Artifact/repository management | DT is not a registry |

### Summary of Code Reduction

| Phase | Lines removable | Tables removable | Services simplified |
|-------|----------------|-------------------|---------------------|
| Phase 1 | 0 (additive only) | 0 | scanner_service (add DT upload step) |
| Phase 2 | ~350 | cve_history, repo_security_scores | sbom_service, scan_result_service, sbom_server.rs CveHistoryGrpcServer |
| Phase 3 | ~250 | license_policies | sbom_service, sbom_server.rs SecurityPolicyGrpcServer |
| Phase 4 | ~100 | scan_policies (partial) | policy_service |
| **Total** | **~700 lines** | **3-4 tables** | **4 services simplified** |

### Risk Mitigation

1. **DT availability:** If DT is down, vulnerability/policy queries fail. Add circuit breaker + fallback to cached data.
2. **DT version coupling:** Pin to DT 4.x API. DT 5.x (if released) may change endpoints.
3. **Data consistency:** During migration, dual-write to both our DB and DT. Validate that DT findings match our scan findings before cutting over.
4. **Performance:** DT finding queries are paginated (default 100). Our API may need to aggregate multiple pages for large projects. Consider background sync rather than real-time proxy.

---

## Appendix: DT API Endpoint Reference (Running Instance v4.11.4)

Key endpoint groups relevant to this integration:

| Tag | Endpoints | Purpose |
|-----|-----------|---------|
| project | 14 endpoints | Project CRUD, lookup, clone, children |
| bom | 5 endpoints | BOM upload (PUT/POST), export (CycloneDX), processing status |
| finding | 5 endpoints | Vulnerability findings per project, grouped findings, SARIF export, trigger analysis |
| vulnerability | 12 endpoints | Vulnerability CRUD, lookup by source/vulnId, project/component associations |
| analysis | 2 endpoints | Triage decisions (state, justification, suppression) |
| violation | 3 endpoints | Policy violations per portfolio/project/component |
| violationanalysis | 2 endpoints | Triage for policy violations |
| policy | 8 endpoints | Policy CRUD, project/tag assignment |
| policyCondition | 3 endpoints | Condition CRUD within policies |
| license | 5 endpoints | License metadata, custom licenses |
| licenseGroup | 7 endpoints | License grouping with risk weights |
| metrics | 13 endpoints | Project/portfolio/component/vulnerability metrics, historical data |
| component | 9 endpoints | Component CRUD, identity lookup, hash lookup, dependency graph |
| vex | 3 endpoints | VEX document upload and export |
