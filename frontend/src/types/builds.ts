// Build-related types for build information and analysis

/**
 * Status of a build
 */
export type BuildStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'success'
  | 'failed'
  | 'cancelled'
  | 'unstable';

/**
 * Summary of a build
 */
export interface Build {
  id: string;
  /** Build number or identifier */
  build_number: string;
  /** Name of the project/pipeline */
  project_name: string;
  /** Repository associated with this build */
  repository_id?: string;
  repository_key?: string;
  /** Current status */
  status: BuildStatus;
  /** Build duration in milliseconds */
  duration_ms?: number;
  /** Number of artifacts produced */
  artifact_count: number;
  /** Total size of produced artifacts */
  artifact_size_bytes: number;
  /** Number of modules in the build */
  module_count: number;
  /** Who triggered the build */
  triggered_by?: string;
  /** Build trigger source (CI system, manual, etc.) */
  trigger_source?: string;
  /** Git commit SHA */
  commit_sha?: string;
  /** Git branch name */
  branch?: string;
  /** When the build started */
  started_at?: string;
  /** When the build completed */
  completed_at?: string;
  /** When the build was created */
  created_at: string;
}

/**
 * A module within a build (e.g., Maven module, npm workspace package)
 */
export interface BuildModule {
  id: string;
  build_id: string;
  /** Module name/identifier */
  name: string;
  /** Module type (maven, npm, gradle, etc.) */
  module_type: string;
  /** Module version */
  version?: string;
  /** Artifacts produced by this module */
  artifacts: BuildModuleArtifact[];
  /** Dependencies of this module */
  dependencies: BuildDependency[];
  /** Issues found in this module */
  issues: BuildIssue[];
  /** Module-specific properties */
  properties?: Record<string, string>;
}

/**
 * An artifact produced by a build module
 */
export interface BuildModuleArtifact {
  id: string;
  /** Artifact path in the build */
  path: string;
  /** Artifact name */
  name: string;
  /** File type */
  type: string;
  /** Size in bytes */
  size_bytes: number;
  /** SHA-256 checksum */
  checksum_sha256: string;
  /** Where the artifact was published (if applicable) */
  published_to?: string;
}

/**
 * A dependency used in a build
 */
export interface BuildDependency {
  id: string;
  /** Dependency identifier (group:artifact:version, package@version, etc.) */
  identifier: string;
  /** Dependency name */
  name: string;
  /** Dependency version */
  version: string;
  /** Type of dependency */
  dependency_type: 'compile' | 'runtime' | 'test' | 'provided' | 'development';
  /** Scope (direct, transitive) */
  scope: 'direct' | 'transitive';
  /** Repository from which it was resolved */
  resolved_from?: string;
  /** SHA-256 checksum of resolved artifact */
  checksum_sha256?: string;
  /** License information */
  license?: string;
}

/**
 * An issue found during build analysis
 */
export interface BuildIssue {
  id: string;
  /** Issue severity */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Issue type/category */
  issue_type: string;
  /** Issue title/summary */
  title: string;
  /** Detailed description */
  description: string;
  /** File where issue was found */
  file_path?: string;
  /** Line number in file */
  line_number?: number;
  /** Suggested fix */
  suggestion?: string;
  /** Link to more information */
  documentation_url?: string;
}

/**
 * Detailed view of a build
 */
export interface BuildDetail extends Build {
  /** All modules in this build */
  modules: BuildModule[];
  /** All dependencies aggregated */
  all_dependencies: BuildDependency[];
  /** All issues aggregated */
  all_issues: BuildIssue[];
  /** Build environment information */
  environment: BuildEnvironment;
  /** Build logs URL */
  logs_url?: string;
  /** Build configuration */
  config?: Record<string, unknown>;
}

/**
 * Build environment information
 */
export interface BuildEnvironment {
  /** Operating system */
  os?: string;
  /** Architecture */
  arch?: string;
  /** Build tool name */
  build_tool?: string;
  /** Build tool version */
  build_tool_version?: string;
  /** Runtime version (JDK, Node, Python, etc.) */
  runtime_version?: string;
  /** CI system name */
  ci_system?: string;
  /** Additional environment variables (non-sensitive) */
  variables?: Record<string, string>;
}

/**
 * History of releases for a project
 */
export interface ReleaseHistory {
  project_name: string;
  repository_key: string;
  /** List of releases ordered by date */
  releases: ReleaseInfo[];
  /** Total number of releases */
  total_releases: number;
}

/**
 * Information about a single release
 */
export interface ReleaseInfo {
  /** Version of the release */
  version: string;
  /** Build that produced this release */
  build_id: string;
  build_number: string;
  /** Release date */
  released_at: string;
  /** Release notes/changelog */
  release_notes?: string;
  /** Git tag */
  tag?: string;
  /** Whether this is the latest release */
  is_latest: boolean;
  /** Whether this is a pre-release */
  is_prerelease: boolean;
}

/**
 * Comparison between two builds
 */
export interface BuildDiff {
  /** Source build */
  from_build: BuildSummary;
  /** Target build */
  to_build: BuildSummary;
  /** Module differences */
  module_diffs: ModuleDiff[];
  /** New dependencies */
  added_dependencies: BuildDependency[];
  /** Removed dependencies */
  removed_dependencies: BuildDependency[];
  /** Changed dependencies */
  changed_dependencies: DependencyChange[];
  /** New issues */
  added_issues: BuildIssue[];
  /** Resolved issues */
  resolved_issues: BuildIssue[];
}

/**
 * Summary of a build for diff display
 */
export interface BuildSummary {
  id: string;
  build_number: string;
  project_name: string;
  status: BuildStatus;
  completed_at?: string;
  commit_sha?: string;
  branch?: string;
}

/**
 * Difference between modules in two builds
 */
export interface ModuleDiff {
  module_name: string;
  /** Status of the module in the diff */
  status: 'added' | 'removed' | 'modified' | 'unchanged';
  /** Version change if modified */
  version_from?: string;
  version_to?: string;
  /** Artifact changes */
  artifact_changes: ArtifactChange[];
}

/**
 * Change to an artifact between builds
 */
export interface ArtifactChange {
  artifact_name: string;
  status: 'added' | 'removed' | 'modified' | 'unchanged';
  size_from?: number;
  size_to?: number;
  checksum_from?: string;
  checksum_to?: string;
}

/**
 * Change to a dependency between builds
 */
export interface DependencyChange {
  identifier: string;
  name: string;
  version_from: string;
  version_to: string;
  license_changed: boolean;
}

/**
 * Request to search builds
 */
export interface BuildSearchRequest {
  project_name?: string;
  repository_id?: string;
  status?: BuildStatus;
  branch?: string;
  triggered_by?: string;
  from_date?: string;
  to_date?: string;
  page?: number;
  per_page?: number;
  sort_by?: 'build_number' | 'created_at' | 'duration';
  sort_order?: 'asc' | 'desc';
}
