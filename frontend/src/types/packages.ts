// Package-related types for artifact package management

/**
 * Supported package formats
 * Based on data-model.md Format Enum (FR-007 through FR-020)
 */
export type PackageType =
  | 'maven'
  | 'gradle'
  | 'npm'
  | 'pypi'
  | 'nuget'
  | 'go'
  | 'rubygems'
  | 'docker'
  | 'helm'
  | 'rpm'
  | 'debian'
  | 'conan'
  | 'cargo'
  | 'generic'
  | 'podman'
  | 'buildx'
  | 'oras'
  | 'wasm_oci'
  | 'helm_oci'
  | 'poetry'
  | 'conda'
  | 'yarn'
  | 'bower'
  | 'pnpm'
  | 'chocolatey'
  | 'powershell'
  | 'terraform'
  | 'opentofu'
  | 'alpine'
  | 'conda_native'
  | 'composer'
  | 'hex'
  | 'cocoapods'
  | 'swift'
  | 'pub'
  | 'sbt'
  | 'chef'
  | 'puppet'
  | 'ansible'
  | 'gitlfs'
  | 'vscode'
  | 'jetbrains'
  | 'huggingface'
  | 'mlmodel'
  | 'cran'
  | 'vagrant'
  | 'opkg'
  | 'p2'
  | 'bazel';

/**
 * A package in the artifact registry
 */
export interface Package {
  id: string;
  /** Repository containing this package */
  repository_id: string;
  repository_key: string;
  /** Package name (format-specific) */
  name: string;
  /** Package type/format */
  package_type: PackageType;
  /** Latest version string */
  latest_version?: string;
  /** Total number of versions available */
  version_count: number;
  /** Total size across all versions */
  total_size_bytes: number;
  /** Total downloads across all versions */
  total_downloads: number;
  /** Package description from metadata */
  description?: string;
  /** Package license */
  license?: string;
  /** Package author or maintainer */
  author?: string;
  /** Homepage or repository URL */
  homepage_url?: string;
  /** When the package was first uploaded */
  created_at: string;
  /** When the package was last updated */
  updated_at: string;
}

/**
 * A specific version of a package
 */
export interface PackageVersion {
  id: string;
  package_id: string;
  /** Version string (semver, Maven coords, etc.) */
  version: string;
  /** Size of this version's artifact(s) */
  size_bytes: number;
  /** SHA-256 checksum of primary artifact */
  checksum_sha256: string;
  /** Download count for this version */
  download_count: number;
  /** Whether this is the latest version */
  is_latest: boolean;
  /** Whether this is a pre-release version */
  is_prerelease: boolean;
  /** Who uploaded this version */
  uploaded_by?: string;
  /** Release notes or changelog */
  release_notes?: string;
  /** When this version was uploaded */
  created_at: string;
  /** Version-specific metadata */
  metadata?: Record<string, unknown>;
}

/**
 * A dependency of a package
 */
export interface PackageDependency {
  /** Dependency package name */
  name: string;
  /** Version constraint (e.g., "^1.0.0", ">=2.0,<3.0") */
  version_constraint: string;
  /** Type of dependency */
  dependency_type: 'runtime' | 'development' | 'build' | 'optional' | 'peer';
  /** Whether this is a direct or transitive dependency */
  is_direct: boolean;
  /** Repository where dependency is resolved (if known) */
  resolved_repository?: string;
  /** Resolved version (if known) */
  resolved_version?: string;
}

/**
 * Detailed view of a package including versions and dependencies
 */
export interface PackageDetail extends Package {
  /** All available versions */
  versions: PackageVersion[];
  /** Dependencies of the latest version */
  dependencies: PackageDependency[];
  /** Packages that depend on this one */
  dependents_count: number;
  /** Format-specific metadata */
  format_metadata: PackageFormatMetadata;
}

/**
 * Format-specific metadata union type
 */
export type PackageFormatMetadata =
  | MavenMetadata
  | NpmMetadata
  | PypiMetadata
  | DockerMetadata
  | HelmMetadata
  | RpmMetadata
  | DebianMetadata
  | GenericMetadata;

export interface MavenMetadata {
  type: 'maven';
  group_id: string;
  artifact_id: string;
  packaging: string;
  classifier?: string;
}

export interface NpmMetadata {
  type: 'npm';
  scope?: string;
  keywords?: string[];
  engines?: Record<string, string>;
  repository?: {
    type: string;
    url: string;
  };
}

export interface PypiMetadata {
  type: 'pypi';
  requires_python?: string;
  classifiers?: string[];
  project_urls?: Record<string, string>;
}

export interface DockerMetadata {
  type: 'docker';
  digest: string;
  media_type: string;
  architecture: string;
  os: string;
  layers: DockerLayer[];
}

export interface DockerLayer {
  digest: string;
  size: number;
  media_type: string;
}

export interface HelmMetadata {
  type: 'helm';
  app_version?: string;
  kube_version?: string;
  api_version: string;
  chart_type: 'application' | 'library';
}

export interface RpmMetadata {
  type: 'rpm';
  release: string;
  arch: string;
  requires: string[];
  provides: string[];
  epoch?: number;
}

export interface DebianMetadata {
  type: 'debian';
  architecture: string;
  section?: string;
  priority?: string;
  depends?: string[];
  recommends?: string[];
}

export interface GenericMetadata {
  type: 'generic';
  custom_properties?: Record<string, unknown>;
}

/**
 * Installation instructions for a package version
 */
export interface InstallationInstruction {
  /** Package manager or tool name */
  tool: string;
  /** Command to run */
  command: string;
  /** Configuration file snippet (if applicable) */
  config_snippet?: {
    filename: string;
    content: string;
    language: string;
  };
  /** Additional notes */
  notes?: string;
}

/**
 * Request to search packages
 */
export interface PackageSearchRequest {
  query?: string;
  package_type?: PackageType;
  repository_id?: string;
  page?: number;
  per_page?: number;
  sort_by?: 'name' | 'downloads' | 'updated' | 'created';
  sort_order?: 'asc' | 'desc';
}
