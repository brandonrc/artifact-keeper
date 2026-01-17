// Search-related types for quick and advanced search functionality

import type { PackageType } from './packages';
import type { RepositoryFormat, RepositoryType } from './index';

/**
 * Request for quick search across all entity types
 */
export interface QuickSearchRequest {
  /** Search query string */
  query: string;
  /** Maximum results to return */
  limit?: number;
  /** Entity types to search */
  types?: QuickSearchType[];
}

/**
 * Entity types available for quick search
 */
export type QuickSearchType = 'artifact' | 'package' | 'repository' | 'build';

/**
 * Response from quick search
 */
export interface QuickSearchResult {
  /** Total matches found */
  total_count: number;
  /** Artifact matches */
  artifacts: ArtifactSearchHit[];
  /** Package matches */
  packages: PackageSearchHit[];
  /** Repository matches */
  repositories: RepositorySearchHit[];
  /** Search execution time in milliseconds */
  took_ms: number;
}

/**
 * An artifact match from search
 */
export interface ArtifactSearchHit {
  id: string;
  /** Repository containing this artifact */
  repository_id: string;
  repository_key: string;
  /** Full path within repository */
  path: string;
  /** Artifact name */
  name: string;
  /** Version if applicable */
  version?: string;
  /** Size in bytes */
  size_bytes: number;
  /** SHA-256 checksum */
  checksum_sha256: string;
  /** File type */
  content_type: string;
  /** Upload timestamp */
  created_at: string;
  /** Highlighted name with match markers */
  name_highlighted?: string;
  /** Highlighted path with match markers */
  path_highlighted?: string;
  /** Search relevance score */
  score: number;
}

/**
 * A package match from search
 */
export interface PackageSearchHit {
  id: string;
  /** Repository containing this package */
  repository_id: string;
  repository_key: string;
  /** Package name */
  name: string;
  /** Package type */
  package_type: PackageType;
  /** Latest version */
  latest_version?: string;
  /** Description */
  description?: string;
  /** Total downloads */
  total_downloads: number;
  /** Last updated timestamp */
  updated_at: string;
  /** Highlighted name with match markers */
  name_highlighted?: string;
  /** Highlighted description with match markers */
  description_highlighted?: string;
  /** Search relevance score */
  score: number;
}

/**
 * A repository match from search
 */
export interface RepositorySearchHit {
  id: string;
  /** Repository key */
  key: string;
  /** Repository display name */
  name: string;
  /** Repository description */
  description?: string;
  /** Repository format */
  format: RepositoryFormat;
  /** Repository type */
  repo_type: RepositoryType;
  /** Whether publicly accessible */
  is_public: boolean;
  /** Number of artifacts */
  artifact_count: number;
  /** Storage used in bytes */
  storage_used_bytes: number;
  /** Highlighted key with match markers */
  key_highlighted?: string;
  /** Highlighted name with match markers */
  name_highlighted?: string;
  /** Highlighted description with match markers */
  description_highlighted?: string;
  /** Search relevance score */
  score: number;
}

/**
 * Types available for advanced search
 */
export type AdvancedSearchType = 'artifact' | 'package' | 'repository' | 'build' | 'user';

/**
 * Request for advanced search with filters
 */
export interface AdvancedSearchRequest {
  /** Primary search query */
  query?: string;
  /** Type of entity to search */
  type: AdvancedSearchType;
  /** Type-specific search parameters */
  params: AdvancedSearchParams;
  /** Property filters */
  filters?: PropertyFilter[];
  /** Pagination */
  page?: number;
  per_page?: number;
  /** Sorting */
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  /** Whether to include facets in response */
  include_facets?: boolean;
}

/**
 * Type-specific search parameters
 */
export interface AdvancedSearchParams {
  /** For artifacts: repository to search in */
  repository_id?: string;
  /** For artifacts: file path pattern */
  path_pattern?: string;
  /** For artifacts: name pattern */
  name_pattern?: string;
  /** For artifacts/packages: version pattern */
  version_pattern?: string;
  /** For packages: package type filter */
  package_type?: PackageType;
  /** For repositories: format filter */
  format?: RepositoryFormat;
  /** For repositories: type filter */
  repo_type?: RepositoryType;
  /** For builds: project name */
  project_name?: string;
  /** For builds: status filter */
  build_status?: string;
  /** For builds: branch filter */
  branch?: string;
  /** Date range: created after */
  created_after?: string;
  /** Date range: created before */
  created_before?: string;
  /** Date range: updated after */
  updated_after?: string;
  /** Date range: updated before */
  updated_before?: string;
  /** Size range: minimum bytes */
  min_size_bytes?: number;
  /** Size range: maximum bytes */
  max_size_bytes?: number;
  /** Checksum for exact match */
  checksum_sha256?: string;
}

/**
 * A property filter for advanced search
 */
export interface PropertyFilter {
  /** Property key (e.g., "metadata.author", "properties.env") */
  key: string;
  /** Comparison operator */
  operator: PropertyFilterOperator;
  /** Value to compare against */
  value: string | number | boolean | string[];
}

/**
 * Operators for property filtering
 */
export type PropertyFilterOperator =
  | 'eq'      // Equals
  | 'ne'      // Not equals
  | 'lt'      // Less than
  | 'le'      // Less than or equal
  | 'gt'      // Greater than
  | 'ge'      // Greater than or equal
  | 'contains' // String contains
  | 'starts_with' // String starts with
  | 'ends_with'   // String ends with
  | 'in'      // Value in array
  | 'not_in'  // Value not in array
  | 'exists'  // Property exists
  | 'not_exists'; // Property does not exist

/**
 * Response from advanced search
 */
export interface AdvancedSearchResponse<T> {
  /** Search results */
  items: T[];
  /** Total matching items */
  total_count: number;
  /** Current page */
  page: number;
  /** Items per page */
  per_page: number;
  /** Total pages */
  total_pages: number;
  /** Search facets for filtering */
  facets?: SearchFacets;
  /** Search execution time in milliseconds */
  took_ms: number;
}

/**
 * Facets for search result filtering
 */
export interface SearchFacets {
  /** Facets by repository */
  by_repository?: FacetValue[];
  /** Facets by format */
  by_format?: FacetValue[];
  /** Facets by type */
  by_type?: FacetValue[];
  /** Facets by package type */
  by_package_type?: FacetValue[];
  /** Facets by status (for builds) */
  by_status?: FacetValue[];
  /** Facets by date range */
  by_date?: FacetValue[];
  /** Custom property facets */
  by_property?: Record<string, FacetValue[]>;
}

/**
 * A single facet value with count
 */
export interface FacetValue {
  /** Facet value */
  value: string;
  /** Display label */
  label?: string;
  /** Number of items matching this facet */
  count: number;
  /** Whether this facet is currently selected */
  selected?: boolean;
}

/**
 * Saved search configuration
 */
export interface SavedSearch {
  id: string;
  /** User who saved this search */
  user_id: string;
  /** Search name */
  name: string;
  /** Search description */
  description?: string;
  /** The search request to execute */
  search_request: AdvancedSearchRequest;
  /** Whether this is a shared search */
  is_shared: boolean;
  /** When the search was created */
  created_at: string;
  /** When the search was last used */
  last_used_at?: string;
}

/**
 * Request to create a saved search
 */
export interface CreateSavedSearchRequest {
  name: string;
  description?: string;
  search_request: AdvancedSearchRequest;
  is_shared?: boolean;
}
