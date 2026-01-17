// Tree-related types for hierarchical navigation of artifacts

/**
 * Types of nodes in the artifact tree
 */
export type TreeNodeType =
  | 'root'           // Root of the tree
  | 'repository'     // Repository container
  | 'folder'         // Virtual folder/directory
  | 'package'        // Package grouping
  | 'version'        // Version container
  | 'artifact'       // Actual artifact file
  | 'metadata';      // Metadata file (pom.xml, package.json, etc.)

/**
 * A node in the artifact tree hierarchy
 */
export interface TreeNode {
  /** Unique identifier for this node */
  id: string;
  /** Display name */
  name: string;
  /** Type of node */
  type: TreeNodeType;
  /** Full path from root */
  path: string;
  /** Parent node ID (null for root) */
  parent_id?: string;
  /** Whether this node has children */
  has_children: boolean;
  /** Number of children (if known) */
  children_count?: number;
  /** Children nodes (loaded on demand) */
  children?: TreeNode[];
  /** Whether children are currently loading */
  is_loading?: boolean;
  /** Whether this node is expanded in the UI */
  is_expanded?: boolean;
  /** Type-specific metadata */
  metadata?: TreeNodeMetadata;
  /** Icon hint for the UI */
  icon?: string;
  /** Whether this node is selectable */
  is_selectable?: boolean;
  /** Whether this node is currently selected */
  is_selected?: boolean;
}

/**
 * Metadata associated with a tree node
 */
export interface TreeNodeMetadata {
  /** For repository nodes */
  repository?: TreeRepositoryMetadata;
  /** For package nodes */
  package?: TreePackageMetadata;
  /** For version nodes */
  version?: TreeVersionMetadata;
  /** For artifact nodes */
  artifact?: TreeArtifactMetadata;
  /** For folder nodes */
  folder?: TreeFolderMetadata;
}

/**
 * Metadata for repository nodes
 */
export interface TreeRepositoryMetadata {
  repository_id: string;
  key: string;
  format: string;
  repo_type: string;
  is_public: boolean;
  artifact_count: number;
  storage_used_bytes: number;
}

/**
 * Metadata for package nodes
 */
export interface TreePackageMetadata {
  package_id: string;
  package_type: string;
  latest_version?: string;
  version_count: number;
  total_downloads: number;
}

/**
 * Metadata for version nodes
 */
export interface TreeVersionMetadata {
  version: string;
  is_latest: boolean;
  is_prerelease: boolean;
  artifact_count: number;
  total_size_bytes: number;
  created_at: string;
}

/**
 * Metadata for artifact nodes
 */
export interface TreeArtifactMetadata {
  artifact_id: string;
  size_bytes: number;
  checksum_sha256: string;
  content_type: string;
  download_count: number;
  created_at: string;
  /** Download URL for this artifact */
  download_url?: string;
}

/**
 * Metadata for folder nodes
 */
export interface TreeFolderMetadata {
  /** Number of files in this folder (not recursive) */
  file_count: number;
  /** Number of subfolders */
  folder_count: number;
  /** Total size of files in this folder (not recursive) */
  total_size_bytes?: number;
}

/**
 * Request to load tree children
 */
export interface TreeLoadRequest {
  /** Parent node ID (null for root) */
  parent_id?: string;
  /** Repository to load (for root level) */
  repository_id?: string;
  /** Path within repository */
  path?: string;
  /** Maximum depth to load (default 1) */
  depth?: number;
  /** Whether to include artifact counts */
  include_counts?: boolean;
  /** Whether to include metadata */
  include_metadata?: boolean;
  /** Sort order for children */
  sort_by?: 'name' | 'type' | 'size' | 'date';
  sort_order?: 'asc' | 'desc';
}

/**
 * Response from tree load
 */
export interface TreeLoadResponse {
  /** Parent node (if requested) */
  parent?: TreeNode;
  /** Child nodes */
  children: TreeNode[];
  /** Whether there are more children (for pagination) */
  has_more: boolean;
  /** Cursor for loading more */
  next_cursor?: string;
}

/**
 * Breadcrumb item for tree navigation
 */
export interface TreeBreadcrumb {
  /** Node ID */
  id: string;
  /** Display name */
  name: string;
  /** Node type */
  type: TreeNodeType;
  /** Full path */
  path: string;
}

/**
 * Full path information for tree navigation
 */
export interface TreePath {
  /** Repository key */
  repository_key: string;
  /** Path segments */
  segments: string[];
  /** Breadcrumb trail */
  breadcrumbs: TreeBreadcrumb[];
  /** Current node */
  current: TreeNode;
}

/**
 * Options for tree display configuration
 */
export interface TreeDisplayOptions {
  /** Show hidden files (starting with .) */
  show_hidden: boolean;
  /** Show file sizes */
  show_sizes: boolean;
  /** Show last modified dates */
  show_dates: boolean;
  /** Show download counts */
  show_downloads: boolean;
  /** Group by type (folders first, then files) */
  group_by_type: boolean;
  /** Default sort order */
  default_sort: 'name' | 'type' | 'size' | 'date';
  /** Default sort direction */
  default_sort_order: 'asc' | 'desc';
}
