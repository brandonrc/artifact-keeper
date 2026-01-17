// Permission-related types for access control

/**
 * Target entity for permission assignment
 */
export type PermissionTarget = 'user' | 'group';

/**
 * Actions that can be granted on repositories
 * Based on data-model.md Permission Enum
 */
export type PermissionAction = 'read' | 'write' | 'delete' | 'admin';

/**
 * Pattern-based repository permission matching
 */
export interface RepositoryPattern {
  /** Glob pattern for matching repository keys (e.g., "npm-*", "docker-prod-*") */
  pattern: string;
  /** Whether pattern includes nested paths */
  include_nested?: boolean;
}

/**
 * A permission assignment linking a target (user/group) to repository access
 */
export interface PermissionAssignment {
  id: string;
  /** Type of target receiving the permission */
  target_type: PermissionTarget;
  /** ID of the user or group */
  target_id: string;
  /** Name of the user or group for display */
  target_name: string;
  /** Specific repository ID (null for pattern-based or global) */
  repository_id?: string;
  /** Repository key for display */
  repository_key?: string;
  /** Pattern for matching multiple repositories */
  repository_pattern?: RepositoryPattern;
  /** Granted permission actions */
  actions: PermissionAction[];
  /** Whether this is a global (all repos) permission */
  is_global: boolean;
  /** Role name if assigned via role */
  role_name?: string;
  /** When the permission was granted */
  created_at: string;
  /** Who granted the permission */
  granted_by?: string;
}

/**
 * Summary of effective permissions for a user or repository
 */
export interface PermissionSummary {
  /** Entity this summary is for */
  entity_type: 'user' | 'repository';
  entity_id: string;
  entity_name: string;
  /** Direct permission assignments */
  direct_permissions: PermissionAssignment[];
  /** Permissions inherited from groups */
  inherited_permissions: PermissionAssignment[];
  /** Computed effective actions (union of all permissions) */
  effective_actions: PermissionAction[];
  /** Whether the entity has admin-level access */
  is_admin: boolean;
}

/**
 * Request to create a new permission assignment
 */
export interface CreatePermissionRequest {
  target_type: PermissionTarget;
  target_id: string;
  repository_id?: string;
  repository_pattern?: string;
  actions: PermissionAction[];
}

/**
 * Request to update an existing permission assignment
 */
export interface UpdatePermissionRequest {
  actions: PermissionAction[];
}

/**
 * Request to check if a user has specific permissions
 */
export interface PermissionCheckRequest {
  user_id: string;
  repository_id: string;
  actions: PermissionAction[];
}

/**
 * Response for permission check
 */
export interface PermissionCheckResponse {
  allowed: boolean;
  granted_actions: PermissionAction[];
  denied_actions: PermissionAction[];
  reason?: string;
}
