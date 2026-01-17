# Data Model: Frontend UI/UX Parity

**Feature**: 003-frontend-ui-parity
**Date**: 2026-01-16
**Status**: Complete

## Overview

This document defines TypeScript types for frontend state management and API responses. These extend the existing types in `frontend/src/types/index.ts`.

---

## Core Entities

### User (Extended)

```typescript
// Extends existing User type
export interface User {
  id: string;
  username: string;
  email: string;
  display_name?: string;
  avatar_url?: string;
  is_admin: boolean;
  is_active: boolean;
  must_change_password: boolean;
  mfa_enabled: boolean;
  last_login?: string;
  created_at: string;
  updated_at: string;
}

export interface UserProfile extends User {
  groups: Group[];
  permissions_summary: PermissionSummary[];
}
```

### Group

```typescript
export interface Group {
  id: string;
  name: string;
  description?: string;
  auto_join: boolean;
  member_count: number;
  is_external: boolean; // LDAP/SAML sourced
  created_at: string;
  updated_at: string;
}

export interface GroupDetail extends Group {
  members: GroupMember[];
}

export interface GroupMember {
  user_id: string;
  username: string;
  display_name?: string;
  joined_at: string;
}
```

### Permission Target

```typescript
export interface PermissionTarget {
  id: string;
  name: string;
  description?: string;
  repositories: RepositoryPattern[];
  users: PermissionAssignment[];
  groups: PermissionAssignment[];
  created_at: string;
  updated_at: string;
}

export interface RepositoryPattern {
  pattern: string; // e.g., "libs-*", "docker-local"
  include_patterns: string[];
  exclude_patterns: string[];
}

export interface PermissionAssignment {
  id: string; // user_id or group_id
  name: string; // username or group name
  actions: PermissionAction[];
}

export type PermissionAction =
  | 'read'
  | 'annotate'
  | 'deploy'
  | 'delete'
  | 'manage';

export interface PermissionSummary {
  repository_key: string;
  actions: PermissionAction[];
  source: 'user' | 'group';
  source_name: string;
}
```

### Access Token & API Key

```typescript
export interface AccessToken {
  id: string;
  name: string;
  scopes: TokenScope[];
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
}

export type TokenScope =
  | 'read:artifacts'
  | 'write:artifacts'
  | 'delete:artifacts'
  | 'admin:users'
  | 'admin:repos';

export interface ApiKey {
  id: string;
  key_prefix: string; // First 8 chars for identification
  created_at: string;
  last_used_at?: string;
}

// Response when creating (only time full key is visible)
export interface ApiKeyCreated {
  id: string;
  key: string; // Full key, shown once
  created_at: string;
}
```

---

## Repository Browser Entities

### Tree Node

```typescript
export interface TreeNode {
  key: string; // Full path: "repo-key/path/to/item"
  title: string; // Display name
  isLeaf: boolean;
  children?: TreeNode[];
  icon?: React.ReactNode;
  nodeType: TreeNodeType;
  metadata?: TreeNodeMetadata;
}

export type TreeNodeType =
  | 'repository-local'
  | 'repository-remote'
  | 'repository-virtual'
  | 'repository-federated'
  | 'folder'
  | 'file';

export interface TreeNodeMetadata {
  size?: number;
  modified_at?: string;
  artifact_id?: string;
}
```

### Artifact (Extended)

```typescript
// Extends existing Artifact type with detail fields
export interface ArtifactDetail extends Artifact {
  checksum_md5: string;
  checksum_sha1: string;
  checksum_sha256: string;
  properties: ArtifactProperty[];
  builds: ArtifactBuild[];
  effective_permissions: EffectivePermission[];
}

export interface ArtifactProperty {
  key: string;
  value: string;
  inherited: boolean; // From parent folder
}

export interface ArtifactBuild {
  build_name: string;
  build_number: string;
  build_url?: string;
  created_at: string;
}

export interface EffectivePermission {
  principal: string; // Username or group name
  principal_type: 'user' | 'group';
  actions: PermissionAction[];
}
```

---

## Package & Build Entities

### Package

```typescript
export interface Package {
  id: string;
  name: string;
  package_type: PackageType;
  latest_version: string;
  versions_count: number;
  download_count: number;
  repositories: string[]; // Repository keys
  created_at: string;
  updated_at: string;
}

export type PackageType =
  | 'maven'
  | 'npm'
  | 'pypi'
  | 'docker'
  | 'helm'
  | 'go'
  | 'cargo'
  | 'nuget'
  | 'rubygems'
  | 'composer'
  | 'debian'
  | 'rpm'
  | 'alpine'
  | 'generic';

export interface PackageVersion {
  version: string;
  artifacts: Artifact[];
  download_count: number;
  created_at: string;
}

export interface PackageDetail extends Package {
  description?: string;
  versions: PackageVersion[];
  dependencies: PackageDependency[];
  installation_instructions: InstallationInstruction[];
}

export interface PackageDependency {
  name: string;
  version_constraint: string;
  scope?: string; // e.g., 'compile', 'test', 'dev'
}

export interface InstallationInstruction {
  tool: string; // e.g., 'maven', 'npm', 'pip'
  command: string;
}
```

### Build

```typescript
export interface Build {
  id: string;
  name: string;
  number: string;
  status: BuildStatus;
  started_at: string;
  duration_ms: number;
  modules_count: number;
  agent?: string;
  principal?: string;
}

export type BuildStatus = 'success' | 'failure' | 'running' | 'unknown';

export interface BuildDetail extends Build {
  modules: BuildModule[];
  dependencies: BuildDependency[];
  environment: Record<string, string>;
  issues: BuildIssue[];
  release_history: ReleaseHistory[];
}

export interface BuildModule {
  id: string;
  name: string;
  artifacts: Artifact[];
}

export interface BuildDependency {
  id: string;
  name: string;
  version: string;
  scope: string;
}

export interface BuildIssue {
  key: string;
  url?: string;
  summary?: string;
}

export interface ReleaseHistory {
  version: string;
  released_at: string;
  release_bundle?: string;
}

export interface BuildDiff {
  build1: BuildSummary;
  build2: BuildSummary;
  added_dependencies: BuildDependency[];
  removed_dependencies: BuildDependency[];
  changed_modules: ModuleDiff[];
}

export interface BuildSummary {
  name: string;
  number: string;
}

export interface ModuleDiff {
  module_name: string;
  added_artifacts: string[];
  removed_artifacts: string[];
}
```

---

## Search Entities

### Search Request/Response

```typescript
export interface QuickSearchRequest {
  query: string;
  limit?: number;
}

export interface QuickSearchResult {
  artifacts: ArtifactSearchHit[];
  packages: PackageSearchHit[];
  repositories: RepositorySearchHit[];
  total_count: number;
}

export interface ArtifactSearchHit {
  artifact_id: string;
  path: string;
  repository_key: string;
  name: string;
  highlight?: string; // Matched text with highlighting
}

export interface PackageSearchHit {
  package_id: string;
  name: string;
  package_type: PackageType;
  latest_version: string;
}

export interface RepositorySearchHit {
  repository_key: string;
  name: string;
  format: RepositoryFormat;
}

export interface AdvancedSearchRequest {
  search_type: AdvancedSearchType;
  params: AdvancedSearchParams;
}

export type AdvancedSearchType =
  | 'quick'
  | 'package'
  | 'property'
  | 'checksum'
  | 'gavc';

export interface AdvancedSearchParams {
  // Quick search
  query?: string;

  // Package search
  package_name?: string;
  package_version?: string;
  package_type?: PackageType;

  // Property search
  properties?: PropertyFilter[];

  // Checksum search
  checksum?: string;
  checksum_algorithm?: 'md5' | 'sha1' | 'sha256';

  // GAVC search (Maven)
  group_id?: string;
  artifact_id?: string;
  version?: string;
  classifier?: string;

  // Common filters
  repositories?: string[];
  limit?: number;
  offset?: number;
}

export interface PropertyFilter {
  key: string;
  value: string;
  match_type: 'exact' | 'contains' | 'regex';
}

export interface AdvancedSearchResponse {
  results: ArtifactSearchHit[];
  total_count: number;
  facets?: SearchFacets;
}

export interface SearchFacets {
  repositories: FacetValue[];
  formats: FacetValue[];
}

export interface FacetValue {
  value: string;
  count: number;
}
```

---

## Authentication Entities

### SSO Configuration

```typescript
export interface SSOProvider {
  id: string;
  provider_type: SSOProviderType;
  name: string;
  icon?: string;
  enabled: boolean;
}

export type SSOProviderType =
  | 'github'
  | 'gitlab'
  | 'google'
  | 'azure'
  | 'okta'
  | 'saml';

export interface SSOLoginRequest {
  provider: SSOProviderType;
  redirect_url: string;
}

export interface MFAEnrollmentRequest {
  method: MFAMethod;
}

export type MFAMethod = 'totp' | 'sms' | 'email';

export interface MFAEnrollmentResponse {
  secret?: string; // For TOTP
  qr_code_url?: string; // For TOTP
  verification_required: boolean;
}

export interface MFAVerifyRequest {
  code: string;
  method: MFAMethod;
}
```

---

## UI State Types

### Session State

```typescript
export interface SessionState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  mustChangePassword: boolean;
  mfaRequired: boolean;
  expiresAt?: number;
}

export interface PendingAction {
  id: string;
  action: () => Promise<void>;
  description: string;
  timestamp: number;
}
```

### Theme State

```typescript
export interface ThemeState {
  mode: 'light' | 'dark';
  sidebarCollapsed: boolean;
  tokens: DesignTokens;
}

export interface DesignTokens {
  colorPrimary: string;
  colorSuccess: string;
  colorWarning: string;
  colorError: string;
  colorInfo: string;
  colorBgContainer: string;
  siderBg: string;
  borderRadius: number;
}
```

### Wizard State

```typescript
export interface WizardState<T> {
  currentStep: number;
  totalSteps: number;
  data: Partial<T>;
  isComplete: boolean;
  errors: Record<string, string>;
}

export interface CreateRepositoryWizardData {
  repo_type: RepositoryType;
  package_type: PackageType;
  key: string;
  name: string;
  description?: string;
  include_patterns?: string[];
  exclude_patterns?: string[];
  // Remote-specific
  remote_url?: string;
  proxy_id?: string;
  // Virtual-specific
  included_repositories?: string[];
}
```

---

## Validation Rules

| Entity | Field | Rule |
|--------|-------|------|
| Group | name | 2-50 chars, alphanumeric + underscore |
| PermissionTarget | name | 2-100 chars, alphanumeric + dash |
| RepositoryPattern | pattern | Valid glob pattern |
| AccessToken | name | 1-100 chars |
| AccessToken | expires_at | Must be future date if set |
| Package | name | Package type specific validation |
| Build | number | Non-empty string |
| Search | query | 1-500 chars |
| Search | limit | 1-1000, default 50 |

---

## State Transitions

### Session Lifecycle

```
[Initial] -> [Loading] -> [Authenticated] -> [Expired] -> [Re-authenticating] -> [Authenticated]
                      \-> [Unauthenticated]
                      \-> [MFA Required] -> [Authenticated]
```

### Wizard Flow

```
[Step 1: Type] -> [Step 2: Package] -> [Step 3: Basic] -> [Step 4: Advanced] -> [Complete]
     ^                                        |
     +----------------------------------------+ (Back navigation allowed)
```

### Tree Node Loading

```
[Collapsed] -> [Expanding] -> [Expanded with children]
                          \-> [Error] -> [Collapsed] (with retry available)
```

---

## Relationships

```
User 1:N Group (membership)
User 1:N AccessToken
User 1:N ApiKey
Group N:M PermissionTarget
PermissionTarget N:M Repository (via patterns)
Repository 1:N Artifact
Artifact N:M Build
Package 1:N PackageVersion
PackageVersion 1:N Artifact
Build 1:N BuildModule
BuildModule 1:N Artifact
```
