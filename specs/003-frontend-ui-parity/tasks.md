# Tasks: Frontend UI/UX Parity

**Input**: Design documents from `/specs/003-frontend-ui-parity/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Frontend**: `frontend/src/` for source, `frontend/e2e/` for E2E tests
- Components: `frontend/src/components/{area}/`
- Pages: `frontend/src/pages/`
- API clients: `frontend/src/api/`
- Types: `frontend/src/types/`
- Hooks: `frontend/src/hooks/`
- Styles: `frontend/src/styles/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Design system tokens, common components, and foundational hooks

- [x] T001 Create design tokens file in frontend/src/styles/tokens.ts
- [x] T002 Create Ant Design theme configuration in frontend/src/styles/theme.ts
- [x] T003 [P] Create ThemeContext provider in frontend/src/contexts/ThemeContext.tsx
- [x] T004 [P] Add theme configuration to App.tsx with ConfigProvider
- [x] T005 [P] Create Toast notification wrapper component in frontend/src/components/common/Toast/Toast.tsx
- [x] T006 [P] Create EmptyState component in frontend/src/components/common/EmptyState/EmptyState.tsx
- [x] T007 [P] Create ConfirmDialog component in frontend/src/components/common/ConfirmDialog/ConfirmDialog.tsx
- [x] T008 [P] Create ErrorRetry component in frontend/src/components/common/ErrorRetry/ErrorRetry.tsx
- [x] T009 Create index exports for common components in frontend/src/components/common/index.ts

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Custom hooks, API clients, and types that ALL user stories depend on

**CRITICAL**: No user story work can begin until this phase is complete

- [x] T010 Create useSessionGuard hook for session expiry handling in frontend/src/hooks/useSessionGuard.ts
- [x] T011 [P] Create useApiError hook for error handling with retry in frontend/src/hooks/useApiError.ts
- [x] T012 [P] Create useTreeLoader hook for lazy tree loading in frontend/src/hooks/useTreeLoader.ts
- [x] T013 Update hooks index exports in frontend/src/hooks/index.ts
- [x] T014 [P] Create Group type definitions in frontend/src/types/groups.ts
- [x] T015 [P] Create Permission type definitions in frontend/src/types/permissions.ts
- [x] T016 [P] Create Package type definitions in frontend/src/types/packages.ts
- [x] T017 [P] Create Build type definitions in frontend/src/types/builds.ts
- [x] T018 [P] Create Search type definitions in frontend/src/types/search.ts
- [x] T019 [P] Create TreeNode type definitions in frontend/src/types/tree.ts
- [x] T020 Update types index exports in frontend/src/types/index.ts
- [x] T021 [P] Create groups API client in frontend/src/api/groups.ts
- [x] T022 [P] Create permissions API client in frontend/src/api/permissions.ts
- [x] T023 [P] Create packages API client in frontend/src/api/packages.ts
- [x] T024 [P] Create builds API client in frontend/src/api/builds.ts
- [x] T025 [P] Create search API client in frontend/src/api/search.ts
- [x] T026 [P] Create tree API client in frontend/src/api/tree.ts
- [x] T027 [P] Create profile API client in frontend/src/api/profile.ts
- [x] T028 Update API index exports in frontend/src/api/index.ts

**Checkpoint**: Foundation ready - all types, hooks, and API clients available for user stories

---

## Phase 3: User Story 1 - Repository Browser with Artifact Management (Priority: P1) 🎯 MVP

**Goal**: Users can browse repositories, navigate folder hierarchies, view artifact details, and perform actions on artifacts

**Independent Test**: Navigate to Artifacts view, expand repository tree, select artifact, view details in tabs, download artifact

### Implementation for User Story 1

- [x] T029 [P] [US1] Create RepositoryTree component in frontend/src/components/repository/RepositoryTree/RepositoryTree.tsx
- [x] T030 [P] [US1] Create RepositoryTreeNode component in frontend/src/components/repository/RepositoryTree/RepositoryTreeNode.tsx
- [x] T031 [P] [US1] Create repository tree index exports in frontend/src/components/repository/RepositoryTree/index.ts
- [x] T032 [P] [US1] Create ArtifactList component in frontend/src/components/repository/ArtifactList/ArtifactList.tsx
- [x] T033 [P] [US1] Create ArtifactListItem component in frontend/src/components/repository/ArtifactList/ArtifactListItem.tsx
- [x] T034 [P] [US1] Create artifact list index exports in frontend/src/components/repository/ArtifactList/index.ts
- [x] T035 [P] [US1] Create ArtifactDetail component in frontend/src/components/repository/ArtifactDetail/ArtifactDetail.tsx
- [x] T036 [P] [US1] Create GeneralTab component in frontend/src/components/repository/ArtifactDetail/GeneralTab.tsx
- [x] T037 [P] [US1] Create PropertiesTab component in frontend/src/components/repository/ArtifactDetail/PropertiesTab.tsx
- [x] T038 [P] [US1] Create BuildsTab component in frontend/src/components/repository/ArtifactDetail/BuildsTab.tsx
- [x] T039 [P] [US1] Create PermissionsTab component in frontend/src/components/repository/ArtifactDetail/PermissionsTab.tsx
- [x] T040 [P] [US1] Create artifact detail index exports in frontend/src/components/repository/ArtifactDetail/index.ts
- [x] T041 [US1] Create repository components index in frontend/src/components/repository/index.ts
- [x] T042 [US1] Update Artifacts page with 3-panel browser layout in frontend/src/pages/Artifacts.tsx
- [x] T043 [US1] Add artifact download action handler in frontend/src/pages/Artifacts.tsx
- [x] T044 [US1] Add copy path action with toast notification in frontend/src/pages/Artifacts.tsx
- [x] T045 [US1] Add delete artifact action with confirmation dialog in frontend/src/pages/Artifacts.tsx

**Checkpoint**: Repository browser fully functional - can browse, view, and manage artifacts

---

## Phase 4: User Story 2 - Authentication and User Profile (Priority: P1)

**Goal**: Users can log in, manage credentials, configure MFA, manage API keys and access tokens

**Independent Test**: Log in, navigate to profile, generate API key, copy it

### Implementation for User Story 2

- [x] T046 [P] [US2] Create SSOButtons component in frontend/src/components/auth/SSOButtons/SSOButtons.tsx
- [x] T047 [P] [US2] Create MFAVerify component in frontend/src/components/auth/MFAVerify/MFAVerify.tsx
- [x] T048 [P] [US2] Create MFAEnroll component in frontend/src/components/auth/MFAEnroll/MFAEnroll.tsx
- [x] T049 [P] [US2] Create auth components index in frontend/src/components/auth/index.ts
- [x] T050 [US2] Update Login page with SSO buttons in frontend/src/pages/Login.tsx
- [x] T051 [US2] Add MFA verification flow to Login page in frontend/src/pages/Login.tsx
- [x] T052 [US2] Enhance AuthContext with MFA and SSO support in frontend/src/contexts/AuthContext.tsx
- [x] T053 [P] [US2] Create ProfileHeader component in frontend/src/components/profile/ProfileHeader/ProfileHeader.tsx
- [x] T054 [P] [US2] Create ProfileForm component in frontend/src/components/profile/ProfileForm/ProfileForm.tsx
- [x] T055 [P] [US2] Create ApiKeyManager component in frontend/src/components/profile/ApiKeyManager/ApiKeyManager.tsx
- [x] T056 [P] [US2] Create AccessTokenManager component in frontend/src/components/profile/AccessTokenManager/AccessTokenManager.tsx
- [x] T057 [P] [US2] Create profile components index in frontend/src/components/profile/index.ts
- [x] T058 [US2] Create Profile page in frontend/src/pages/Profile.tsx
- [x] T059 [US2] Add Profile route to App.tsx in frontend/src/App.tsx
- [x] T060 [US2] Add Profile link to Header component in frontend/src/components/layout/Header.tsx

**Checkpoint**: Authentication and profile management fully functional

---

## Phase 5: User Story 3 - Dashboard and Quick Actions (Priority: P2)

**Goal**: Users see dashboard with widgets, quick actions, and onboarding for new users

**Independent Test**: Log in as new user, see onboarding; log in as existing user, see dashboard widgets

### Implementation for User Story 3

- [x] T061 [P] [US3] Create DashboardWidget component in frontend/src/components/dashboard/DashboardWidget/DashboardWidget.tsx
- [x] T062 [P] [US3] Create ArtifactCountWidget in frontend/src/components/dashboard/widgets/ArtifactCountWidget.tsx
- [x] T063 [P] [US3] Create StorageSummaryWidget in frontend/src/components/dashboard/widgets/StorageSummaryWidget.tsx
- [x] T064 [P] [US3] Create RecentActivityWidget in frontend/src/components/dashboard/widgets/RecentActivityWidget.tsx
- [x] T065 [P] [US3] Create QuickActionsWidget in frontend/src/components/dashboard/widgets/QuickActionsWidget.tsx
- [x] T066 [P] [US3] Create OnboardingWizard component in frontend/src/components/dashboard/OnboardingWizard/OnboardingWizard.tsx
- [x] T067 [P] [US3] Create dashboard components index in frontend/src/components/dashboard/index.ts
- [x] T068 [US3] Update Dashboard page with new widgets layout in frontend/src/pages/Dashboard.tsx
- [x] T069 [US3] Add first-time user detection and onboarding display in frontend/src/pages/Dashboard.tsx
- [x] T070 [US3] Add quick actions dropdown functionality in frontend/src/pages/Dashboard.tsx

**Checkpoint**: Dashboard with widgets and onboarding fully functional

---

## Phase 6: User Story 4 - Search and Discovery (Priority: P2)

**Goal**: Users can search artifacts using quick search and advanced search with multiple criteria

**Independent Test**: Use quick search to find artifact, use advanced property search to filter results

### Implementation for User Story 4

- [x] T071 [P] [US4] Create QuickSearch component in frontend/src/components/search/QuickSearch/QuickSearch.tsx
- [x] T072 [P] [US4] Create QuickSearchResults component in frontend/src/components/search/QuickSearch/QuickSearchResults.tsx
- [x] T073 [P] [US4] Create quick search index in frontend/src/components/search/QuickSearch/index.ts
- [x] T074 [P] [US4] Create AdvancedSearchForm component in frontend/src/components/search/AdvancedSearch/AdvancedSearchForm.tsx
- [x] T075 [P] [US4] Create PackageSearchTab component in frontend/src/components/search/AdvancedSearch/PackageSearchTab.tsx
- [x] T076 [P] [US4] Create PropertySearchTab component in frontend/src/components/search/AdvancedSearch/PropertySearchTab.tsx
- [x] T077 [P] [US4] Create ChecksumSearchTab component in frontend/src/components/search/AdvancedSearch/ChecksumSearchTab.tsx
- [x] T078 [P] [US4] Create GAVCSearchTab component in frontend/src/components/search/AdvancedSearch/GAVCSearchTab.tsx
- [x] T079 [P] [US4] Create SearchResults component in frontend/src/components/search/SearchResults/SearchResults.tsx
- [x] T080 [P] [US4] Create search components index in frontend/src/components/search/index.ts
- [x] T081 [US4] Update Header with QuickSearch integration in frontend/src/components/layout/Header.tsx
- [x] T082 [US4] Create Search page with advanced search in frontend/src/pages/Search.tsx
- [x] T083 [US4] Add Search route to App.tsx in frontend/src/App.tsx

**Checkpoint**: Quick search and advanced search fully functional

---

## Phase 7: User Story 5 - Administration: Repository Management (Priority: P2)

**Goal**: Administrators can create, configure, and manage repositories through a wizard interface

**Independent Test**: Create a new Local Maven repository using wizard, verify it appears in tree

### Implementation for User Story 5

- [x] T084 [P] [US5] Create RepoTypeSelector component in frontend/src/components/admin/RepoWizard/RepoTypeSelector.tsx
- [x] T085 [P] [US5] Create PackageTypeSelector component in frontend/src/components/admin/RepoWizard/PackageTypeSelector.tsx
- [x] T086 [P] [US5] Create BasicConfigStep component in frontend/src/components/admin/RepoWizard/BasicConfigStep.tsx
- [x] T087 [P] [US5] Create AdvancedConfigStep component in frontend/src/components/admin/RepoWizard/AdvancedConfigStep.tsx
- [x] T088 [P] [US5] Create RemoteRepoConfig component in frontend/src/components/admin/RepoWizard/RemoteRepoConfig.tsx
- [x] T089 [P] [US5] Create VirtualRepoConfig component in frontend/src/components/admin/RepoWizard/VirtualRepoConfig.tsx
- [x] T090 [P] [US5] Create RepoWizard main component in frontend/src/components/admin/RepoWizard/RepoWizard.tsx
- [x] T091 [P] [US5] Create repo wizard index in frontend/src/components/admin/RepoWizard/index.ts
- [x] T092 [P] [US5] Create RepositoryTable component in frontend/src/components/admin/RepositoryManagement/RepositoryTable.tsx
- [x] T093 [P] [US5] Create repo management index in frontend/src/components/admin/RepositoryManagement/index.ts
- [x] T094 [US5] Update Repositories page with admin management table in frontend/src/pages/Repositories.tsx
- [x] T095 [US5] Add create repository wizard modal to Repositories page in frontend/src/pages/Repositories.tsx
- [x] T096 [US5] Add delete repository confirmation with type-to-confirm in frontend/src/pages/Repositories.tsx

**Checkpoint**: Repository management wizard fully functional

---

## Phase 8: User Story 6 - Administration: User and Access Management (Priority: P2)

**Goal**: Administrators can manage users, groups, and permissions with role-based access control

**Independent Test**: Create user, add to group, create permission target, assign group with read access

### Implementation for User Story 6

- [x] T097 [P] [US6] Create UserTable component in frontend/src/components/admin/UserManagement/UserTable.tsx
- [x] T098 [P] [US6] Create UserForm component in frontend/src/components/admin/UserManagement/UserForm.tsx
- [x] T099 [P] [US6] Create user management index in frontend/src/components/admin/UserManagement/index.ts
- [x] T100 [P] [US6] Create GroupTable component in frontend/src/components/admin/GroupManagement/GroupTable.tsx
- [x] T101 [P] [US6] Create GroupForm component in frontend/src/components/admin/GroupManagement/GroupForm.tsx
- [x] T102 [P] [US6] Create GroupMemberManager component in frontend/src/components/admin/GroupManagement/GroupMemberManager.tsx
- [x] T103 [P] [US6] Create group management index in frontend/src/components/admin/GroupManagement/index.ts
- [x] T104 [P] [US6] Create PermissionTargetTable component in frontend/src/components/admin/PermissionTargets/PermissionTargetTable.tsx
- [x] T105 [P] [US6] Create PermissionTargetWizard component in frontend/src/components/admin/PermissionTargets/PermissionTargetWizard.tsx
- [x] T106 [P] [US6] Create RepositoryPatternSelector component in frontend/src/components/admin/PermissionTargets/RepositoryPatternSelector.tsx
- [x] T107 [P] [US6] Create PermissionAssigner component in frontend/src/components/admin/PermissionTargets/PermissionAssigner.tsx
- [x] T108 [P] [US6] Create permission targets index in frontend/src/components/admin/PermissionTargets/index.ts
- [x] T109 [US6] Update Users page with enhanced management table in frontend/src/pages/Users.tsx
- [x] T110 [US6] Create Groups page in frontend/src/pages/admin/Groups.tsx
- [x] T111 [US6] Create Permissions page in frontend/src/pages/admin/Permissions.tsx
- [x] T112 [US6] Add Groups and Permissions routes to App.tsx in frontend/src/App.tsx
- [x] T113 [US6] Update Sidebar with Groups and Permissions links in frontend/src/components/layout/Sidebar.tsx

**Checkpoint**: User, group, and permission management fully functional

---

## Phase 9: User Story 7 - Packages and Builds View (Priority: P3)

**Goal**: Users can browse packages by type and view build information with diff comparison

**Independent Test**: Navigate to Packages, filter by npm, select package, view version history

### Implementation for User Story 7

- [x] T114 [P] [US7] Create PackageList component in frontend/src/components/packages/PackageList/PackageList.tsx
- [x] T115 [P] [US7] Create PackageCard component in frontend/src/components/packages/PackageList/PackageCard.tsx
- [x] T116 [P] [US7] Create PackageFilters component in frontend/src/components/packages/PackageFilters/PackageFilters.tsx
- [x] T117 [P] [US7] Create PackageDetail component in frontend/src/components/packages/PackageDetail/PackageDetail.tsx
- [x] T118 [P] [US7] Create VersionHistory component in frontend/src/components/packages/PackageDetail/VersionHistory.tsx
- [x] T119 [P] [US7] Create DependencyTree component in frontend/src/components/packages/PackageDetail/DependencyTree.tsx
- [x] T120 [P] [US7] Create packages components index in frontend/src/components/packages/index.ts
- [x] T121 [P] [US7] Create BuildList component in frontend/src/components/builds/BuildList/BuildList.tsx
- [x] T122 [P] [US7] Create BuildDetail component in frontend/src/components/builds/BuildDetail/BuildDetail.tsx
- [x] T123 [P] [US7] Create BuildDiff component in frontend/src/components/builds/BuildDiff/BuildDiff.tsx
- [x] T124 [P] [US7] Create builds components index in frontend/src/components/builds/index.ts
- [x] T125 [US7] Create Packages page in frontend/src/pages/Packages.tsx
- [x] T126 [US7] Create Builds page in frontend/src/pages/Builds.tsx
- [x] T127 [US7] Add Packages and Builds routes to App.tsx in frontend/src/App.tsx
- [x] T128 [US7] Update Sidebar with Packages and Builds links in frontend/src/components/layout/Sidebar.tsx

**Checkpoint**: Package browsing and build management fully functional

---

## Phase 10: User Story 8 - Setup Integration Wizards (Priority: P3)

**Goal**: Users can access setup wizards for package managers and CI/CD platforms

**Independent Test**: Navigate to Set Me Up, select npm, view configuration commands

### Implementation for User Story 8

- [x] T129 [P] [US8] Create PackageManagerWizard component in frontend/src/components/setup/PackageManager/PackageManagerWizard.tsx
- [x] T130 [P] [US8] Create MavenSetup component in frontend/src/components/setup/PackageManager/MavenSetup.tsx
- [x] T131 [P] [US8] Create NpmSetup component in frontend/src/components/setup/PackageManager/NpmSetup.tsx
- [x] T132 [P] [US8] Create DockerSetup component in frontend/src/components/setup/PackageManager/DockerSetup.tsx
- [x] T133 [P] [US8] Create PyPISetup component in frontend/src/components/setup/PackageManager/PyPISetup.tsx
- [x] T134 [P] [US8] Create package manager index in frontend/src/components/setup/PackageManager/index.ts
- [x] T135 [P] [US8] Create CICDPlatformWizard component in frontend/src/components/setup/CICDPlatform/CICDPlatformWizard.tsx
- [x] T136 [P] [US8] Create JenkinsSetup component in frontend/src/components/setup/CICDPlatform/JenkinsSetup.tsx
- [x] T137 [P] [US8] Create GitHubActionsSetup component in frontend/src/components/setup/CICDPlatform/GitHubActionsSetup.tsx
- [x] T138 [P] [US8] Create GitLabCISetup component in frontend/src/components/setup/CICDPlatform/GitLabCISetup.tsx
- [x] T139 [P] [US8] Create AzureDevOpsSetup component in frontend/src/components/setup/CICDPlatform/AzureDevOpsSetup.tsx
- [x] T140 [P] [US8] Create CICD platform index in frontend/src/components/setup/CICDPlatform/index.ts
- [x] T141 [P] [US8] Create setup components index in frontend/src/components/setup/index.ts
- [x] T142 [US8] Create SetupWizards page in frontend/src/pages/SetupWizards.tsx
- [x] T143 [US8] Add SetupWizards route to App.tsx in frontend/src/App.tsx
- [x] T144 [US8] Add Set Me Up link to Sidebar in frontend/src/components/layout/Sidebar.tsx

**Checkpoint**: Setup integration wizards fully functional

---

## Phase 11: User Story 9 - Visual Design System and Layout (Priority: P3)

**Goal**: Application follows Artifactory OSS visual design with dark navy sidebar, JFrog-inspired palette

**Independent Test**: Verify sidebar is dark navy (#152033), accent colors are JFrog green (#3EB065)

### Implementation for User Story 9

- [x] T145 [P] [US9] Create AppShell responsive wrapper in frontend/src/components/layout/AppShell/AppShell.tsx
- [x] T146 [P] [US9] Create app shell index in frontend/src/components/layout/AppShell/index.ts
- [x] T147 [US9] Update Sidebar with collapsible behavior in frontend/src/components/layout/Sidebar.tsx
- [x] T148 [US9] Add responsive breakpoints to Sidebar in frontend/src/components/layout/Sidebar.tsx
- [x] T149 [US9] Update Sidebar with dark navy styling per design tokens in frontend/src/components/layout/Sidebar.tsx
- [x] T150 [US9] Add hamburger menu for mobile in frontend/src/components/layout/Header.tsx
- [x] T151 [US9] Update App.tsx to use AppShell wrapper in frontend/src/App.tsx
- [x] T152 [US9] Add keyboard navigation handlers for tree and modals in frontend/src/hooks/useKeyboardNav.ts
- [x] T153 [US9] Add status color indicators throughout components in frontend/src/styles/tokens.ts

**Checkpoint**: Visual design system and responsive layout fully implemented

---

## Phase 12: User Story 10 - Error Handling and Empty States (Priority: P3)

**Goal**: Application displays error pages, empty states with illustrations, and toast notifications

**Independent Test**: Navigate to non-existent URL, see 404 page; trigger action, see toast

### Implementation for User Story 10

- [x] T154 [P] [US10] Update NotFound page with friendly illustration in frontend/src/pages/NotFound.tsx
- [x] T155 [P] [US10] Create ServerError page (500) in frontend/src/pages/errors/ServerError.tsx
- [x] T156 [P] [US10] Create Forbidden page (403) in frontend/src/pages/errors/Forbidden.tsx
- [x] T157 [P] [US10] Create errors pages index in frontend/src/pages/errors/index.ts
- [x] T158 [US10] Add error routes to App.tsx in frontend/src/App.tsx
- [x] T159 [US10] Update ErrorBoundary to redirect to error pages in frontend/src/components/ErrorBoundary.tsx
- [x] T160 [US10] Integrate toast notifications throughout all action handlers
- [x] T161 [US10] Add empty states to all list views (Artifacts, Packages, Builds, Users, Groups)

**Checkpoint**: Error handling and empty states fully implemented

---

## Phase 13: Polish & Cross-Cutting Concerns

**Purpose**: Final improvements, validation, and cleanup

- [x] T162 [P] Run TypeScript type checking and fix any errors
- [x] T163 [P] Run ESLint and fix any linting issues
- [x] T164 [P] Add accessibility attributes (aria-labels, roles) to all interactive components
- [x] T165 [P] Verify keyboard navigation works for all core workflows
- [x] T166 [P] Test responsive breakpoints at 768px, 1280px, 1920px
- [x] T167 Create E2E test for repository browser flow in frontend/e2e/repository-browser.spec.ts
- [x] T168 [P] Create E2E test for search flow in frontend/e2e/search.spec.ts
- [x] T169 [P] Create E2E test for admin workflow in frontend/e2e/admin.spec.ts
- [x] T170 Validate all user story acceptance criteria manually
- [x] T171 Run quickstart.md validation steps

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-12)**: All depend on Foundational phase completion
  - US1 and US2 are P1 priority - should complete first
  - US3-US6 are P2 priority - can run in parallel after P1
  - US7-US10 are P3 priority - can run in parallel after P2
- **Polish (Phase 13)**: Depends on all user stories being complete

### User Story Dependencies

| Story | Can Start After | Dependencies |
|-------|-----------------|--------------|
| US1 (Repository Browser) | Phase 2 | None - MVP |
| US2 (Authentication) | Phase 2 | None - can run parallel with US1 |
| US3 (Dashboard) | Phase 2 | None - can run parallel |
| US4 (Search) | Phase 2 | Needs Header from US9 for QuickSearch |
| US5 (Repo Management) | Phase 2 | Uses ConfirmDialog from Setup |
| US6 (User Management) | Phase 2 | None - can run parallel |
| US7 (Packages/Builds) | Phase 2 | None - can run parallel |
| US8 (Setup Wizards) | Phase 2 | None - can run parallel |
| US9 (Design System) | Phase 2 | Affects Sidebar used by all stories |
| US10 (Error Handling) | Phase 2 | Uses Toast/EmptyState from Setup |

### Parallel Opportunities

Within Phase 1 (Setup):
- T003, T004 can run in parallel (different files)
- T005, T006, T007, T008 can run in parallel (different component directories)

Within Phase 2 (Foundational):
- T014-T019 can run in parallel (different type files)
- T021-T027 can run in parallel (different API client files)

Within User Stories:
- All [P] marked tasks can run in parallel
- Component tasks within same story can often be parallelized
- Different user stories can be worked on in parallel by different team members

---

## Parallel Example: User Story 6 (User Management)

```bash
# Launch all component tasks in parallel:
Task: "T097 [P] [US6] Create UserTable component"
Task: "T098 [P] [US6] Create UserForm component"
Task: "T100 [P] [US6] Create GroupTable component"
Task: "T101 [P] [US6] Create GroupForm component"
Task: "T102 [P] [US6] Create GroupMemberManager component"
Task: "T104 [P] [US6] Create PermissionTargetTable component"
Task: "T105 [P] [US6] Create PermissionTargetWizard component"
Task: "T106 [P] [US6] Create RepositoryPatternSelector component"
Task: "T107 [P] [US6] Create PermissionAssigner component"
```

---

## Implementation Strategy

### MVP First (User Stories 1 + 2 Only)

1. Complete Phase 1: Setup (T001-T009)
2. Complete Phase 2: Foundational (T010-T028)
3. Complete Phase 3: User Story 1 - Repository Browser (T029-T045)
4. Complete Phase 4: User Story 2 - Authentication (T046-T060)
5. **STOP and VALIDATE**: Test repository browsing and auth independently
6. Deploy/demo if ready

### Incremental Delivery

| Increment | Stories | Value Delivered |
|-----------|---------|-----------------|
| MVP | Setup + Foundational + US1 + US2 | Core artifact browsing and auth |
| +1 | US3 + US4 | Dashboard widgets and search |
| +2 | US5 + US6 | Admin repository and user management |
| +3 | US7 + US8 | Package/build views and setup wizards |
| +4 | US9 + US10 | Design polish and error handling |
| Final | Polish | E2E tests, accessibility, validation |

### Team Parallel Strategy

With 3 developers after Foundational:
- Developer A: US1 (Repository Browser) → US5 (Repo Management) → US9 (Design System)
- Developer B: US2 (Authentication) → US6 (User Management) → US10 (Error Handling)
- Developer C: US3 (Dashboard) → US4 (Search) → US7 (Packages/Builds) → US8 (Setup Wizards)

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Total tasks: 171
- Task breakdown by phase:
  - Setup: 9 tasks
  - Foundational: 19 tasks
  - US1 (Repository Browser): 17 tasks
  - US2 (Authentication): 15 tasks
  - US3 (Dashboard): 10 tasks
  - US4 (Search): 13 tasks
  - US5 (Repo Management): 13 tasks
  - US6 (User Management): 17 tasks
  - US7 (Packages/Builds): 15 tasks
  - US8 (Setup Wizards): 16 tasks
  - US9 (Design System): 9 tasks
  - US10 (Error Handling): 8 tasks
  - Polish: 10 tasks
