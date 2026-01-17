# Feature Specification: Frontend UI/UX Parity

**Feature Branch**: `003-frontend-ui-parity`
**Created**: 2026-01-16
**Status**: Draft
**Input**: User description: "Complete frontend implementation matching Artifactory OSS UI/UX patterns"

## Clarifications

### Session 2026-01-16

- Q: What happens when session expires during an action? → A: Queue action, prompt re-login, then resume
- Q: How should the frontend handle backend API failures? → A: Show inline error with manual retry button
- Q: How should the system handle large/deep repository trees? → A: Lazy-load children on expand (one level at a time)

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Repository Browser with Artifact Management (Priority: P1)

Users need to browse repositories, navigate folder hierarchies, view artifact details, and perform actions (download, delete, copy path) on artifacts. This is the core functionality of an artifact registry.

**Why this priority**: Repository browsing is the primary user activity - without it, users cannot access or manage their artifacts.

**Independent Test**: Navigate to repository tree, expand folders, select an artifact, view its details in the right panel, and download it.

**Acceptance Scenarios**:

1. **Given** a logged-in user with read access, **When** they navigate to the Artifacts view, **Then** they see a tree of repositories in the left panel with appropriate icons for repository types (Local, Remote, Virtual, Federated).
2. **Given** a repository tree, **When** the user expands a folder, **Then** child items load and display with file/folder icons.
3. **Given** a selected artifact, **When** viewing the center panel, **Then** they see a table with Name, Size, Modified Date, and Actions columns.
4. **Given** a selected artifact, **When** viewing the right panel, **Then** they see tabs for General (path, checksums, dates), Properties (key-value metadata), Builds (associated CI/CD builds), and Effective Permissions.
5. **Given** an artifact selected, **When** clicking download, **Then** the file downloads to their device.
6. **Given** an artifact selected, **When** clicking "Copy Path", **Then** the artifact path is copied to clipboard with a success toast.

---

### User Story 2 - Authentication and User Profile (Priority: P1)

Users need to log in, manage their credentials, configure MFA, and manage their profile including API keys and access tokens.

**Why this priority**: Authentication gates access to all features; users cannot do anything without logging in.

**Independent Test**: Log in with username/password, navigate to profile, generate an API key, copy it.

**Acceptance Scenarios**:

1. **Given** the login page, **When** entering valid credentials, **Then** the user is authenticated and redirected to home/dashboard.
2. **Given** the login page, **When** entering invalid credentials, **Then** an error message displays without revealing which field is wrong.
3. **Given** a logged-in user, **When** navigating to User Profile, **Then** they can view and edit display name, email, and avatar.
4. **Given** the profile page, **When** clicking "Generate API Key", **Then** a new key is created and displayed once for copying.
5. **Given** SSO is configured, **When** on the login page, **Then** SSO provider buttons (GitHub, GitLab, Google, etc.) appear.
6. **Given** MFA is required, **When** logging in, **Then** the user is prompted for OTP after password.
7. **Given** the forgot password link, **When** clicking it, **Then** a password recovery form appears.

---

### User Story 3 - Dashboard and Quick Actions (Priority: P2)

Users see an overview dashboard on login with widgets for artifact count, storage summary, recent activity, and quick actions. First-time users see onboarding guidance.

**Why this priority**: Provides immediate value and orientation; important but not blocking core workflows.

**Independent Test**: Log in as a new user, see welcome experience and getting started guide; log in as existing user, see dashboard widgets.

**Acceptance Scenarios**:

1. **Given** a first-time user login, **When** landing on home, **Then** they see a getting started wizard with feature highlights.
2. **Given** an existing user with data, **When** on the dashboard, **Then** widgets display artifact count, storage used/available, and recent activity.
3. **Given** the dashboard, **When** clicking "Quick Actions", **Then** options to create repo or upload artifact appear.
4. **Given** no content exists, **When** viewing dashboard, **Then** an empty state with illustration and "Get Started" CTA displays.

---

### User Story 4 - Search and Discovery (Priority: P2)

Users search for artifacts using quick search from the top bar or advanced search with multiple criteria (package, property, checksum, GAVC).

**Why this priority**: Critical for finding artifacts in large repositories; enables efficient workflows.

**Independent Test**: Use quick search to find an artifact by name, then use advanced property search to filter results.

**Acceptance Scenarios**:

1. **Given** the top bar, **When** typing in the search box, **Then** instant search results appear as the user types with recent searches shown.
2. **Given** the Advanced Search page, **When** selecting "Package Search", **Then** filters for package name, version, and type appear.
3. **Given** search results, **When** viewing them, **Then** results are grouped by repository with file icons and path breadcrumbs.
4. **Given** a checksum value, **When** using Checksum Search, **Then** artifacts matching that MD5/SHA1/SHA256 are returned.
5. **Given** Maven coordinates, **When** using GAVC Search, **Then** artifacts matching Group, Artifact, Version, Classifier are found.
6. **Given** no results, **When** viewing search, **Then** an empty state with suggestions to modify the search appears.

---

### User Story 5 - Administration: Repository Management (Priority: P2)

Administrators create, configure, and manage repositories through a wizard interface supporting Local, Remote, Virtual, and Federated types with multiple package types.

**Why this priority**: Admins must set up repositories before users can store artifacts.

**Independent Test**: Create a new Local Maven repository using the wizard, configure basic settings, verify it appears in the tree.

**Acceptance Scenarios**:

1. **Given** the Admin Console, **When** navigating to Repositories, **Then** a table lists all repos with Name, Type, Package Type, Status, and Actions.
2. **Given** clicking Create Repository, **When** in Step 1, **Then** a type selector (Local/Remote/Virtual/Federated) appears with descriptions.
3. **Given** Step 2, **When** selecting package type, **Then** a grid of icons for Maven, npm, Docker, PyPI, Go, Cargo, etc. appears.
4. **Given** Step 3, **When** configuring basics, **Then** fields for Repository Key, Description, and Include/Exclude patterns appear.
5. **Given** a Remote repository, **When** in advanced config, **Then** Remote URL field and proxy settings appear.
6. **Given** a Virtual repository, **When** configuring, **Then** a list to select included repositories appears.
7. **Given** repository list, **When** clicking delete, **Then** a confirmation dialog with "type name to confirm" appears.

---

### User Story 6 - Administration: User and Access Management (Priority: P2)

Administrators manage users, groups, and permissions with role-based access control.

**Why this priority**: Security and access control are essential for multi-user environments.

**Independent Test**: Create a new user, add them to a group, create a permission target for a repository, assign the group with read access.

**Acceptance Scenarios**:

1. **Given** Users page, **When** viewing the list, **Then** columns show Username, Email, Status, Admin badge, Last login, Actions.
2. **Given** Create User form, **When** filling fields, **Then** Username, Email, Password/Auto-generate, Admin checkbox, and Groups appear.
3. **Given** Groups page, **When** creating a group, **Then** fields for name, description, auto-join, and member management appear.
4. **Given** Permissions page, **When** creating a permission target, **Then** a wizard with name, repository selection (with patterns), and user/group assignment appears.
5. **Given** permission assignment, **When** selecting actions, **Then** checkboxes for Read, Annotate, Deploy/Cache, Delete, Manage appear.
6. **Given** user profile, **When** viewing as admin, **Then** avatar, contact info, API keys, access tokens, and permission summary display.

---

### User Story 7 - Packages and Builds View (Priority: P3)

Users browse packages by type with search/filter, view package details with version history and dependencies. Users also view build information with modules and diff comparison.

**Why this priority**: Enhances discoverability but users can work with artifacts directly without this.

**Independent Test**: Navigate to Packages, filter by npm type, select a package, view its version history and dependencies.

**Acceptance Scenarios**:

1. **Given** Packages view, **When** loading, **Then** a search bar with package type selector and repository filter appears.
2. **Given** package results, **When** viewing grid/list, **Then** package name, latest version, type icon, download count, and last updated show.
3. **Given** a package selected, **When** viewing details, **Then** version history, dependency tree, and installation instructions display.
4. **Given** Builds view, **When** loading, **Then** a table with build name, number, status icon, duration, and modules count appears.
5. **Given** build detail, **When** viewing, **Then** tabs for General, Modules, Dependencies, Environment, Issues, Release History show.
6. **Given** two builds, **When** using Build Diff, **Then** added/removed dependencies and changed modules display side-by-side.

---

### User Story 8 - Setup Integration Wizards (Priority: P3)

Users access setup wizards for configuring package managers (Maven, npm, Docker, etc.) and CI/CD platforms (Jenkins, GitHub Actions, GitLab CI, Azure DevOps).

**Why this priority**: Helpful for onboarding but not required for core functionality.

**Independent Test**: Navigate to Set Me Up, select npm, view configuration commands and example publish/install commands.

**Acceptance Scenarios**:

1. **Given** Set Me Up page, **When** selecting Maven, **Then** XML configuration for settings.xml and pom.xml displays.
2. **Given** npm selected, **When** viewing, **Then** npm config commands for registry and authentication show.
3. **Given** Docker selected, **When** viewing, **Then** docker login and push/pull commands display.
4. **Given** CI/CD section, **When** selecting Jenkins, **Then** step-by-step plugin installation and configuration instructions show.
5. **Given** GitHub Actions, **When** viewing, **Then** YAML workflow template with JFrog CLI setup displays.

---

### User Story 9 - Visual Design System and Layout (Priority: P3)

The application follows the Artifactory OSS visual design with dark navy sidebar, JFrog-inspired color palette, status colors, and consistent component styling.

**Why this priority**: Important for professional appearance but doesn't block functionality.

**Independent Test**: Verify sidebar is dark navy (#152033), accent colors are JFrog green (#3EB065), and status indicators use correct colors.

**Acceptance Scenarios**:

1. **Given** the application, **When** viewing layout, **Then** dark navy sidebar, light content area, and top bar with search/profile appear.
2. **Given** sidebar, **When** interacting, **Then** it can collapse/expand with icon-only vs icon+label modes.
3. **Given** status indicators, **When** viewing, **Then** Critical=Red, High=Orange, Medium=Yellow, Low=Blue, Success=Green.
4. **Given** any page, **When** at 1280px width, **Then** sidebar becomes collapsible; at 768px, hidden with hamburger menu.
5. **Given** interactive elements, **When** using keyboard, **Then** Tab navigates, Escape closes modals, Enter submits, arrows navigate trees.

---

### User Story 10 - Error Handling and Empty States (Priority: P3)

The application displays helpful error pages (404, 500, 403), empty states with illustrations, and toast notifications for operations.

**Why this priority**: Polish feature that improves user experience but not core functionality.

**Independent Test**: Navigate to non-existent URL, see 404 page with illustration; trigger an action, see success/error toast.

**Acceptance Scenarios**:

1. **Given** a non-existent URL, **When** navigating, **Then** a 404 page with friendly illustration and home link appears.
2. **Given** a server error, **When** occurring, **Then** a 500 page with illustration and support contact displays.
3. **Given** permission denied, **When** accessing restricted area, **Then** a 403 page with explanation and admin contact shows.
4. **Given** a successful action, **When** completed, **Then** a green toast notification auto-dismisses after 5 seconds.
5. **Given** an empty repository, **When** viewing, **Then** an illustrated empty state with "Create your first artifact" CTA appears.
6. **Given** a modal for deletion, **When** deleting critical items, **Then** a confirmation dialog with warning icon and type-to-confirm appears.

---

### Edge Cases

- **Session expiration during action**: Queue the pending action, prompt user to re-login, then automatically resume the queued action after successful re-authentication
- **Deep folder hierarchies (100+ levels)**: Lazy-load children one level at a time on expand; no depth limit enforced
- What happens when file upload exceeds size limits?
- How does search handle special characters in artifact names?
- What happens when SSO provider is unavailable?
- How does the system handle concurrent edits to the same permission?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST display a collapsible sidebar with navigation sections for Artifactory, Packages, Builds, Artifacts, and Administration
- **FR-002**: System MUST support repository tree navigation with expand/collapse for folders using lazy-loading (one level at a time on expand)
- **FR-003**: System MUST display artifact details in a tabbed panel (General, Properties, Builds, Permissions)
- **FR-004**: System MUST provide artifact actions: download, delete, copy path
- **FR-005**: System MUST support username/password authentication with session management
- **FR-006**: System MUST display SSO provider buttons when configured (GitHub, GitLab, Google, Azure, Okta)
- **FR-007**: System MUST support MFA enrollment and OTP verification
- **FR-008**: System MUST provide user profile management with API key and access token generation
- **FR-009**: System MUST display dashboard widgets: artifact count, storage summary, recent activity
- **FR-010**: System MUST provide first-time user onboarding with getting started wizard
- **FR-011**: System MUST support quick search from top bar with instant results
- **FR-012**: System MUST provide advanced search: package, property, checksum, GAVC search types
- **FR-013**: System MUST provide repository creation wizard with type and package type selection
- **FR-014**: System MUST support all package types: Maven, npm, Docker, PyPI, Go, Cargo, NuGet, Helm, etc.
- **FR-015**: System MUST provide user management: create, edit, delete, disable users
- **FR-016**: System MUST provide group management with member assignment
- **FR-017**: System MUST provide permission targets with repository patterns and action levels
- **FR-018**: System MUST display packages view with search, filter, grid/list toggle
- **FR-019**: System MUST display builds view with status, duration, and diff comparison
- **FR-020**: System MUST provide setup integration wizards for package managers and CI/CD platforms
- **FR-021**: System MUST display toast notifications for success/error/warning states
- **FR-022**: System MUST display empty states with illustrations and CTAs
- **FR-023**: System MUST display error pages (404, 500, 403) with friendly illustrations
- **FR-024**: System MUST support keyboard navigation (Tab, Escape, Enter, Arrow keys)
- **FR-025**: System MUST be responsive: full sidebar at 1920px+, collapsible at 1280px, hidden at 768px
- **FR-026**: System MUST queue pending actions during session expiration, prompt re-login, and resume queued actions after re-authentication
- **FR-027**: System MUST display inline error messages with manual retry buttons when backend API calls fail

### Key Entities

- **User**: Represents authenticated users with username, email, password hash, admin flag, MFA settings
- **Group**: Collection of users for permission assignment
- **Repository**: Storage location with type (Local/Remote/Virtual/Federated) and package type
- **Artifact**: File stored in repository with path, checksums, size, timestamps, properties
- **Permission Target**: Named permission configuration linking repositories to users/groups with action levels
- **Access Token**: Scoped authentication token with expiration
- **API Key**: User-specific key for programmatic access
- **Build**: CI/CD build record with modules, dependencies, and environment
- **Package**: Versioned package entity aggregating artifacts

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can navigate to any artifact within 3 clicks from the dashboard
- **SC-002**: Repository tree loads and displays within 2 seconds for repositories with up to 10,000 items
- **SC-003**: Search results return within 1 second for repositories with up to 100,000 artifacts
- **SC-004**: 95% of new users complete the onboarding wizard
- **SC-005**: All core workflows (login, browse, search, download) are completable using keyboard only
- **SC-006**: Application renders correctly on screens from 768px to 4K resolution
- **SC-007**: Users can create a repository using the wizard in under 2 minutes
- **SC-008**: Toast notifications are visible for 5 seconds before auto-dismiss
- **SC-009**: All error states display user-friendly messages with next-step guidance
- **SC-010**: Page transitions and modals animate smoothly at 60fps

## Assumptions

- Backend APIs for all data operations already exist or will be created as part of the artifact-registry feature
- The existing React/TypeScript frontend structure will be extended
- Authentication backend supports both local auth and SSO providers
- The design system will use CSS-in-JS or Tailwind for styling
- Icons will use a consistent icon library (e.g., Lucide, Heroicons)
- The application targets modern browsers (Chrome, Firefox, Safari, Edge - latest 2 versions)
