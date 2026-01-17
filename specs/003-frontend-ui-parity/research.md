# Research: Frontend UI/UX Parity

**Feature**: 003-frontend-ui-parity
**Date**: 2026-01-16
**Status**: Complete

## Executive Summary

Research confirms the existing tech stack (React 19, TypeScript 5, Ant Design 6, TanStack Query 5) is well-suited for implementing Artifactory-style UI/UX. Key decisions focus on design system customization, tree virtualization, and session management patterns.

---

## Technology Decisions

### 1. Design System Approach

**Decision**: Customize Ant Design theme with CSS variables for Artifactory-inspired palette

**Rationale**:
- Ant Design 6.x supports ConfigProvider with token-based theming
- CSS custom properties enable runtime theme switching (future dark mode)
- Avoids maintaining custom component library
- Consistent with existing codebase patterns

**Alternatives Considered**:
| Option | Rejected Because |
|--------|------------------|
| Tailwind CSS | Would require rewriting existing Ant Design components |
| Custom component library | Maintenance overhead, duplicates Ant Design effort |
| CSS-in-JS (Emotion/styled-components) | Ant Design already uses cssinjs internally |

**Implementation**:
```typescript
// styles/tokens.ts
export const designTokens = {
  colorPrimary: '#3EB065', // JFrog Green
  colorBgContainer: '#F9FFF9',
  siderBg: '#152033', // Dark navy sidebar
  colorSuccess: '#3EB065',
  colorError: '#FF4D4F',
  colorWarning: '#FAAD14',
  colorInfo: '#1677FF',
}
```

---

### 2. Repository Tree Component

**Decision**: Use Ant Design Tree with custom async data loading (lazy-load on expand)

**Rationale**:
- Ant Design Tree supports loadData prop for async children
- Native virtualization via Tree's height and virtual props
- Matches spec requirement: "lazy-load children one level at a time"
- Performance target: 2s load for 10,000 items achievable with virtual scrolling

**Alternatives Considered**:
| Option | Rejected Because |
|--------|------------------|
| react-arborist | Additional dependency, less Ant Design integration |
| Custom tree implementation | Significant development effort |
| react-window + custom | Reinventing what Ant Design Tree provides |

**Implementation Pattern**:
```typescript
const loadTreeData = async (node: TreeNode): Promise<TreeNode[]> => {
  const children = await api.getChildren(node.key);
  return children.map(child => ({
    key: child.path,
    title: child.name,
    isLeaf: child.type === 'file',
    icon: getIcon(child),
  }));
};
```

---

### 3. Session Expiration Handling

**Decision**: Queue pending action, show re-login modal, resume after authentication

**Rationale**:
- Matches clarified spec requirement
- Preserves user work (unsaved form data, pending uploads)
- Standard UX pattern for enterprise applications

**Implementation Pattern**:
```typescript
// hooks/useSessionGuard.ts
const useSessionGuard = () => {
  const [pendingAction, setPendingAction] = useState<() => Promise<void>>();
  const [showRelogin, setShowRelogin] = useState(false);

  const executeWithGuard = async (action: () => Promise<void>) => {
    try {
      await action();
    } catch (error) {
      if (isSessionExpired(error)) {
        setPendingAction(() => action);
        setShowRelogin(true);
      } else {
        throw error;
      }
    }
  };

  const onReloginSuccess = async () => {
    setShowRelogin(false);
    if (pendingAction) {
      await pendingAction();
      setPendingAction(undefined);
    }
  };

  return { executeWithGuard, showRelogin, onReloginSuccess };
};
```

---

### 4. API Error Handling Pattern

**Decision**: Inline error display with manual retry button using TanStack Query

**Rationale**:
- Matches clarified spec requirement
- TanStack Query provides built-in retry and refetch capabilities
- Inline errors maintain context (user sees what failed)
- Manual retry gives user control

**Implementation Pattern**:
```typescript
// components/common/ErrorRetry.tsx
const ErrorRetry = ({ error, onRetry, children }) => {
  if (error) {
    return (
      <Alert
        type="error"
        message={error.message}
        action={<Button onClick={onRetry}>Retry</Button>}
      />
    );
  }
  return children;
};

// Usage with TanStack Query
const { data, error, refetch, isLoading } = useQuery({ queryKey, queryFn });
return (
  <ErrorRetry error={error} onRetry={refetch}>
    <ComponentContent data={data} />
  </ErrorRetry>
);
```

---

### 5. Collapsible Sidebar Implementation

**Decision**: Enhance existing Ant Design Sider with collapsible prop and responsive breakpoints

**Rationale**:
- Ant Design Sider supports collapsible, collapsedWidth, and breakpoint props
- Matches spec: full at 1920px+, collapsible at 1280px, hidden at 768px
- Existing Sidebar.tsx can be enhanced without rewrite

**Implementation Pattern**:
```typescript
<Sider
  collapsible
  collapsed={collapsed}
  onCollapse={setCollapsed}
  breakpoint="lg" // 992px triggers collapse
  collapsedWidth={80} // Icon-only mode
  trigger={null} // Custom trigger in header
/>
```

---

### 6. Search Implementation

**Decision**: Debounced quick search (300ms) + dedicated advanced search page

**Rationale**:
- Quick search in header provides instant feedback
- Advanced search page for complex queries (GAVC, checksum, properties)
- 300ms debounce balances responsiveness with API load
- Matches Artifactory pattern

**Alternatives Considered**:
| Option | Rejected Because |
|--------|------------------|
| No debounce | Excessive API calls, poor performance |
| Single search interface | Complex UI, harder to use |
| Server-side search only | No instant feedback |

---

### 7. Multi-Step Wizard Pattern

**Decision**: Use Ant Design Steps component with form state management

**Rationale**:
- Steps component provides visual progress indicator
- Form state persists across steps
- Matches spec for repository creation wizard (4 steps)
- Consistent with Artifactory wizard UX

**Implementation Pattern**:
```typescript
const [currentStep, setCurrentStep] = useState(0);
const [formData, setFormData] = useState<WizardFormData>({});

const steps = [
  { title: 'Type', content: <SelectRepoType /> },
  { title: 'Package', content: <SelectPackageType /> },
  { title: 'Config', content: <BasicConfig /> },
  { title: 'Advanced', content: <AdvancedConfig /> },
];
```

---

### 8. Toast Notification System

**Decision**: Use Ant Design message/notification APIs with custom styling

**Rationale**:
- Ant Design provides message (lightweight) and notification (rich) APIs
- Auto-dismiss after 5 seconds (spec requirement)
- Position top-right for consistency with Artifactory
- Clickable for details via notification API

**Implementation Pattern**:
```typescript
// Lightweight toasts
message.success('Artifact downloaded');
message.error('Upload failed');

// Rich notifications with actions
notification.error({
  message: 'API Error',
  description: error.message,
  btn: <Button onClick={() => refetch()}>Retry</Button>,
  duration: 5,
});
```

---

### 9. Empty State Components

**Decision**: Create reusable EmptyState component with illustration slots

**Rationale**:
- Consistent empty state UX across all views
- Illustrations add visual appeal (matches Artifactory frog mascot style)
- CTA buttons drive user action
- Reusable pattern reduces code duplication

**Implementation Pattern**:
```typescript
interface EmptyStateProps {
  illustration?: React.ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

const EmptyState: React.FC<EmptyStateProps> = ({
  illustration = <DefaultIllustration />,
  title,
  description,
  action,
}) => (
  <div className="empty-state">
    {illustration}
    <h3>{title}</h3>
    {description && <p>{description}</p>}
    {action && <Button type="primary" onClick={action.onClick}>{action.label}</Button>}
  </div>
);
```

---

### 10. Accessibility Implementation

**Decision**: Follow WCAG 2.1 AA using Ant Design's built-in a11y + custom enhancements

**Rationale**:
- Ant Design components are largely WCAG compliant
- Add focus management for modals and tree navigation
- Ensure color contrast meets AA standards (4.5:1 ratio)
- Test with keyboard-only navigation

**Key Enhancements**:
- Focus trap in modals
- Arrow key navigation in tree
- Screen reader announcements for async operations
- Alt text for all icons (decorative marked as aria-hidden)

---

## Integration Patterns

### API Client Pattern

Extend existing Axios-based API clients with new endpoints:

```typescript
// api/search.ts
export const searchApi = {
  quickSearch: (query: string) =>
    client.get('/api/v1/search', { params: { q: query } }),

  advancedSearch: (params: AdvancedSearchParams) =>
    client.post('/api/v1/search/advanced', params),

  checksumSearch: (checksum: string, algorithm: 'md5' | 'sha1' | 'sha256') =>
    client.get('/api/v1/search/checksum', { params: { checksum, algorithm } }),
};
```

### State Management

Continue using TanStack Query for server state, React Context for UI state:

- **Server state**: TanStack Query (repositories, artifacts, users, search results)
- **UI state**: React Context (theme, sidebar collapsed, current user)
- **Form state**: React Hook Form or Ant Design Form (local to components)

---

## Performance Considerations

1. **Tree virtualization**: Enable virtual scrolling for trees > 100 nodes
2. **Search debouncing**: 300ms debounce on quick search input
3. **Code splitting**: Lazy load admin pages and setup wizards
4. **Image optimization**: Use SVG for icons, optimize illustrations
5. **Bundle size**: Tree-shake Ant Design imports

---

## Dependencies to Add

No new dependencies required. Existing stack sufficient:
- Ant Design Tree (virtualization built-in)
- Ant Design Steps (wizard pattern)
- Ant Design notification/message (toasts)
- TanStack Query (data fetching, caching, retry)

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Ant Design Tree perf for 10k+ nodes | High | Enable virtual scrolling, test with load |
| Session resumption complexity | Medium | Implement in AuthContext, thorough testing |
| Accessibility gaps in custom components | Medium | Audit with axe-core, keyboard testing |
| API contract drift | Medium | Define contracts in OpenAPI, contract tests |

---

## Conclusion

The existing tech stack is well-suited for this implementation. Key focus areas:
1. Design system tokens for Artifactory styling
2. Lazy-loading tree for repository browser
3. Session guard hook for expiration handling
4. Inline error retry pattern for API failures

No technology changes or new major dependencies required.
