# Quickstart: Frontend UI/UX Parity

**Feature**: 003-frontend-ui-parity
**Date**: 2026-01-16

## Prerequisites

- Node.js 18+ (LTS recommended)
- npm 9+ or pnpm 8+
- Backend server running (for API integration)
- Modern browser (Chrome, Firefox, Safari, or Edge)

## Quick Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Open browser to http://localhost:5173
```

## Development Workflow

### 1. Start Backend First

The frontend requires the backend API to be running:

```bash
# From project root
cd backend
cargo run
# API available at http://localhost:3000
```

### 2. Frontend Development

```bash
cd frontend

# Development with hot reload
npm run dev

# Run tests in watch mode
npm test

# Run E2E tests
npm run test:e2e

# Type checking
npx tsc --noEmit

# Linting
npm run lint
```

### 3. Component Development Pattern

When creating new components:

```typescript
// 1. Create component file
// frontend/src/components/common/EmptyState/EmptyState.tsx

import React from 'react';
import { Button, Result } from 'antd';
import styles from './EmptyState.module.css';

interface EmptyStateProps {
  illustration?: React.ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  illustration,
  title,
  description,
  action,
}) => (
  <Result
    icon={illustration}
    title={title}
    subTitle={description}
    extra={
      action && (
        <Button type="primary" onClick={action.onClick}>
          {action.label}
        </Button>
      )
    }
  />
);

// 2. Create index file for exports
// frontend/src/components/common/EmptyState/index.ts
export { EmptyState } from './EmptyState';
export type { EmptyStateProps } from './EmptyState';

// 3. Add test file
// frontend/src/components/common/EmptyState/EmptyState.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { EmptyState } from './EmptyState';

describe('EmptyState', () => {
  it('renders title', () => {
    render(<EmptyState title="No items" />);
    expect(screen.getByText('No items')).toBeInTheDocument();
  });

  it('calls action on button click', () => {
    const onClick = vi.fn();
    render(
      <EmptyState
        title="No items"
        action={{ label: 'Create', onClick }}
      />
    );
    fireEvent.click(screen.getByText('Create'));
    expect(onClick).toHaveBeenCalled();
  });
});
```

### 4. API Client Pattern

When adding new API endpoints:

```typescript
// frontend/src/api/groups.ts
import { client } from './client';
import type { Group, GroupDetail, CreateGroupRequest, PaginatedResponse } from '../types';

export const groupsApi = {
  list: (params?: { page?: number; per_page?: number; search?: string }) =>
    client.get<PaginatedResponse<Group>>('/groups', { params }),

  get: (groupId: string) =>
    client.get<GroupDetail>(`/groups/${groupId}`),

  create: (data: CreateGroupRequest) =>
    client.post<Group>('/groups', data),

  update: (groupId: string, data: Partial<CreateGroupRequest>) =>
    client.put<Group>(`/groups/${groupId}`, data),

  delete: (groupId: string) =>
    client.delete(`/groups/${groupId}`),

  addMembers: (groupId: string, userIds: string[]) =>
    client.post(`/groups/${groupId}/members`, { user_ids: userIds }),

  removeMembers: (groupId: string, userIds: string[]) =>
    client.delete(`/groups/${groupId}/members`, { data: { user_ids: userIds } }),
};
```

### 5. Using TanStack Query

```typescript
// In a component
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { groupsApi } from '../api/groups';

function GroupList() {
  const queryClient = useQueryClient();

  // Fetch groups
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['groups'],
    queryFn: () => groupsApi.list(),
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: groupsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groups'] });
    },
  });

  // With error retry pattern
  if (error) {
    return (
      <ErrorRetry error={error} onRetry={refetch}>
        <GroupListContent data={data} />
      </ErrorRetry>
    );
  }

  return <GroupListContent data={data} isLoading={isLoading} />;
}
```

## Directory Structure

```
frontend/src/
├── api/                    # API clients
│   ├── client.ts           # Axios instance
│   ├── groups.ts           # Groups API
│   ├── permissions.ts      # Permissions API
│   └── search.ts           # Search API
├── components/
│   ├── common/             # Shared components
│   │   ├── EmptyState/
│   │   ├── ErrorRetry/
│   │   ├── ConfirmDialog/
│   │   └── Toast/
│   ├── layout/             # Layout components
│   │   ├── Sidebar.tsx
│   │   ├── Header.tsx
│   │   └── AppShell.tsx
│   ├── repository/         # Repository browser
│   │   ├── RepositoryTree/
│   │   ├── ArtifactList/
│   │   └── ArtifactDetail/
│   ├── search/             # Search components
│   ├── admin/              # Admin console
│   └── setup/              # Integration wizards
├── pages/                  # Route pages
├── hooks/                  # Custom hooks
├── contexts/               # React contexts
├── styles/                 # Design system
│   ├── tokens.ts           # Design tokens
│   └── theme.ts            # Ant Design theme
└── types/                  # TypeScript types
```

## Design System

### Color Tokens

```typescript
// frontend/src/styles/tokens.ts
export const designTokens = {
  // Primary palette (JFrog-inspired)
  colorPrimary: '#3EB065',      // JFrog Green
  colorPrimaryHover: '#7CCF83', // Lighter green

  // Background
  colorBgContainer: '#F9FFF9',  // Light green tint
  siderBg: '#152033',           // Dark navy sidebar

  // Status colors
  colorSuccess: '#3EB065',      // Green
  colorError: '#FF4D4F',        // Red (critical)
  colorWarning: '#FAAD14',      // Orange (high)
  colorInfo: '#1677FF',         // Blue (low)

  // Severity mapping
  severity: {
    critical: '#FF4D4F',
    high: '#FA8C16',
    medium: '#FADB14',
    low: '#1677FF',
    ok: '#3EB065',
  },
};
```

### Using Theme

```typescript
// frontend/src/styles/theme.ts
import { ThemeConfig } from 'antd';
import { designTokens } from './tokens';

export const antdTheme: ThemeConfig = {
  token: {
    colorPrimary: designTokens.colorPrimary,
    colorSuccess: designTokens.colorSuccess,
    colorError: designTokens.colorError,
    colorWarning: designTokens.colorWarning,
    colorInfo: designTokens.colorInfo,
    colorBgContainer: designTokens.colorBgContainer,
  },
  components: {
    Layout: {
      siderBg: designTokens.siderBg,
    },
  },
};

// In App.tsx
import { ConfigProvider } from 'antd';
import { antdTheme } from './styles/theme';

function App() {
  return (
    <ConfigProvider theme={antdTheme}>
      {/* App content */}
    </ConfigProvider>
  );
}
```

## Testing

### Unit Tests

```bash
# Run all tests
npm test

# Watch mode
npm test -- --watch

# Coverage report
npm run test:coverage

# Specific file
npm test -- EmptyState
```

### E2E Tests

```bash
# Run Playwright tests
npm run test:e2e

# Interactive UI mode
npm run test:e2e:ui

# Headed mode (see browser)
npm run test:e2e:headed

# Specific test file
npx playwright test auth.spec.ts
```

### Test Patterns

```typescript
// Unit test with MSW mock
import { rest } from 'msw';
import { setupServer } from 'msw/node';

const server = setupServer(
  rest.get('/api/v1/groups', (req, res, ctx) => {
    return res(ctx.json({
      items: [{ id: '1', name: 'Developers' }],
      pagination: { page: 1, total: 1 }
    }));
  })
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// E2E test
import { test, expect } from '@playwright/test';

test('create group', async ({ page }) => {
  await page.goto('/admin/groups');
  await page.click('button:has-text("Create Group")');
  await page.fill('input[name="name"]', 'Test Group');
  await page.click('button:has-text("Save")');
  await expect(page.locator('text=Test Group')).toBeVisible();
});
```

## Common Tasks

### Add a New Page

1. Create page component in `src/pages/`
2. Add route in `src/App.tsx`
3. Add sidebar menu item in `src/components/layout/Sidebar.tsx`
4. Add E2E test in `frontend/e2e/`

### Add API Endpoint

1. Create/update API client in `src/api/`
2. Add types in `src/types/`
3. Add MSW handler in `src/test/mocks/handlers.ts`
4. Use in component with TanStack Query

### Add Design Token

1. Add to `src/styles/tokens.ts`
2. Reference in `src/styles/theme.ts` if for Ant Design
3. Use via theme or direct import

## Troubleshooting

### API Connection Issues

```bash
# Check backend is running
curl http://localhost:3000/health

# Check CORS in vite.config.ts
export default defineConfig({
  server: {
    proxy: {
      '/api': 'http://localhost:3000'
    }
  }
});
```

### Type Errors

```bash
# Regenerate types
npx tsc --noEmit

# Check for missing types
npm install -D @types/react @types/react-dom
```

### Test Failures

```bash
# Clear test cache
npm test -- --clearCache

# Update snapshots
npm test -- -u
```

## Resources

- [Ant Design Components](https://ant.design/components/overview)
- [TanStack Query Docs](https://tanstack.com/query/latest)
- [React Router v7](https://reactrouter.com/)
- [Playwright Testing](https://playwright.dev/)
- [Vitest Testing](https://vitest.dev/)
