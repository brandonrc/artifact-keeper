import { test, expect } from '@playwright/test'

test.describe('Repository Browser', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test('should navigate to repositories page', async ({ page }) => {
    await page.getByRole('link', { name: 'Repositories' }).click()
    await expect(page).toHaveURL('/repositories')
    await expect(page.getByRole('heading', { name: 'Repositories' })).toBeVisible()
  })

  test('should display repository list with data', async ({ page }) => {
    await page.goto('/repositories')

    await expect(page.getByRole('table')).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Key' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Name' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Format' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Type' })).toBeVisible()
  })

  test('should click on a repository to view details', async ({ page }) => {
    await page.goto('/repositories')

    await page.getByRole('button', { name: 'View' }).first().click()

    await expect(page.getByText('Repository Details')).toBeVisible()
    await expect(page.getByText('Key')).toBeVisible()
    await expect(page.getByText('Format')).toBeVisible()
    await expect(page.getByText('Type')).toBeVisible()
  })

  test('should browse artifacts in the repository', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await expect(page.getByText('Artifacts')).toBeVisible()

    await expect(page.getByRole('columnheader', { name: 'Name' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Path' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Size' })).toBeVisible()
  })

  test('should search artifacts within repository', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.getByPlaceholder('Search artifacts...').fill('app')
    await page.getByPlaceholder('Search artifacts...').press('Enter')

    await expect(page.getByPlaceholder('Search artifacts...')).toHaveValue('app')
  })

  test('should open artifact details modal', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.getByRole('button', { name: 'Details' }).first().click()

    await expect(page.getByText('Artifact Details')).toBeVisible()
    await expect(page.getByText('SHA-256 Checksum')).toBeVisible()
    await expect(page.getByText('Download URL')).toBeVisible()
  })

  test('should test artifact download action', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.getByRole('button', { name: 'Details' }).first().click()

    await expect(page.getByRole('button', { name: /download/i })).toBeVisible()
    await expect(page.getByRole('button', { name: /download/i })).toBeEnabled()
  })

  test('should test copy path action in artifact detail', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.getByRole('button', { name: 'Details' }).first().click()

    await expect(page.getByText('Artifact Details')).toBeVisible()
    await expect(page.locator('[aria-label="copy"]').first()).toBeVisible()
  })

  test('should download artifact from table action', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await expect(page.getByRole('button', { name: /download/i }).first()).toBeVisible()
  })

  test('should display breadcrumb navigation', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await expect(page.locator('.ant-breadcrumb')).toBeVisible()
    await expect(page.locator('.ant-breadcrumb').getByText('Repositories')).toBeVisible()
  })

  test('should navigate back via breadcrumb', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.locator('.ant-breadcrumb').getByText('Repositories').click()

    await expect(page).toHaveURL('/repositories')
  })

  test('should navigate back via back button', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.getByRole('button', { name: 'Back to Repositories' }).click()

    await expect(page).toHaveURL('/repositories')
  })

  test('should display repository storage information', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await expect(page.getByText('Storage Used')).toBeVisible()
  })

  test('should show upload artifact button', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await expect(page.getByRole('button', { name: 'Upload Artifact' })).toBeVisible()
  })

  test('should close artifact detail modal', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.getByRole('button', { name: 'Details' }).first().click()
    await expect(page.getByText('Artifact Details')).toBeVisible()

    await page.getByRole('button', { name: 'Close' }).click()
    await expect(page.getByText('Artifact Details')).not.toBeVisible()
  })
})
