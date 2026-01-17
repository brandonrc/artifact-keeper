import { test, expect } from '@playwright/test'

test.describe('Search Functionality', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test.describe('Quick Search', () => {
    test('should display quick search in header', async ({ page }) => {
      await expect(page.getByPlaceholder('Search artifacts...')).toBeVisible()
    })

    test('should type in quick search and see dropdown', async ({ page }) => {
      const searchInput = page.getByPlaceholder('Search artifacts...')
      await searchInput.fill('app')

      await page.waitForTimeout(500)
      await expect(searchInput).toHaveValue('app')
    })

    test('should navigate to advanced search from quick search', async ({ page }) => {
      const searchInput = page.getByPlaceholder('Search artifacts...')
      await searchInput.fill('test')
      await searchInput.press('Enter')

      await expect(page).toHaveURL(/.*search.*/)
    })

    test('should clear quick search input', async ({ page }) => {
      const searchInput = page.getByPlaceholder('Search artifacts...')
      await searchInput.fill('test')
      await expect(searchInput).toHaveValue('test')

      await page.locator('.ant-input-clear-icon').first().click()
      await expect(searchInput).toHaveValue('')
    })
  })

  test.describe('Advanced Search Page', () => {
    test('should navigate to advanced search page', async ({ page }) => {
      await page.goto('/search')
      await expect(page.getByRole('heading', { name: 'Advanced Search' })).toBeVisible()
    })

    test('should display search tabs', async ({ page }) => {
      await page.goto('/search')

      await expect(page.getByRole('tab', { name: 'Package' })).toBeVisible()
      await expect(page.getByRole('tab', { name: 'Property' })).toBeVisible()
      await expect(page.getByRole('tab', { name: 'Checksum' })).toBeVisible()
      await expect(page.getByRole('tab', { name: 'GAVC' })).toBeVisible()
    })

    test('should display search button', async ({ page }) => {
      await page.goto('/search')
      await expect(page.getByRole('button', { name: /search/i })).toBeVisible()
    })
  })

  test.describe('Package Search Tab', () => {
    test('should display package search form fields', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Package' }).click()

      await expect(page.getByText('Package Name')).toBeVisible()
      await expect(page.getByText('Version')).toBeVisible()
      await expect(page.getByText('Repository')).toBeVisible()
      await expect(page.getByText('Package Format')).toBeVisible()
    })

    test('should fill package search form', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Package' }).click()

      await page.getByPlaceholder('Enter package name (supports wildcards)').fill('my-package')
      await page.getByPlaceholder('Enter version (e.g., 1.0.0, 1.*, >=2.0.0)').fill('1.0.0')

      await expect(page.getByPlaceholder('Enter package name (supports wildcards)')).toHaveValue('my-package')
      await expect(page.getByPlaceholder('Enter version (e.g., 1.0.0, 1.*, >=2.0.0)')).toHaveValue('1.0.0')
    })

    test('should submit package search', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Package' }).click()
      await page.getByPlaceholder('Enter package name (supports wildcards)').fill('app')

      await page.getByRole('button', { name: /search/i }).click()

      await expect(page).toHaveURL(/.*search.*/)
    })
  })

  test.describe('Property Search Tab', () => {
    test('should switch to property search tab', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Property' }).click()

      await expect(page.getByText('Match Type')).toBeVisible()
      await expect(page.getByText('Add property filters to search by key-value pairs')).toBeVisible()
    })

    test('should display match type selector', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Property' }).click()

      await expect(page.getByText('Exact Match')).toBeVisible()
    })

    test('should add property filter', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Property' }).click()

      await page.getByRole('button', { name: 'Add Property Filter' }).click()

      await expect(page.getByPlaceholder('Property key')).toBeVisible()
      await expect(page.getByPlaceholder('Property value')).toBeVisible()
    })

    test('should fill property filter fields', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Property' }).click()
      await page.getByRole('button', { name: 'Add Property Filter' }).click()

      await page.getByPlaceholder('Property key').fill('build.number')
      await page.getByPlaceholder('Property value').fill('123')

      await expect(page.getByPlaceholder('Property key')).toHaveValue('build.number')
      await expect(page.getByPlaceholder('Property value')).toHaveValue('123')
    })

    test('should remove property filter', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Property' }).click()
      await page.getByRole('button', { name: 'Add Property Filter' }).click()

      await expect(page.getByPlaceholder('Property key')).toBeVisible()

      await page.locator('[aria-label="minus-circle"]').click()

      await expect(page.getByPlaceholder('Property key')).not.toBeVisible()
    })
  })

  test.describe('Search Results', () => {
    test('should display results area after search', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Package' }).click()
      await page.getByPlaceholder('Enter package name (supports wildcards)').fill('test')
      await page.getByRole('button', { name: /search/i }).click()

      await page.waitForSelector('.ant-card', { state: 'visible' })
    })

    test('should preserve search query in URL', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Package' }).click()
      await page.getByPlaceholder('Enter package name (supports wildcards)').fill('myapp')
      await page.getByRole('button', { name: /search/i }).click()

      await expect(page).toHaveURL(/.*q=myapp.*/)
    })
  })

  test.describe('Checksum Search Tab', () => {
    test('should switch to checksum search tab', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'Checksum' }).click()

      await expect(page.getByText('Checksum Type')).toBeVisible()
    })
  })

  test.describe('GAVC Search Tab', () => {
    test('should switch to GAVC search tab', async ({ page }) => {
      await page.goto('/search')

      await page.getByRole('tab', { name: 'GAVC' }).click()

      await expect(page.getByText('Group ID')).toBeVisible()
      await expect(page.getByText('Artifact ID')).toBeVisible()
    })
  })
})
