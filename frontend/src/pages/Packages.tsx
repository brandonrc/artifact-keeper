import { useState, useCallback, useEffect } from 'react'
import { Layout, Spin, Typography, Empty } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { packagesApi, repositoriesApi } from '../api'
import type { Package, PackageVersion, PackageDependency, Repository } from '../types'
import { useDocumentTitle } from '../hooks'
import {
  PackageList,
  PackageFilters,
  PackageDetail,
  type ViewMode,
  type PackageFilterValue,
} from '../components/packages'
import { colors } from '../styles/tokens'

const { Sider, Content } = Layout
const { Title } = Typography

const Packages = () => {
  useDocumentTitle('Packages')

  const [searchParams, setSearchParams] = useSearchParams()

  // State for selected package
  const [selectedPackage, setSelectedPackage] = useState<Package | null>(null)

  // State for view mode
  const [viewMode, setViewMode] = useState<ViewMode>('grid')

  // State for pagination
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(24)

  // Initialize filters from URL params
  const [filters, setFilters] = useState<PackageFilterValue>(() => ({
    search: searchParams.get('search') || undefined,
    format: (searchParams.get('format') as PackageFilterValue['format']) || undefined,
    repository_id: searchParams.get('repository_id') || undefined,
    sort_by: (searchParams.get('sort_by') as PackageFilterValue['sort_by']) || undefined,
    sort_order: (searchParams.get('sort_order') as PackageFilterValue['sort_order']) || undefined,
  }))

  // Update URL when filters change
  useEffect(() => {
    const params = new URLSearchParams()
    if (filters.search) params.set('search', filters.search)
    if (filters.format) params.set('format', filters.format)
    if (filters.repository_id) params.set('repository_id', filters.repository_id)
    if (filters.sort_by) params.set('sort_by', filters.sort_by)
    if (filters.sort_order) params.set('sort_order', filters.sort_order)
    setSearchParams(params, { replace: true })
  }, [filters, setSearchParams])

  // Fetch repositories for filter dropdown
  const { data: reposData } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => repositoriesApi.list({ per_page: 100 }),
  })

  const repositories: Repository[] = reposData?.items ?? []

  // Fetch packages
  const { data: packagesData, isLoading: packagesLoading } = useQuery({
    queryKey: ['packages', filters, page, pageSize],
    queryFn: () =>
      packagesApi.list({
        page,
        per_page: pageSize,
        search: filters.search,
        format: filters.format,
        repository_key: filters.repository_id,
      }),
  })

  // Fetch package detail when a package is selected
  const { data: packageDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['package', selectedPackage?.id],
    queryFn: () => (selectedPackage ? packagesApi.get(selectedPackage.id) : null),
    enabled: !!selectedPackage,
  })

  // Fetch package versions when a package is selected
  const { data: packageVersions } = useQuery({
    queryKey: ['package-versions', selectedPackage?.id],
    queryFn: () => (selectedPackage ? packagesApi.getVersions(selectedPackage.id) : null),
    enabled: !!selectedPackage,
  })

  // Handle package selection
  const handlePackageSelect = useCallback((pkg: Package) => {
    setSelectedPackage(pkg)
  }, [])

  // Handle filter changes
  const handleFiltersChange = useCallback((newFilters: PackageFilterValue) => {
    setFilters(newFilters)
    setPage(1)
    setSelectedPackage(null)
  }, [])

  // Handle view mode change
  const handleViewModeChange = useCallback((mode: ViewMode) => {
    setViewMode(mode)
  }, [])

  // Handle pagination change
  const handlePaginationChange = useCallback((newPage: number, newPageSize: number) => {
    setPage(newPage)
    setPageSize(newPageSize)
  }, [])

  // Handle version selection
  const handleVersionSelect = useCallback((version: PackageVersion) => {
    console.log('Selected version:', version)
  }, [])

  // Handle dependency selection
  const handleDependencySelect = useCallback((dependency: PackageDependency) => {
    console.log('Selected dependency:', dependency)
  }, [])

  // Handle sort from list component
  const handleSort = useCallback(
    (field: string, order: 'ascend' | 'descend' | null) => {
      const sortByMap: Record<string, PackageFilterValue['sort_by']> = {
        name: 'name',
        total_downloads: 'downloads',
        updated_at: 'updated',
        created_at: 'created',
        version_count: 'name',
        total_size_bytes: 'name',
      }
      const sortBy = sortByMap[field] || undefined
      const sortOrder = order === 'ascend' ? 'asc' : order === 'descend' ? 'desc' : undefined

      setFilters((prev) => ({
        ...prev,
        sort_by: sortBy,
        sort_order: sortOrder,
      }))
    },
    []
  )

  const packages = packagesData?.items ?? []

  return (
    <Layout style={{ height: 'calc(100vh - 112px)', background: colors.bgLayout }}>
      {/* Left Panel: Filters and Package List */}
      <Content
        style={{
          background: colors.bgContainer,
          borderRight: selectedPackage ? `1px solid ${colors.border}` : undefined,
          overflow: 'auto',
          minWidth: 400,
          flex: 1,
        }}
      >
        <div style={{ padding: 16 }}>
          <div style={{ marginBottom: 16 }}>
            <Title level={4} style={{ margin: 0 }}>
              Packages
            </Title>
          </div>

          <PackageFilters
            value={filters}
            onChange={handleFiltersChange}
            repositories={repositories}
            loading={packagesLoading}
          />

          {packagesLoading ? (
            <div
              style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: 200,
              }}
            >
              <Spin size="large" />
            </div>
          ) : packages.length === 0 ? (
            <Empty
              description="No packages found"
              style={{ marginTop: 48 }}
            />
          ) : (
            <PackageList
              packages={packages}
              loading={packagesLoading}
              viewMode={viewMode}
              onSelect={handlePackageSelect}
              onViewModeChange={handleViewModeChange}
              onSort={handleSort}
              pagination={{
                current: page,
                pageSize,
                total: packagesData?.pagination?.total ?? 0,
                onChange: handlePaginationChange,
              }}
            />
          )}
        </div>
      </Content>

      {/* Right Panel: Package Detail */}
      {selectedPackage && (
        <Sider
          width={500}
          style={{
            background: colors.bgContainer,
            overflow: 'auto',
          }}
        >
          <PackageDetail
            package={packageDetail ?? selectedPackage}
            versions={packageVersions ?? []}
            dependencies={[]}
            loading={detailLoading}
            onVersionSelect={handleVersionSelect}
            onDependencySelect={handleDependencySelect}
          />
        </Sider>
      )}
    </Layout>
  )
}

export default Packages
