import { useState, useCallback, useMemo } from 'react'
import { Layout, Spin, Typography, Space, Input, Select, DatePicker, Button, Empty } from 'antd'
import { SearchOutlined, SwapOutlined, CloseOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { buildsApi } from '../api'
import type { Build, BuildDetail as BuildDetailType, BuildStatus, BuildSummary, BuildDiff as BuildDiffType } from '../types'
import { useDocumentTitle } from '../hooks'
import { BuildList, BuildDetail, BuildDiff } from '../components/builds'
import { colors, spacing, borderRadius } from '../styles/tokens'

const { Sider, Content } = Layout
const { Title } = Typography
const { RangePicker } = DatePicker

type DateRange = [string | undefined, string | undefined]

interface BuildFilters {
  search?: string
  status?: BuildStatus
  dateRange?: DateRange
}

const statusOptions: { value: BuildStatus; label: string }[] = [
  { value: 'success', label: 'Success' },
  { value: 'failed', label: 'Failed' },
  { value: 'running', label: 'Running' },
  { value: 'pending', label: 'Pending' },
  { value: 'cancelled', label: 'Cancelled' },
  { value: 'unstable', label: 'Unstable' },
]

const Builds = () => {
  useDocumentTitle('Builds')

  // State for selected build
  const [selectedBuild, setSelectedBuild] = useState<Build | null>(null)

  // State for comparison mode
  const [comparisonMode, setComparisonMode] = useState(false)
  const [compareBuild, setCompareBuild] = useState<Build | null>(null)

  // State for filters
  const [filters, setFilters] = useState<BuildFilters>({})

  // State for pagination
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  // Fetch builds
  const { data: buildsData, isLoading: buildsLoading } = useQuery({
    queryKey: ['builds', filters, page, pageSize],
    queryFn: () =>
      buildsApi.list({
        page,
        per_page: pageSize,
        search: filters.search,
        status: filters.status,
        sort_by: 'build_number',
        sort_order: 'desc',
      }),
  })

  // Fetch build detail when a build is selected
  const { data: buildDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['build', selectedBuild?.id],
    queryFn: () => (selectedBuild ? buildsApi.get(selectedBuild.id) : null),
    enabled: !!selectedBuild && !comparisonMode,
  })

  // Fetch build diff when in comparison mode
  const { data: buildDiff, isLoading: diffLoading } = useQuery({
    queryKey: ['build-diff', compareBuild?.id, selectedBuild?.id],
    queryFn: () =>
      compareBuild && selectedBuild
        ? buildsApi.diff(compareBuild.id, selectedBuild.id)
        : null,
    enabled: !!compareBuild && !!selectedBuild && comparisonMode,
  })

  // Handle build selection
  const handleBuildSelect = useCallback(
    (build: Build) => {
      if (comparisonMode && selectedBuild) {
        setCompareBuild(selectedBuild)
        setSelectedBuild(build)
      } else {
        setSelectedBuild(build)
        setCompareBuild(null)
      }
    },
    [comparisonMode, selectedBuild]
  )

  // Handle compare action from detail view
  const handleCompare = useCallback((build: BuildDetailType) => {
    setComparisonMode(true)
    setCompareBuild(null)
  }, [])

  // Exit comparison mode
  const handleExitComparison = useCallback(() => {
    setComparisonMode(false)
    setCompareBuild(null)
  }, [])

  // Handle filter changes
  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setFilters((prev) => ({ ...prev, search: e.target.value || undefined }))
    setPage(1)
  }, [])

  const handleStatusChange = useCallback((status: BuildStatus | undefined) => {
    setFilters((prev) => ({ ...prev, status }))
    setPage(1)
  }, [])

  const handleDateRangeChange = useCallback(
    (dates: unknown, dateStrings: [string, string]) => {
      setFilters((prev) => ({
        ...prev,
        dateRange: dateStrings[0] ? [dateStrings[0], dateStrings[1]] : undefined,
      }))
      setPage(1)
    },
    []
  )

  const handleClearFilters = useCallback(() => {
    setFilters({})
    setPage(1)
  }, [])

  // Handle pagination change
  const handlePaginationChange = useCallback((newPage: number, newPageSize: number) => {
    setPage(newPage)
    setPageSize(newPageSize)
  }, [])

  const builds = buildsData?.items ?? []

  const hasFilters = filters.search || filters.status || filters.dateRange

  // Convert Build to BuildSummary for diff component
  const buildToSummary = useCallback((build: Build): BuildSummary => ({
    id: build.id,
    build_number: build.build_number,
    project_name: build.project_name,
    status: build.status,
    completed_at: build.completed_at,
    commit_sha: build.commit_sha,
    branch: build.branch,
  }), [])

  // Create mock diff result when API returns data in different format
  const diffResult: BuildDiffType | null = useMemo(() => {
    if (!buildDiff || !compareBuild || !selectedBuild) return null

    return {
      from_build: buildToSummary(compareBuild),
      to_build: buildToSummary(selectedBuild),
      module_diffs: buildDiff.module_diffs ?? [],
      added_dependencies: buildDiff.added_dependencies ?? [],
      removed_dependencies: buildDiff.removed_dependencies ?? [],
      changed_dependencies: buildDiff.changed_dependencies ?? [],
      added_issues: buildDiff.added_issues ?? [],
      resolved_issues: buildDiff.resolved_issues ?? [],
    }
  }, [buildDiff, compareBuild, selectedBuild, buildToSummary])

  return (
    <Layout style={{ height: 'calc(100vh - 112px)', background: colors.bgLayout }}>
      {/* Left Panel: Build List with Filters */}
      <Content
        style={{
          background: colors.bgContainer,
          borderRight: selectedBuild ? `1px solid ${colors.border}` : undefined,
          overflow: 'auto',
          minWidth: 500,
          flex: 1,
        }}
      >
        <div style={{ padding: spacing.md }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: spacing.md,
            }}
          >
            <Title level={4} style={{ margin: 0 }}>
              Builds
            </Title>
            {comparisonMode && (
              <Button
                type="primary"
                icon={<CloseOutlined />}
                onClick={handleExitComparison}
              >
                Exit Comparison Mode
              </Button>
            )}
          </div>

          {comparisonMode && (
            <div
              style={{
                background: colors.bgLayout,
                padding: spacing.sm,
                borderRadius: borderRadius.md,
                marginBottom: spacing.md,
              }}
            >
              <Space>
                <SwapOutlined style={{ color: colors.primary }} />
                <Typography.Text>
                  {compareBuild
                    ? `Comparing ${compareBuild.project_name} #${compareBuild.build_number} with ${selectedBuild?.project_name} #${selectedBuild?.build_number}`
                    : 'Select another build to compare'}
                </Typography.Text>
              </Space>
            </div>
          )}

          {/* Filters */}
          <div
            style={{
              background: colors.bgLayout,
              padding: spacing.md,
              borderRadius: borderRadius.lg,
              marginBottom: spacing.md,
            }}
          >
            <Space wrap size="middle" style={{ width: '100%' }}>
              <Input
                placeholder="Search builds..."
                prefix={<SearchOutlined />}
                value={filters.search}
                onChange={handleSearchChange}
                allowClear
                style={{ width: 240 }}
              />

              <Select
                placeholder="Status"
                value={filters.status}
                onChange={handleStatusChange}
                allowClear
                options={statusOptions}
                style={{ width: 140 }}
              />

              <RangePicker
                onChange={handleDateRangeChange}
                style={{ width: 260 }}
              />

              {hasFilters && (
                <Button type="link" onClick={handleClearFilters}>
                  Clear filters
                </Button>
              )}
            </Space>
          </div>

          {/* Build List */}
          {buildsLoading ? (
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
          ) : builds.length === 0 ? (
            <Empty
              description="No builds found"
              style={{ marginTop: 48 }}
            />
          ) : (
            <BuildList
              builds={builds}
              loading={buildsLoading}
              onSelect={handleBuildSelect}
              pagination={{
                current: page,
                pageSize,
                total: buildsData?.pagination?.total ?? 0,
                onChange: handlePaginationChange,
              }}
            />
          )}
        </div>
      </Content>

      {/* Right Panel: Build Detail or Diff */}
      {selectedBuild && (
        <Sider
          width={600}
          style={{
            background: colors.bgContainer,
            overflow: 'auto',
          }}
        >
          {comparisonMode && compareBuild && diffResult ? (
            diffLoading ? (
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
            ) : (
              <BuildDiff
                buildA={diffResult.from_build}
                buildB={diffResult.to_build}
                diffResult={diffResult}
              />
            )
          ) : detailLoading ? (
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
          ) : buildDetail ? (
            <BuildDetail
              build={buildDetail}
              onCompare={handleCompare}
            />
          ) : (
            <BuildDetail
              build={{
                ...selectedBuild,
                modules: [],
                all_dependencies: [],
                all_issues: [],
                environment: {},
              } as BuildDetailType}
              onCompare={handleCompare}
            />
          )}
        </Sider>
      )}
    </Layout>
  )
}

export default Builds
