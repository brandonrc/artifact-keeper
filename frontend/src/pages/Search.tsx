import { useState, useCallback } from 'react'
import { Card, Typography, message, Form } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { searchApi, artifactsApi } from '../api'
import { useDocumentTitle } from '../hooks'
import {
  AdvancedSearchForm,
  SearchResults,
  type AdvancedSearchValues,
  type SearchTabType,
  type ViewMode,
  type SortField,
  type SortOrder,
} from '../components/search'
import type { ArtifactSearchHit } from '../types'

const { Title } = Typography

const Search = () => {
  useDocumentTitle('Search')
  const [searchParams, setSearchParams] = useSearchParams()
  const [form] = Form.useForm()

  // Search state
  const [searchValues, setSearchValues] = useState<AdvancedSearchValues | null>(null)
  const [activeTab, setActiveTab] = useState<SearchTabType>('package')

  // View state
  const [viewMode, setViewMode] = useState<ViewMode>('list')
  const [sortField, setSortField] = useState<SortField>('created_at')
  const [sortOrder, setSortOrder] = useState<SortOrder>('descend')

  // Pagination state
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  // Get initial query from URL
  const urlQuery = searchParams.get('q')
  const urlTab = searchParams.get('tab') as SearchTabType | null

  // Search query
  const { data: searchResults, isLoading, isFetching } = useQuery({
    queryKey: ['advanced-search', searchValues, page, pageSize, sortField, sortOrder],
    queryFn: async () => {
      if (!searchValues) return null

      // Build search request based on active tab
      const request: Parameters<typeof searchApi.advanced>[0] = {
        page,
        per_page: pageSize,
      }

      switch (searchValues.searchType) {
        case 'package':
          if (searchValues.packageName) request.query = searchValues.packageName
          if (searchValues.repository) request.repository_key = searchValues.repository
          if (searchValues.format) request.format = searchValues.format
          break
        case 'property':
          if (searchValues.properties?.length) {
            request.properties = searchValues.properties.reduce((acc, prop) => {
              if (prop.key && prop.value) {
                acc[prop.key] = prop.value
              }
              return acc
            }, {} as Record<string, string>)
          }
          break
        case 'checksum':
          if (searchValues.checksum) {
            request.checksum = searchValues.checksum
            request.checksum_type = searchValues.checksumType
          }
          break
        case 'gavc':
          if (searchValues.groupId) request.group_id = searchValues.groupId
          if (searchValues.artifactId) request.artifact_id = searchValues.artifactId
          if (searchValues.version) request.version = searchValues.version
          if (searchValues.classifier) request.classifier = searchValues.classifier
          break
      }

      return searchApi.advanced(request)
    },
    enabled: !!searchValues,
  })

  // Handle search form submit
  const handleSearch = useCallback((values: AdvancedSearchValues) => {
    setSearchValues(values)
    setPage(1)

    // Update URL with search query
    const params = new URLSearchParams()
    if (values.packageName) params.set('q', values.packageName)
    if (values.searchType) params.set('tab', values.searchType)
    setSearchParams(params)
  }, [setSearchParams])

  // Handle result selection
  const handleSelect = useCallback((result: ArtifactSearchHit) => {
    // Navigate to artifact detail - handled by SearchResults component
  }, [])

  // Handle download
  const handleDownload = useCallback((result: ArtifactSearchHit) => {
    const url = artifactsApi.getDownloadUrl(result.repository_key, result.path)
    window.open(url, '_blank')
    message.success('Download started')
  }, [])

  // Handle pagination change
  const handlePaginationChange = useCallback((newPage: number, newPageSize: number) => {
    setPage(newPage)
    setPageSize(newPageSize)
  }, [])

  // Handle sort change
  const handleSortChange = useCallback((field: SortField, order: SortOrder) => {
    setSortField(field)
    setSortOrder(order)
  }, [])

  // Transform search results to expected format
  const results: ArtifactSearchHit[] = searchResults?.items ?? []

  return (
    <div>
      <Title level={2} style={{ marginBottom: 24 }}>Advanced Search</Title>

      <Card style={{ marginBottom: 24 }}>
        <AdvancedSearchForm
          onSearch={handleSearch}
          loading={isLoading || isFetching}
          defaultTab={urlTab || 'package'}
        />
      </Card>

      {searchValues && (
        <Card>
          <SearchResults
            results={results}
            loading={isLoading || isFetching}
            onSelect={handleSelect}
            onDownload={handleDownload}
            viewMode={viewMode}
            onViewModeChange={setViewMode}
            sortField={sortField}
            sortOrder={sortOrder}
            onSortChange={handleSortChange}
            pagination={{
              current: page,
              pageSize,
              total: searchResults?.pagination?.total ?? 0,
              onChange: handlePaginationChange,
            }}
          />
        </Card>
      )}
    </div>
  )
}

export default Search
