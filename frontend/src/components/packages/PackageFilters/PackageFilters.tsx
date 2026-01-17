import React, { useCallback } from 'react';
import { Input, Select, Space, Card } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import type { PackageType, Repository } from '../../../types';
import { spacing, borderRadius } from '../../../styles/tokens';

const { Option } = Select;

export type SortBy = 'name' | 'downloads' | 'updated' | 'created';
export type SortOrder = 'asc' | 'desc';

export interface PackageFilterValue {
  search?: string;
  format?: PackageType;
  repository_id?: string;
  sort_by?: SortBy;
  sort_order?: SortOrder;
}

export interface PackageFiltersProps {
  value: PackageFilterValue;
  onChange: (value: PackageFilterValue) => void;
  repositories?: Repository[];
  loading?: boolean;
}

const formatOptions: { value: PackageType; label: string }[] = [
  { value: 'maven', label: 'Maven' },
  { value: 'gradle', label: 'Gradle' },
  { value: 'npm', label: 'npm' },
  { value: 'pypi', label: 'PyPI' },
  { value: 'nuget', label: 'NuGet' },
  { value: 'go', label: 'Go' },
  { value: 'rubygems', label: 'RubyGems' },
  { value: 'docker', label: 'Docker' },
  { value: 'helm', label: 'Helm' },
  { value: 'rpm', label: 'RPM' },
  { value: 'debian', label: 'Debian' },
  { value: 'conan', label: 'Conan' },
  { value: 'cargo', label: 'Cargo' },
  { value: 'generic', label: 'Generic' },
];

const sortByOptions: { value: SortBy; label: string }[] = [
  { value: 'name', label: 'Name' },
  { value: 'downloads', label: 'Downloads' },
  { value: 'updated', label: 'Last Updated' },
  { value: 'created', label: 'Created Date' },
];

const sortOrderOptions: { value: SortOrder; label: string }[] = [
  { value: 'asc', label: 'Ascending' },
  { value: 'desc', label: 'Descending' },
];

export const PackageFilters: React.FC<PackageFiltersProps> = ({
  value,
  onChange,
  repositories = [],
  loading = false,
}) => {
  const handleSearchChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      onChange({ ...value, search: e.target.value || undefined });
    },
    [value, onChange]
  );

  const handleFormatChange = useCallback(
    (format: PackageType | undefined) => {
      onChange({ ...value, format });
    },
    [value, onChange]
  );

  const handleRepositoryChange = useCallback(
    (repository_id: string | undefined) => {
      onChange({ ...value, repository_id });
    },
    [value, onChange]
  );

  const handleSortByChange = useCallback(
    (sort_by: SortBy | undefined) => {
      onChange({ ...value, sort_by });
    },
    [value, onChange]
  );

  const handleSortOrderChange = useCallback(
    (sort_order: SortOrder | undefined) => {
      onChange({ ...value, sort_order });
    },
    [value, onChange]
  );

  return (
    <Card
      style={{
        borderRadius: borderRadius.lg,
        marginBottom: spacing.lg,
      }}
      styles={{
        body: {
          padding: spacing.md,
        },
      }}
    >
      <Space wrap size="middle" style={{ width: '100%' }}>
        <Input
          placeholder="Search packages..."
          prefix={<SearchOutlined />}
          value={value.search}
          onChange={handleSearchChange}
          allowClear
          style={{ width: 240 }}
          disabled={loading}
        />

        <Select
          placeholder="Format"
          value={value.format}
          onChange={handleFormatChange}
          allowClear
          showSearch
          optionFilterProp="label"
          options={formatOptions}
          style={{ width: 140 }}
          disabled={loading}
        />

        <Select
          placeholder="Repository"
          value={value.repository_id}
          onChange={handleRepositoryChange}
          allowClear
          showSearch
          optionFilterProp="children"
          style={{ width: 180 }}
          disabled={loading}
        >
          {repositories.map((repo) => (
            <Option key={repo.id} value={repo.id}>
              {repo.name}
            </Option>
          ))}
        </Select>

        <Space.Compact>
          <Select
            placeholder="Sort by"
            value={value.sort_by}
            onChange={handleSortByChange}
            allowClear
            options={sortByOptions}
            style={{ width: 140 }}
            disabled={loading}
          />
          <Select
            placeholder="Order"
            value={value.sort_order}
            onChange={handleSortOrderChange}
            allowClear
            options={sortOrderOptions}
            style={{ width: 120 }}
            disabled={loading}
          />
        </Space.Compact>
      </Space>
    </Card>
  );
};

export default PackageFilters;
