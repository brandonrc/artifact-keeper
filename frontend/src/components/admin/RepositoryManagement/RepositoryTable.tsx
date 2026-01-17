import React, { useMemo, useState, useCallback } from 'react';
import {
  Table,
  Tag,
  Button,
  Dropdown,
  Space,
  Input,
  Badge,
  Tooltip,
  Typography,
  Select,
  Popconfirm,
  Result,
} from 'antd';
import type { ColumnsType, TablePaginationConfig } from 'antd/es/table';
import type { SorterResult, FilterValue } from 'antd/es/table/interface';
import type { MenuProps } from 'antd';
import {
  EditOutlined,
  DeleteOutlined,
  EllipsisOutlined,
  SearchOutlined,
  PlusOutlined,
  SettingOutlined,
  EyeOutlined,
  DatabaseOutlined,
  CloudDownloadOutlined,
  CloudServerOutlined,
  AppstoreOutlined,
  CodeOutlined,
} from '@ant-design/icons';
import type { Repository, RepositoryType, RepositoryFormat } from '../../../types';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;

export interface RepositoryTableProps {
  repositories: Repository[];
  loading?: boolean;
  onEdit: (repository: Repository) => void;
  onDelete: (repository: Repository) => void;
  onView: (repository: Repository) => void;
  onConfigure?: (repository: Repository) => void;
  onBulkDelete?: (repositories: Repository[]) => void;
  onCreate?: () => void;
}

const typeColors: Record<RepositoryType, string> = {
  local: colors.success,
  remote: colors.info,
  virtual: colors.warning,
};

const typeLabels: Record<RepositoryType, string> = {
  local: 'Local',
  remote: 'Remote',
  virtual: 'Virtual',
};

const formatIcons: Record<RepositoryFormat, React.ReactNode> = {
  maven: <CodeOutlined />,
  pypi: <CodeOutlined />,
  npm: <AppstoreOutlined />,
  docker: <DatabaseOutlined />,
  helm: <CloudServerOutlined />,
  rpm: <AppstoreOutlined />,
  debian: <AppstoreOutlined />,
  go: <CodeOutlined />,
  nuget: <AppstoreOutlined />,
  cargo: <CodeOutlined />,
  generic: <AppstoreOutlined />,
};

const formatStorageBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const getStoragePercentage = (used: number, quota?: number): number => {
  if (!quota || quota === 0) return 0;
  return Math.min(100, Math.round((used / quota) * 100));
};

const getStorageStatus = (percentage: number): 'success' | 'warning' | 'error' | 'default' => {
  if (percentage >= 90) return 'error';
  if (percentage >= 75) return 'warning';
  if (percentage > 0) return 'success';
  return 'default';
};

export const RepositoryTable: React.FC<RepositoryTableProps> = ({
  repositories,
  loading = false,
  onEdit,
  onDelete,
  onView,
  onConfigure,
  onBulkDelete,
  onCreate,
}) => {
  const [searchText, setSearchText] = useState('');
  const [typeFilter, setTypeFilter] = useState<RepositoryType | 'all'>('all');
  const [formatFilter, setFormatFilter] = useState<RepositoryFormat | 'all'>('all');
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [sortedInfo, setSortedInfo] = useState<SorterResult<Repository>>({});

  const handleSearch = useCallback((value: string) => {
    setSearchText(value);
  }, []);

  const handleTypeFilterChange = useCallback((value: RepositoryType | 'all') => {
    setTypeFilter(value);
  }, []);

  const handleFormatFilterChange = useCallback((value: RepositoryFormat | 'all') => {
    setFormatFilter(value);
  }, []);

  const handleTableChange = useCallback(
    (
      _pagination: TablePaginationConfig,
      _filters: Record<string, FilterValue | null>,
      sorter: SorterResult<Repository> | SorterResult<Repository>[]
    ) => {
      if (!Array.isArray(sorter)) {
        setSortedInfo(sorter);
      }
    },
    []
  );

  const handleSelectChange = useCallback((newSelectedRowKeys: React.Key[]) => {
    setSelectedRowKeys(newSelectedRowKeys);
  }, []);

  const handleBulkDelete = useCallback(() => {
    if (onBulkDelete && selectedRowKeys.length > 0) {
      const selectedRepos = repositories.filter((repo) =>
        selectedRowKeys.includes(repo.id)
      );
      onBulkDelete(selectedRepos);
      setSelectedRowKeys([]);
    }
  }, [onBulkDelete, selectedRowKeys, repositories]);

  const filteredRepositories = useMemo(() => {
    return repositories.filter((repo) => {
      const matchesSearch =
        searchText === '' ||
        repo.key.toLowerCase().includes(searchText.toLowerCase()) ||
        repo.name.toLowerCase().includes(searchText.toLowerCase()) ||
        (repo.description?.toLowerCase().includes(searchText.toLowerCase()) ?? false);

      const matchesType = typeFilter === 'all' || repo.repo_type === typeFilter;
      const matchesFormat = formatFilter === 'all' || repo.format === formatFilter;

      return matchesSearch && matchesType && matchesFormat;
    });
  }, [repositories, searchText, typeFilter, formatFilter]);

  const getActionMenuItems = useCallback(
    (repository: Repository): MenuProps['items'] => {
      const items: MenuProps['items'] = [
        {
          key: 'view',
          label: 'View',
          icon: <EyeOutlined />,
          onClick: () => onView(repository),
        },
        {
          key: 'edit',
          label: 'Edit',
          icon: <EditOutlined />,
          onClick: () => onEdit(repository),
        },
      ];

      if (onConfigure) {
        items.push({
          key: 'configure',
          label: 'Configure',
          icon: <SettingOutlined />,
          onClick: () => onConfigure(repository),
        });
      }

      items.push(
        { type: 'divider' },
        {
          key: 'delete',
          label: 'Delete',
          icon: <DeleteOutlined />,
          danger: true,
          onClick: () => onDelete(repository),
        }
      );

      return items;
    },
    [onView, onEdit, onConfigure, onDelete]
  );

  const columns: ColumnsType<Repository> = useMemo(
    () => [
      {
        title: 'Key',
        dataIndex: 'key',
        key: 'key',
        sorter: (a, b) => a.key.localeCompare(b.key),
        sortOrder: sortedInfo.columnKey === 'key' ? sortedInfo.order : null,
        ellipsis: true,
        render: (key: string) => (
          <Text strong style={{ color: colors.primary }}>
            {key}
          </Text>
        ),
      },
      {
        title: 'Name',
        dataIndex: 'name',
        key: 'name',
        sorter: (a, b) => a.name.localeCompare(b.name),
        sortOrder: sortedInfo.columnKey === 'name' ? sortedInfo.order : null,
        ellipsis: true,
        render: (name: string, record) => (
          <Tooltip title={record.description}>
            <Text>{name}</Text>
          </Tooltip>
        ),
      },
      {
        title: 'Type',
        dataIndex: 'repo_type',
        key: 'repo_type',
        width: 100,
        sorter: (a, b) => a.repo_type.localeCompare(b.repo_type),
        sortOrder: sortedInfo.columnKey === 'repo_type' ? sortedInfo.order : null,
        render: (type: RepositoryType) => (
          <Tag color={typeColors[type]} style={{ margin: 0 }}>
            {typeLabels[type]}
          </Tag>
        ),
      },
      {
        title: 'Format',
        dataIndex: 'format',
        key: 'format',
        width: 120,
        sorter: (a, b) => a.format.localeCompare(b.format),
        sortOrder: sortedInfo.columnKey === 'format' ? sortedInfo.order : null,
        render: (format: RepositoryFormat) => (
          <Space size={4}>
            {formatIcons[format]}
            <Text>{format.toUpperCase()}</Text>
          </Space>
        ),
      },
      {
        title: 'Storage Used',
        dataIndex: 'storage_used_bytes',
        key: 'storage_used_bytes',
        width: 150,
        sorter: (a, b) => a.storage_used_bytes - b.storage_used_bytes,
        sortOrder: sortedInfo.columnKey === 'storage_used_bytes' ? sortedInfo.order : null,
        render: (bytes: number, record) => {
          const percentage = getStoragePercentage(bytes, record.quota_bytes);
          const status = getStorageStatus(percentage);
          const formattedSize = formatStorageBytes(bytes);
          const quotaText = record.quota_bytes
            ? ` / ${formatStorageBytes(record.quota_bytes)}`
            : '';

          return (
            <Tooltip title={`${formattedSize}${quotaText}`}>
              <Space size={4}>
                <Badge status={status} />
                <Text type="secondary">{formattedSize}</Text>
                {record.quota_bytes && (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    ({percentage}%)
                  </Text>
                )}
              </Space>
            </Tooltip>
          );
        },
      },
      {
        title: 'Status',
        dataIndex: 'is_public',
        key: 'status',
        width: 100,
        render: (isPublic: boolean) => (
          <Tag color={isPublic ? 'green' : 'default'}>
            {isPublic ? 'Public' : 'Private'}
          </Tag>
        ),
      },
      {
        title: 'Actions',
        key: 'actions',
        width: 80,
        align: 'center',
        fixed: 'right',
        render: (_, record) => (
          <Dropdown
            menu={{ items: getActionMenuItems(record) }}
            trigger={['click']}
            placement="bottomRight"
          >
            <Button type="text" icon={<EllipsisOutlined />} />
          </Dropdown>
        ),
      },
    ],
    [sortedInfo, getActionMenuItems]
  );

  const rowSelection = onBulkDelete
    ? {
        selectedRowKeys,
        onChange: handleSelectChange,
        selections: [
          Table.SELECTION_ALL,
          Table.SELECTION_INVERT,
          Table.SELECTION_NONE,
        ],
      }
    : undefined;

  const uniqueFormats = useMemo(() => {
    const formats = new Set(repositories.map((r) => r.format));
    return Array.from(formats).sort();
  }, [repositories]);

  if (!loading && repositories.length === 0) {
    return (
      <Result
        icon={<DatabaseOutlined style={{ fontSize: 64, color: colors.textTertiary }} />}
        title="No repositories yet"
        subTitle="Create your first repository to start managing your artifacts."
        extra={
          onCreate && (
            <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
              Create Repository
            </Button>
          )
        }
        style={{
          padding: spacing.xxl,
          backgroundColor: colors.bgContainer,
        }}
      />
    );
  }

  return (
    <div style={{ backgroundColor: colors.bgContainer }}>
      <div
        style={{
          padding: spacing.md,
          display: 'flex',
          flexWrap: 'wrap',
          gap: spacing.sm,
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: `1px solid ${colors.borderLight}`,
        }}
      >
        <Space wrap>
          <Input
            placeholder="Search repositories..."
            prefix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => handleSearch(e.target.value)}
            style={{ width: 240 }}
            allowClear
          />
          <Select
            value={typeFilter}
            onChange={handleTypeFilterChange}
            style={{ width: 120 }}
            options={[
              { value: 'all', label: 'All Types' },
              { value: 'local', label: 'Local' },
              { value: 'remote', label: 'Remote' },
              { value: 'virtual', label: 'Virtual' },
            ]}
          />
          <Select
            value={formatFilter}
            onChange={handleFormatFilterChange}
            style={{ width: 140 }}
            options={[
              { value: 'all', label: 'All Formats' },
              ...uniqueFormats.map((format) => ({
                value: format,
                label: format.toUpperCase(),
              })),
            ]}
          />
        </Space>

        <Space>
          {selectedRowKeys.length > 0 && onBulkDelete && (
            <Popconfirm
              title="Delete repositories"
              description={`Are you sure you want to delete ${selectedRowKeys.length} selected repositories?`}
              onConfirm={handleBulkDelete}
              okText="Delete"
              cancelText="Cancel"
              okButtonProps={{ danger: true }}
            >
              <Button danger icon={<DeleteOutlined />}>
                Delete ({selectedRowKeys.length})
              </Button>
            </Popconfirm>
          )}
          {onCreate && (
            <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
              Create Repository
            </Button>
          )}
        </Space>
      </div>

      <Table<Repository>
        columns={columns}
        dataSource={filteredRepositories}
        rowKey="id"
        loading={loading}
        rowSelection={rowSelection}
        onChange={handleTableChange}
        pagination={{
          showSizeChanger: true,
          showTotal: (total, range) =>
            `${range[0]}-${range[1]} of ${total} repositories`,
          pageSizeOptions: ['10', '20', '50', '100'],
          defaultPageSize: 20,
        }}
        scroll={{ x: 900 }}
        size="middle"
        locale={{
          emptyText: (
            <Result
              icon={<SearchOutlined style={{ fontSize: 48, color: colors.textTertiary }} />}
              title="No matching repositories"
              subTitle="Try adjusting your search or filter criteria."
              style={{ padding: spacing.lg }}
            />
          ),
        }}
      />
    </div>
  );
};

export default RepositoryTable;
