import React, { useMemo, useState, useCallback } from 'react';
import {
  Table,
  Tag,
  Button,
  Dropdown,
  Space,
  Input,
  Tooltip,
  Typography,
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
  SafetyCertificateOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { colors, spacing } from '../../../styles/tokens';
import type { Permission, PermissionAction } from '../../../api';

const { Text } = Typography;

export interface PermissionTargetData {
  id: string;
  name: string;
  description?: string;
  repository_pattern?: string;
  actions: PermissionAction[];
  assigned_users: Array<{ id: string; name: string }>;
  assigned_groups: Array<{ id: string; name: string }>;
  created_at: string;
  updated_at: string;
}

export interface PermissionTargetTableProps {
  targets: PermissionTargetData[];
  loading?: boolean;
  onEdit: (target: PermissionTargetData) => void;
  onDelete: (target: PermissionTargetData) => void;
  onCreate?: () => void;
}

const actionColors: Record<PermissionAction, string> = {
  read: colors.info,
  write: colors.success,
  delete: colors.error,
  admin: colors.warning,
};

const actionLabels: Record<PermissionAction, string> = {
  read: 'Read',
  write: 'Write',
  delete: 'Delete',
  admin: 'Admin',
};

export const PermissionTargetTable: React.FC<PermissionTargetTableProps> = ({
  targets,
  loading = false,
  onEdit,
  onDelete,
  onCreate,
}) => {
  const [searchText, setSearchText] = useState('');
  const [sortedInfo, setSortedInfo] = useState<SorterResult<PermissionTargetData>>({});

  const handleSearch = useCallback((value: string) => {
    setSearchText(value);
  }, []);

  const handleTableChange = useCallback(
    (
      _pagination: TablePaginationConfig,
      _filters: Record<string, FilterValue | null>,
      sorter: SorterResult<PermissionTargetData> | SorterResult<PermissionTargetData>[]
    ) => {
      if (!Array.isArray(sorter)) {
        setSortedInfo(sorter);
      }
    },
    []
  );

  const filteredTargets = useMemo(() => {
    return targets.filter((target) => {
      const matchesSearch =
        searchText === '' ||
        target.name.toLowerCase().includes(searchText.toLowerCase()) ||
        (target.description?.toLowerCase().includes(searchText.toLowerCase()) ?? false) ||
        (target.repository_pattern?.toLowerCase().includes(searchText.toLowerCase()) ?? false);

      return matchesSearch;
    });
  }, [targets, searchText]);

  const getActionMenuItems = useCallback(
    (target: PermissionTargetData): MenuProps['items'] => {
      return [
        {
          key: 'edit',
          label: 'Edit',
          icon: <EditOutlined />,
          onClick: () => onEdit(target),
        },
        { type: 'divider' },
        {
          key: 'delete',
          label: 'Delete',
          icon: <DeleteOutlined />,
          danger: true,
          onClick: () => onDelete(target),
        },
      ];
    },
    [onEdit, onDelete]
  );

  const renderPatternColumn = (pattern?: string) => {
    if (!pattern) {
      return <Text type="secondary">All repositories</Text>;
    }

    const hasWildcard = pattern.includes('*');
    return (
      <Tooltip title={hasWildcard ? 'Pattern uses wildcard matching' : 'Exact match'}>
        <Tag
          style={{
            fontFamily: 'monospace',
            backgroundColor: hasWildcard ? colors.bgContainerLight : undefined,
          }}
        >
          {pattern}
        </Tag>
      </Tooltip>
    );
  };

  const renderActionsColumn = (actions: PermissionAction[]) => {
    return (
      <Space size={4} wrap>
        {actions.map((action) => (
          <Tag key={action} color={actionColors[action]} style={{ margin: 0 }}>
            {actionLabels[action]}
          </Tag>
        ))}
      </Space>
    );
  };

  const renderAssignedToColumn = (
    users: Array<{ id: string; name: string }>,
    groups: Array<{ id: string; name: string }>
  ) => {
    const totalAssigned = users.length + groups.length;

    if (totalAssigned === 0) {
      return <Text type="secondary">Not assigned</Text>;
    }

    const maxVisible = 3;
    const displayItems: React.ReactNode[] = [];

    groups.slice(0, maxVisible).forEach((group) => {
      displayItems.push(
        <Tag key={`group-${group.id}`} icon={<TeamOutlined />} color="blue">
          {group.name}
        </Tag>
      );
    });

    const remainingSlots = maxVisible - displayItems.length;
    users.slice(0, remainingSlots).forEach((user) => {
      displayItems.push(
        <Tag key={`user-${user.id}`} icon={<UserOutlined />}>
          {user.name}
        </Tag>
      );
    });

    const hiddenCount = totalAssigned - displayItems.length;

    return (
      <Space size={4} wrap>
        {displayItems}
        {hiddenCount > 0 && (
          <Tooltip
            title={
              <div>
                {groups.slice(displayItems.filter((_, i) => i < groups.length).length).map((g) => (
                  <div key={g.id}>
                    <TeamOutlined /> {g.name}
                  </div>
                ))}
                {users.slice(remainingSlots).map((u) => (
                  <div key={u.id}>
                    <UserOutlined /> {u.name}
                  </div>
                ))}
              </div>
            }
          >
            <Tag>+{hiddenCount} more</Tag>
          </Tooltip>
        )}
      </Space>
    );
  };

  const columns: ColumnsType<PermissionTargetData> = useMemo(
    () => [
      {
        title: 'Name',
        dataIndex: 'name',
        key: 'name',
        sorter: (a, b) => a.name.localeCompare(b.name),
        sortOrder: sortedInfo.columnKey === 'name' ? sortedInfo.order : null,
        ellipsis: true,
        render: (name: string, record) => (
          <Tooltip title={record.description}>
            <Text strong style={{ color: colors.primary }}>
              {name}
            </Text>
          </Tooltip>
        ),
      },
      {
        title: 'Repositories Pattern',
        dataIndex: 'repository_pattern',
        key: 'repository_pattern',
        width: 200,
        render: renderPatternColumn,
      },
      {
        title: 'Actions',
        dataIndex: 'actions',
        key: 'actions',
        width: 200,
        render: renderActionsColumn,
      },
      {
        title: 'Assigned To',
        key: 'assigned_to',
        width: 250,
        render: (_, record) =>
          renderAssignedToColumn(record.assigned_users, record.assigned_groups),
      },
      {
        title: '',
        key: 'actions_menu',
        width: 60,
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

  if (!loading && targets.length === 0) {
    return (
      <Result
        icon={<SafetyCertificateOutlined style={{ fontSize: 64, color: colors.textTertiary }} />}
        title="No permission targets yet"
        subTitle="Create your first permission target to manage access control."
        extra={
          onCreate && (
            <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
              Create Permission Target
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
        <Input
          placeholder="Search permission targets..."
          prefix={<SearchOutlined />}
          value={searchText}
          onChange={(e) => handleSearch(e.target.value)}
          style={{ width: 280 }}
          allowClear
        />

        {onCreate && (
          <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
            Create Permission Target
          </Button>
        )}
      </div>

      <Table<PermissionTargetData>
        columns={columns}
        dataSource={filteredTargets}
        rowKey="id"
        loading={loading}
        onChange={handleTableChange}
        pagination={{
          showSizeChanger: true,
          showTotal: (total, range) =>
            `${range[0]}-${range[1]} of ${total} permission targets`,
          pageSizeOptions: ['10', '20', '50', '100'],
          defaultPageSize: 20,
        }}
        scroll={{ x: 800 }}
        size="middle"
        locale={{
          emptyText: (
            <Result
              icon={<SearchOutlined style={{ fontSize: 48, color: colors.textTertiary }} />}
              title="No matching permission targets"
              subTitle="Try adjusting your search criteria."
              style={{ padding: spacing.lg }}
            />
          ),
        }}
      />
    </div>
  );
};

export default PermissionTargetTable;
