import React, { useMemo, useState, useCallback } from 'react';
import {
  Table,
  Tag,
  Button,
  Dropdown,
  Space,
  Input,
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
  UserOutlined,
  KeyOutlined,
  StopOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import type { User } from '../../../types';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;

export interface UserTableProps {
  users: User[];
  loading?: boolean;
  onEdit: (user: User) => void;
  onDelete: (user: User) => void;
  onResetPassword: (user: User) => void;
  onToggleStatus?: (user: User) => void;
  onBulkDelete?: (users: User[]) => void;
  onCreate?: () => void;
}

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

export const UserTable: React.FC<UserTableProps> = ({
  users,
  loading = false,
  onEdit,
  onDelete,
  onResetPassword,
  onToggleStatus,
  onBulkDelete,
  onCreate,
}) => {
  const [searchText, setSearchText] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | 'admin' | 'user'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'disabled'>('all');
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [sortedInfo, setSortedInfo] = useState<SorterResult<User>>({});

  const handleSearch = useCallback((value: string) => {
    setSearchText(value);
  }, []);

  const handleTableChange = useCallback(
    (
      _pagination: TablePaginationConfig,
      _filters: Record<string, FilterValue | null>,
      sorter: SorterResult<User> | SorterResult<User>[]
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
      const selectedUsers = users.filter((user) =>
        selectedRowKeys.includes(user.id)
      );
      onBulkDelete(selectedUsers);
      setSelectedRowKeys([]);
    }
  }, [onBulkDelete, selectedRowKeys, users]);

  const filteredUsers = useMemo(() => {
    return users.filter((user) => {
      const matchesSearch =
        searchText === '' ||
        user.username.toLowerCase().includes(searchText.toLowerCase()) ||
        user.email.toLowerCase().includes(searchText.toLowerCase()) ||
        (user.display_name?.toLowerCase().includes(searchText.toLowerCase()) ?? false);

      const matchesRole =
        roleFilter === 'all' ||
        (roleFilter === 'admin' && user.is_admin) ||
        (roleFilter === 'user' && !user.is_admin);

      const matchesStatus =
        statusFilter === 'all' ||
        (statusFilter === 'active' && user.is_active !== false) ||
        (statusFilter === 'disabled' && user.is_active === false);

      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [users, searchText, roleFilter, statusFilter]);

  const getActionMenuItems = useCallback(
    (user: User): MenuProps['items'] => {
      const isActive = user.is_active !== false;
      const items: MenuProps['items'] = [
        {
          key: 'edit',
          label: 'Edit',
          icon: <EditOutlined />,
          onClick: () => onEdit(user),
        },
        {
          key: 'reset-password',
          label: 'Reset Password',
          icon: <KeyOutlined />,
          onClick: () => onResetPassword(user),
        },
      ];

      if (onToggleStatus) {
        items.push({
          key: 'toggle-status',
          label: isActive ? 'Disable' : 'Enable',
          icon: isActive ? <StopOutlined /> : <CheckCircleOutlined />,
          onClick: () => onToggleStatus(user),
        });
      }

      items.push(
        { type: 'divider' },
        {
          key: 'delete',
          label: 'Delete',
          icon: <DeleteOutlined />,
          danger: true,
          onClick: () => onDelete(user),
        }
      );

      return items;
    },
    [onEdit, onResetPassword, onToggleStatus, onDelete]
  );

  const columns: ColumnsType<User> = useMemo(
    () => [
      {
        title: 'Username',
        dataIndex: 'username',
        key: 'username',
        sorter: (a, b) => a.username.localeCompare(b.username),
        sortOrder: sortedInfo.columnKey === 'username' ? sortedInfo.order : null,
        ellipsis: true,
        render: (username: string) => (
          <Text strong style={{ color: colors.primary }}>
            {username}
          </Text>
        ),
      },
      {
        title: 'Display Name',
        dataIndex: 'display_name',
        key: 'display_name',
        sorter: (a, b) => (a.display_name || '').localeCompare(b.display_name || ''),
        sortOrder: sortedInfo.columnKey === 'display_name' ? sortedInfo.order : null,
        ellipsis: true,
        render: (displayName: string | undefined) => (
          <Text type={displayName ? undefined : 'secondary'}>
            {displayName || '-'}
          </Text>
        ),
      },
      {
        title: 'Email',
        dataIndex: 'email',
        key: 'email',
        sorter: (a, b) => a.email.localeCompare(b.email),
        sortOrder: sortedInfo.columnKey === 'email' ? sortedInfo.order : null,
        ellipsis: true,
      },
      {
        title: 'Role',
        dataIndex: 'is_admin',
        key: 'role',
        width: 100,
        sorter: (a, b) => Number(b.is_admin) - Number(a.is_admin),
        sortOrder: sortedInfo.columnKey === 'role' ? sortedInfo.order : null,
        render: (isAdmin: boolean) => (
          <Tag color={isAdmin ? colors.warning : colors.info} style={{ margin: 0 }}>
            {isAdmin ? 'Admin' : 'User'}
          </Tag>
        ),
      },
      {
        title: 'Status',
        dataIndex: 'is_active',
        key: 'status',
        width: 100,
        sorter: (a, b) => Number(b.is_active ?? true) - Number(a.is_active ?? true),
        sortOrder: sortedInfo.columnKey === 'status' ? sortedInfo.order : null,
        render: (isActive: boolean | undefined) => {
          const active = isActive !== false;
          return (
            <Tag color={active ? colors.success : colors.error} style={{ margin: 0 }}>
              {active ? 'Active' : 'Disabled'}
            </Tag>
          );
        },
      },
      {
        title: 'Created',
        dataIndex: 'created_at',
        key: 'created_at',
        width: 120,
        sorter: (a, b) => {
          const dateA = (a as User & { created_at?: string }).created_at || '';
          const dateB = (b as User & { created_at?: string }).created_at || '';
          return dateA.localeCompare(dateB);
        },
        sortOrder: sortedInfo.columnKey === 'created_at' ? sortedInfo.order : null,
        render: (createdAt: string | undefined) =>
          createdAt ? formatDate(createdAt) : '-',
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

  if (!loading && users.length === 0) {
    return (
      <Result
        icon={<UserOutlined style={{ fontSize: 64, color: colors.textTertiary }} />}
        title="No users yet"
        subTitle="Create your first user to start managing access to your repositories."
        extra={
          onCreate && (
            <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
              Create User
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
            placeholder="Search users..."
            prefix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => handleSearch(e.target.value)}
            style={{ width: 240 }}
            allowClear
          />
          <Button
            type={roleFilter === 'all' ? 'default' : 'primary'}
            ghost={roleFilter !== 'all'}
            onClick={() => setRoleFilter(roleFilter === 'all' ? 'admin' : roleFilter === 'admin' ? 'user' : 'all')}
          >
            {roleFilter === 'all' ? 'All Roles' : roleFilter === 'admin' ? 'Admins' : 'Users'}
          </Button>
          <Button
            type={statusFilter === 'all' ? 'default' : 'primary'}
            ghost={statusFilter !== 'all'}
            onClick={() => setStatusFilter(statusFilter === 'all' ? 'active' : statusFilter === 'active' ? 'disabled' : 'all')}
          >
            {statusFilter === 'all' ? 'All Status' : statusFilter === 'active' ? 'Active' : 'Disabled'}
          </Button>
        </Space>

        <Space>
          {selectedRowKeys.length > 0 && onBulkDelete && (
            <Popconfirm
              title="Delete users"
              description={`Are you sure you want to delete ${selectedRowKeys.length} selected users?`}
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
              Create User
            </Button>
          )}
        </Space>
      </div>

      <Table<User>
        columns={columns}
        dataSource={filteredUsers}
        rowKey="id"
        loading={loading}
        rowSelection={rowSelection}
        onChange={handleTableChange}
        pagination={{
          showSizeChanger: true,
          showTotal: (total, range) =>
            `${range[0]}-${range[1]} of ${total} users`,
          pageSizeOptions: ['10', '20', '50', '100'],
          defaultPageSize: 20,
        }}
        scroll={{ x: 900 }}
        size="middle"
        locale={{
          emptyText: (
            <Result
              icon={<SearchOutlined style={{ fontSize: 48, color: colors.textTertiary }} />}
              title="No matching users"
              subTitle="Try adjusting your search or filter criteria."
              style={{ padding: spacing.lg }}
            />
          ),
        }}
      />
    </div>
  );
};

export default UserTable;
