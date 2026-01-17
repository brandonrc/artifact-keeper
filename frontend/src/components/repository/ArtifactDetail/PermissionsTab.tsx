import React from 'react';
import { Table, Tag, Typography, Empty, Space, Tooltip } from 'antd';
import {
  UserOutlined,
  TeamOutlined,
  CheckCircleOutlined,
  LockOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { PermissionAssignment, PermissionAction } from '../../../types';
import { colors } from '../../../styles/tokens';

const { Text } = Typography;

export interface PermissionsTabProps {
  permissions: PermissionAssignment[];
}

const getActionColor = (action: PermissionAction): string => {
  switch (action) {
    case 'read':
      return 'blue';
    case 'write':
      return 'green';
    case 'delete':
      return 'orange';
    case 'admin':
      return 'red';
    default:
      return 'default';
  }
};

const getActionIcon = (action: PermissionAction): React.ReactNode => {
  switch (action) {
    case 'admin':
      return <LockOutlined />;
    default:
      return null;
  }
};

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

export const PermissionsTab: React.FC<PermissionsTabProps> = ({
  permissions,
}) => {
  const columns: ColumnsType<PermissionAssignment> = [
    {
      title: 'Name',
      key: 'name',
      width: '30%',
      render: (_: unknown, record: PermissionAssignment) => (
        <Space>
          {record.target_type === 'user' ? (
            <UserOutlined style={{ color: colors.info }} />
          ) : (
            <TeamOutlined style={{ color: colors.primary }} />
          )}
          <div>
            <Text strong>{record.target_name}</Text>
            <div>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {record.target_type === 'user' ? 'User' : 'Group'}
              </Text>
            </div>
          </div>
        </Space>
      ),
    },
    {
      title: 'Access Level',
      key: 'actions',
      width: '35%',
      render: (_: unknown, record: PermissionAssignment) => (
        <Space size={4} wrap>
          {record.actions.map((action) => (
            <Tag
              key={action}
              color={getActionColor(action)}
              icon={getActionIcon(action)}
            >
              {action.charAt(0).toUpperCase() + action.slice(1)}
            </Tag>
          ))}
        </Space>
      ),
    },
    {
      title: 'Source',
      key: 'source',
      width: '20%',
      render: (_: unknown, record: PermissionAssignment) => (
        <div>
          {record.role_name ? (
            <Tooltip title="Assigned via role">
              <Tag color="purple">{record.role_name}</Tag>
            </Tooltip>
          ) : record.is_global ? (
            <Tooltip title="Global permission for all repositories">
              <Tag color="cyan">Global</Tag>
            </Tooltip>
          ) : record.repository_pattern ? (
            <Tooltip title={`Pattern: ${record.repository_pattern.pattern}`}>
              <Tag>Pattern</Tag>
            </Tooltip>
          ) : (
            <Tag>Direct</Tag>
          )}
        </div>
      ),
    },
    {
      title: 'Granted',
      key: 'granted',
      width: '15%',
      render: (_: unknown, record: PermissionAssignment) => (
        <div>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {formatDate(record.created_at)}
          </Text>
          {record.granted_by && (
            <div>
              <Text type="secondary" style={{ fontSize: 11 }}>
                by {record.granted_by}
              </Text>
            </div>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <div
        style={{
          marginBottom: 16,
          padding: 12,
          backgroundColor: colors.bgLayout,
          borderRadius: 6,
        }}
      >
        <Space>
          <LockOutlined style={{ color: colors.textSecondary }} />
          <Text type="secondary">
            This is a read-only view of effective permissions for this artifact.
            Permissions are managed by administrators at the repository level.
          </Text>
        </Space>
      </div>

      <Table
        dataSource={permissions}
        columns={columns}
        rowKey="id"
        pagination={false}
        size="small"
        locale={{
          emptyText: (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="No specific permissions assigned"
            />
          ),
        }}
      />
    </div>
  );
};

export default PermissionsTab;
