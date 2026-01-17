import React from 'react';
import { Table, Tag, Typography, Empty, Tooltip } from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
  ClockCircleOutlined,
  ExclamationCircleOutlined,
  StopOutlined,
  MinusCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { Build, BuildStatus } from '../../../types';
import { colors } from '../../../styles/tokens';
import { getStatusColor } from '../../../styles/theme';

const { Text, Link } = Typography;

export interface BuildsTabProps {
  builds: Build[];
  onBuildClick?: (build: Build) => void;
}

const formatDate = (dateString: string | undefined): string => {
  if (!dateString) return '-';
  const date = new Date(dateString);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

const formatDuration = (durationMs: number | undefined): string => {
  if (!durationMs) return '-';
  const seconds = Math.floor(durationMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
};

const getStatusIcon = (status: BuildStatus): React.ReactNode => {
  const iconStyle = { marginRight: 4 };
  switch (status) {
    case 'success':
      return <CheckCircleOutlined style={iconStyle} />;
    case 'failed':
      return <CloseCircleOutlined style={iconStyle} />;
    case 'running':
      return <SyncOutlined spin style={iconStyle} />;
    case 'pending':
    case 'queued':
      return <ClockCircleOutlined style={iconStyle} />;
    case 'cancelled':
      return <StopOutlined style={iconStyle} />;
    case 'unstable':
      return <ExclamationCircleOutlined style={iconStyle} />;
    default:
      return <MinusCircleOutlined style={iconStyle} />;
  }
};

const getStatusTagColor = (status: BuildStatus): string => {
  switch (status) {
    case 'success':
      return 'success';
    case 'failed':
      return 'error';
    case 'running':
      return 'processing';
    case 'pending':
    case 'queued':
      return 'default';
    case 'cancelled':
      return 'default';
    case 'unstable':
      return 'warning';
    default:
      return 'default';
  }
};

export const BuildsTab: React.FC<BuildsTabProps> = ({ builds, onBuildClick }) => {
  const columns: ColumnsType<Build> = [
    {
      title: 'Build',
      key: 'build',
      width: '30%',
      render: (_: unknown, record: Build) => (
        <div>
          {onBuildClick ? (
            <Link onClick={() => onBuildClick(record)} style={{ fontWeight: 500 }}>
              {record.project_name} #{record.build_number}
            </Link>
          ) : (
            <Text strong>
              {record.project_name} #{record.build_number}
            </Text>
          )}
          {record.branch && (
            <div>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {record.branch}
              </Text>
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: '20%',
      render: (status: BuildStatus) => (
        <Tag color={getStatusTagColor(status)}>
          {getStatusIcon(status)}
          {status.charAt(0).toUpperCase() + status.slice(1)}
        </Tag>
      ),
    },
    {
      title: 'Duration',
      dataIndex: 'duration_ms',
      key: 'duration',
      width: '15%',
      render: (duration: number | undefined) => (
        <Text>{formatDuration(duration)}</Text>
      ),
    },
    {
      title: 'Started',
      dataIndex: 'started_at',
      key: 'started_at',
      width: '20%',
      render: (date: string | undefined) => (
        <Text type="secondary">{formatDate(date)}</Text>
      ),
    },
    {
      title: 'Triggered By',
      dataIndex: 'triggered_by',
      key: 'triggered_by',
      width: '15%',
      render: (triggeredBy: string | undefined) => (
        <Text>{triggeredBy || '-'}</Text>
      ),
    },
  ];

  return (
    <Table
      dataSource={builds}
      columns={columns}
      rowKey="id"
      pagination={{
        pageSize: 10,
        showSizeChanger: false,
        showTotal: (total, range) =>
          `${range[0]}-${range[1]} of ${total} builds`,
      }}
      size="small"
      locale={{
        emptyText: (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="No builds associated with this artifact"
          />
        ),
      }}
    />
  );
};

export default BuildsTab;
