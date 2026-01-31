import React, { useState } from 'react';
import { Card, Table, Tag, Button, Space, Typography, Spin, Empty, message } from 'antd';
import { ScanOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { securityApi } from '../../../api';
import type { ScanResult } from '../../../types/security';

const { Text } = Typography;

const severityColors: Record<string, string> = {
  critical: '#f5222d',
  high: '#fa8c16',
  medium: '#faad14',
  low: '#1890ff',
  info: '#d9d9d9',
};

const statusColors: Record<string, string> = {
  completed: 'green',
  running: 'blue',
  pending: 'default',
  failed: 'red',
};

interface SecurityTabProps {
  artifactId: string;
  repositoryKey: string;
}

export const SecurityTab: React.FC<SecurityTabProps> = ({ artifactId, repositoryKey }) => {
  const queryClient = useQueryClient();

  const { data: scansData, isLoading } = useQuery({
    queryKey: ['security', 'artifact-scans', artifactId],
    queryFn: () => securityApi.listArtifactScans(artifactId),
    enabled: !!artifactId,
  });

  const triggerMutation = useMutation({
    mutationFn: () => securityApi.triggerScan({ artifact_id: artifactId }),
    onSuccess: () => {
      message.success('Security scan triggered');
      queryClient.invalidateQueries({ queryKey: ['security', 'artifact-scans', artifactId] });
    },
    onError: () => {
      message.error('Failed to trigger scan');
    },
  });

  const latestScan = scansData?.items?.[0];

  const columns = [
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={statusColors[status] || 'default'}>{status.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'scan_type',
      key: 'scan_type',
      render: (type: string) => <Tag>{type}</Tag>,
    },
    {
      title: 'Findings',
      dataIndex: 'findings_count',
      key: 'findings_count',
      render: (_: number, record: ScanResult) => (
        <Space size={4}>
          {record.critical_count > 0 && (
            <Tag color={severityColors.critical}>{record.critical_count}C</Tag>
          )}
          {record.high_count > 0 && (
            <Tag color={severityColors.high}>{record.high_count}H</Tag>
          )}
          {record.medium_count > 0 && (
            <Tag color={severityColors.medium}>{record.medium_count}M</Tag>
          )}
          {record.low_count > 0 && (
            <Tag color={severityColors.low}>{record.low_count}L</Tag>
          )}
          {record.findings_count === 0 && <Tag color="green">Clean</Tag>}
        </Space>
      ),
    },
    {
      title: 'Started',
      dataIndex: 'started_at',
      key: 'started_at',
      render: (val: string | null) => (val ? new Date(val).toLocaleString() : '-'),
    },
    {
      title: 'Completed',
      dataIndex: 'completed_at',
      key: 'completed_at',
      render: (val: string | null) => (val ? new Date(val).toLocaleString() : '-'),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: unknown, record: ScanResult) => (
        <Link to={`/security/scans/${record.id}`}>View Findings</Link>
      ),
    },
  ];

  if (isLoading) {
    return (
      <div style={{ textAlign: 'center', padding: 48 }}>
        <Spin size="large" />
      </div>
    );
  }

  const renderSummary = () => {
    if (!latestScan) {
      return (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="No security scans yet"
        >
          <Button
            type="primary"
            icon={<ScanOutlined />}
            onClick={() => triggerMutation.mutate()}
            loading={triggerMutation.isPending}
          >
            Trigger Scan
          </Button>
        </Empty>
      );
    }

    if (latestScan.status === 'running' || latestScan.status === 'pending') {
      return (
        <Space direction="vertical" size={8}>
          <Space>
            <Tag color="blue">Scan in progress...</Tag>
            <Button
              icon={<ReloadOutlined />}
              size="small"
              onClick={() =>
                queryClient.invalidateQueries({ queryKey: ['security', 'artifact-scans', artifactId] })
              }
            >
              Refresh
            </Button>
          </Space>
        </Space>
      );
    }

    return (
      <Space direction="vertical" size={8}>
        <Space wrap>
          <Tag color={statusColors[latestScan.status] || 'default'}>
            {latestScan.status.toUpperCase()}
          </Tag>
          {latestScan.critical_count > 0 && (
            <Tag color={severityColors.critical}>{latestScan.critical_count} Critical</Tag>
          )}
          {latestScan.high_count > 0 && (
            <Tag color={severityColors.high}>{latestScan.high_count} High</Tag>
          )}
          {latestScan.medium_count > 0 && (
            <Tag color={severityColors.medium}>{latestScan.medium_count} Medium</Tag>
          )}
          {latestScan.low_count > 0 && (
            <Tag color={severityColors.low}>{latestScan.low_count} Low</Tag>
          )}
          {latestScan.findings_count === 0 && latestScan.status === 'completed' && (
            <Tag color="green">Clean</Tag>
          )}
        </Space>
        <Space>
          <Text type="secondary">
            Last scanned: {latestScan.completed_at ? new Date(latestScan.completed_at).toLocaleString() : new Date(latestScan.created_at).toLocaleString()}
          </Text>
          <Button
            type="primary"
            icon={<ScanOutlined />}
            size="small"
            onClick={() => triggerMutation.mutate()}
            loading={triggerMutation.isPending}
          >
            Trigger Scan
          </Button>
        </Space>
      </Space>
    );
  };

  return (
    <div>
      <Card size="small" style={{ marginBottom: 16 }}>
        {renderSummary()}
      </Card>

      {scansData && scansData.items.length > 0 && (
        <Card size="small" title="Scan History">
          <Table
            dataSource={scansData.items}
            columns={columns}
            rowKey="id"
            size="small"
            pagination={scansData.items.length > 10 ? { pageSize: 10 } : false}
          />
        </Card>
      )}
    </div>
  );
};

export default SecurityTab;
