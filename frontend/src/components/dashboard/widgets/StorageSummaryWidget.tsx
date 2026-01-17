import React from 'react';
import { Progress, Typography, Space, List } from 'antd';
import { HddOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { DashboardWidget } from '../DashboardWidget';
import { adminApi, repositoriesApi } from '../../../api';
import { useAuth } from '../../../contexts';
import { colors, spacing } from '../../../styles/tokens';
import type { Repository } from '../../../types';

const { Text } = Typography;

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const DEFAULT_QUOTA_BYTES = 100 * 1024 * 1024 * 1024; // 100 GB default quota

export const StorageSummaryWidget: React.FC = () => {
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const {
    data: stats,
    isLoading: statsLoading,
    error: statsError,
    isFetching: statsFetching,
  } = useQuery({
    queryKey: ['admin-stats'],
    queryFn: () => adminApi.getStats(),
    enabled: user?.is_admin,
  });

  const {
    data: repositories,
    isLoading: reposLoading,
    error: reposError,
    isFetching: reposFetching,
  } = useQuery({
    queryKey: ['repositories-list'],
    queryFn: () => repositoriesApi.list({ per_page: 100 }),
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['admin-stats'] });
    queryClient.invalidateQueries({ queryKey: ['repositories-list'] });
  };

  const isLoading = statsLoading || reposLoading;
  const isFetching = statsFetching || reposFetching;
  const error = statsError || reposError;

  const totalStorage = stats?.total_storage_bytes ?? 0;
  const quotaBytes = DEFAULT_QUOTA_BYTES;
  const usagePercent = Math.min(Math.round((totalStorage / quotaBytes) * 100), 100);

  const getProgressStatus = (percent: number): 'success' | 'normal' | 'exception' => {
    if (percent >= 90) return 'exception';
    if (percent >= 70) return 'normal';
    return 'success';
  };

  const topRepositories: Repository[] = React.useMemo(() => {
    if (!repositories?.items) return [];
    return [...repositories.items]
      .sort((a, b) => b.storage_used_bytes - a.storage_used_bytes)
      .slice(0, 5);
  }, [repositories?.items]);

  return (
    <DashboardWidget
      title="Storage Summary"
      icon={<HddOutlined />}
      loading={isLoading || isFetching}
      error={error as Error | null}
      onRefresh={handleRefresh}
    >
      <div style={{ marginBottom: spacing.md }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            marginBottom: spacing.xs,
          }}
        >
          <Text type="secondary">Total Storage Used</Text>
          <Text strong>
            {formatBytes(totalStorage)} / {formatBytes(quotaBytes)}
          </Text>
        </div>
        <Progress
          percent={usagePercent}
          status={getProgressStatus(usagePercent)}
          strokeColor={{
            '0%': colors.primary,
            '100%': usagePercent >= 90 ? colors.error : colors.primaryActive,
          }}
          showInfo
        />
      </div>

      {topRepositories.length > 0 && (
        <div>
          <Text
            type="secondary"
            style={{ fontSize: 12, display: 'block', marginBottom: spacing.xs }}
          >
            Top Repositories by Storage
          </Text>
          <List
            size="small"
            dataSource={topRepositories}
            renderItem={(repo) => {
              const repoPercent =
                totalStorage > 0
                  ? Math.round((repo.storage_used_bytes / totalStorage) * 100)
                  : 0;
              return (
                <List.Item
                  style={{
                    padding: `${spacing.xxs}px 0`,
                    borderBottom: 'none',
                  }}
                >
                  <Space
                    style={{
                      width: '100%',
                      justifyContent: 'space-between',
                    }}
                  >
                    <Text ellipsis style={{ maxWidth: 150 }}>
                      {repo.key}
                    </Text>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {formatBytes(repo.storage_used_bytes)} ({repoPercent}%)
                    </Text>
                  </Space>
                </List.Item>
              );
            }}
          />
        </div>
      )}
    </DashboardWidget>
  );
};

export default StorageSummaryWidget;
