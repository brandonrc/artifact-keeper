import React from 'react';
import { Card, Spin, Button, Tooltip } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { ErrorRetry } from '../../common/ErrorRetry/ErrorRetry';
import { colors, spacing, borderRadius, shadows } from '../../../styles/tokens';

export interface DashboardWidgetProps {
  title: string;
  icon?: React.ReactNode;
  loading?: boolean;
  error?: Error | string | null;
  onRefresh?: () => void;
  children: React.ReactNode;
  style?: React.CSSProperties;
  className?: string;
  extra?: React.ReactNode;
}

export const DashboardWidget: React.FC<DashboardWidgetProps> = ({
  title,
  icon,
  loading = false,
  error,
  onRefresh,
  children,
  style,
  className,
  extra,
}) => {
  const headerExtra = (
    <>
      {extra}
      {onRefresh && (
        <Tooltip title="Refresh">
          <Button
            type="text"
            size="small"
            icon={<ReloadOutlined spin={loading} />}
            onClick={onRefresh}
            disabled={loading}
            style={{ marginLeft: extra ? spacing.xs : 0 }}
          />
        </Tooltip>
      )}
    </>
  );

  const cardTitle = (
    <span style={{ display: 'flex', alignItems: 'center', gap: spacing.xs }}>
      {icon && <span style={{ color: colors.primary }}>{icon}</span>}
      <span>{title}</span>
    </span>
  );

  return (
    <Card
      title={cardTitle}
      extra={headerExtra}
      className={className}
      style={{
        borderRadius: borderRadius.lg,
        boxShadow: shadows.sm,
        ...style,
      }}
      styles={{
        header: {
          borderBottom: `1px solid ${colors.borderLight}`,
          padding: `${spacing.sm}px ${spacing.md}px`,
        },
        body: {
          padding: spacing.md,
          position: 'relative',
          minHeight: 120,
        },
      }}
    >
      {error ? (
        <ErrorRetry
          error={error}
          onRetry={onRefresh || (() => {})}
          loading={loading}
          title="Failed to load widget data"
        />
      ) : (
        <Spin spinning={loading}>
          {children}
        </Spin>
      )}
    </Card>
  );
};

export default DashboardWidget;
