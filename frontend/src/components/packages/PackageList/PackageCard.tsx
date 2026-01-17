import React, { useCallback } from 'react';
import { Card, Typography, Space, Badge, Tooltip } from 'antd';
import {
  DownloadOutlined,
  ClockCircleOutlined,
  BuildOutlined,
  BoxPlotOutlined,
  CodeOutlined,
  ContainerOutlined,
  CloudServerOutlined,
  AppstoreOutlined,
  BlockOutlined,
  DeploymentUnitOutlined,
  SettingOutlined,
  FileZipOutlined,
  FileOutlined,
} from '@ant-design/icons';
import type { Package, PackageType } from '../../../types';
import { colors, spacing, borderRadius, shadows } from '../../../styles/tokens';

const { Text, Title } = Typography;

export interface PackageCardProps {
  package: Package;
  onClick?: (pkg: Package) => void;
}

const packageTypeIcons: Record<PackageType, React.ReactNode> = {
  maven: <BuildOutlined />,
  gradle: <BuildOutlined />,
  npm: <BoxPlotOutlined />,
  pypi: <CodeOutlined />,
  nuget: <AppstoreOutlined />,
  go: <DeploymentUnitOutlined />,
  rubygems: <BlockOutlined />,
  docker: <ContainerOutlined />,
  helm: <CloudServerOutlined />,
  rpm: <SettingOutlined />,
  debian: <FileZipOutlined />,
  conan: <BlockOutlined />,
  cargo: <BlockOutlined />,
  generic: <FileOutlined />,
};

const packageTypeLabels: Record<PackageType, string> = {
  maven: 'Maven',
  gradle: 'Gradle',
  npm: 'npm',
  pypi: 'PyPI',
  nuget: 'NuGet',
  go: 'Go',
  rubygems: 'RubyGems',
  docker: 'Docker',
  helm: 'Helm',
  rpm: 'RPM',
  debian: 'Debian',
  conan: 'Conan',
  cargo: 'Cargo',
  generic: 'Generic',
};

const formatDownloadCount = (count: number): string => {
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  }
  if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
};

const formatRelativeTime = (dateString: string): string => {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSeconds = Math.floor(diffMs / 1000);
  const diffMinutes = Math.floor(diffSeconds / 60);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);
  const diffWeeks = Math.floor(diffDays / 7);
  const diffMonths = Math.floor(diffDays / 30);
  const diffYears = Math.floor(diffDays / 365);

  if (diffSeconds < 60) {
    return 'just now';
  } else if (diffMinutes < 60) {
    return `${diffMinutes}m ago`;
  } else if (diffHours < 24) {
    return `${diffHours}h ago`;
  } else if (diffDays < 7) {
    return `${diffDays}d ago`;
  } else if (diffWeeks < 4) {
    return `${diffWeeks}w ago`;
  } else if (diffMonths < 12) {
    return `${diffMonths}mo ago`;
  } else {
    return `${diffYears}y ago`;
  }
};

export const PackageCard: React.FC<PackageCardProps> = ({
  package: pkg,
  onClick,
}) => {
  const handleClick = useCallback(() => {
    if (onClick) {
      onClick(pkg);
    }
  }, [pkg, onClick]);

  const icon = packageTypeIcons[pkg.package_type] || <FileOutlined />;
  const typeLabel = packageTypeLabels[pkg.package_type] || pkg.package_type;

  return (
    <Card
      hoverable
      onClick={handleClick}
      style={{
        borderRadius: borderRadius.lg,
        boxShadow: shadows.sm,
        height: '100%',
        cursor: onClick ? 'pointer' : 'default',
      }}
      styles={{
        body: {
          padding: spacing.md,
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
        },
      }}
    >
      <Space direction="vertical" size="small" style={{ width: '100%', flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: spacing.sm }}>
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: borderRadius.md,
              backgroundColor: colors.bgLayout,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 20,
              color: colors.primary,
              flexShrink: 0,
            }}
          >
            {icon}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <Tooltip title={pkg.name}>
              <Title
                level={5}
                style={{
                  margin: 0,
                  fontSize: 14,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {pkg.name}
              </Title>
            </Tooltip>
            {pkg.latest_version && (
              <Text type="secondary" style={{ fontSize: 12 }}>
                v{pkg.latest_version}
              </Text>
            )}
          </div>
        </div>

        {pkg.description && (
          <Text
            type="secondary"
            style={{
              fontSize: 12,
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
              lineHeight: '1.5',
              minHeight: 36,
            }}
          >
            {pkg.description}
          </Text>
        )}

        <div style={{ marginTop: 'auto', paddingTop: spacing.sm }}>
          <Space size="middle" wrap>
            <Badge
              count={typeLabel}
              style={{
                backgroundColor: colors.bgLayout,
                color: colors.textSecondary,
                fontSize: 11,
                fontWeight: 500,
              }}
            />
          </Space>
        </div>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderTop: `1px solid ${colors.borderLight}`,
            paddingTop: spacing.sm,
            marginTop: spacing.xs,
          }}
        >
          <Tooltip title={`${pkg.total_downloads.toLocaleString()} downloads`}>
            <Space size={4}>
              <DownloadOutlined style={{ color: colors.textTertiary, fontSize: 12 }} />
              <Text type="secondary" style={{ fontSize: 12 }}>
                {formatDownloadCount(pkg.total_downloads)}
              </Text>
            </Space>
          </Tooltip>
          <Tooltip title={new Date(pkg.updated_at).toLocaleString()}>
            <Space size={4}>
              <ClockCircleOutlined style={{ color: colors.textTertiary, fontSize: 12 }} />
              <Text type="secondary" style={{ fontSize: 12 }}>
                {formatRelativeTime(pkg.updated_at)}
              </Text>
            </Space>
          </Tooltip>
        </div>
      </Space>
    </Card>
  );
};

export default PackageCard;
