import React from 'react';
import { Card, Typography, Row, Col, Tooltip } from 'antd';
import {
  CodeOutlined,
  BoxPlotOutlined,
  ContainerOutlined,
  CloudServerOutlined,
  AppstoreOutlined,
  BuildOutlined,
  BlockOutlined,
  SettingOutlined,
  FileOutlined,
  DeploymentUnitOutlined,
  FileZipOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { RepositoryFormat, RepositoryType } from '../../../types';

const { Text, Title } = Typography;

export interface PackageTypeSelectorProps {
  value?: RepositoryFormat;
  onChange: (format: RepositoryFormat) => void;
  repoType?: RepositoryType;
}

interface PackageFormatOption {
  format: RepositoryFormat;
  title: string;
  icon: React.ReactNode;
  supportedTypes: RepositoryType[];
}

const packageFormatOptions: PackageFormatOption[] = [
  {
    format: 'maven',
    title: 'Maven',
    icon: <BuildOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'npm',
    title: 'npm',
    icon: <BoxPlotOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'pypi',
    title: 'PyPI',
    icon: <CodeOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'docker',
    title: 'Docker',
    icon: <ContainerOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'helm',
    title: 'Helm',
    icon: <CloudServerOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'nuget',
    title: 'NuGet',
    icon: <AppstoreOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'cargo',
    title: 'Cargo',
    icon: <BlockOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'go',
    title: 'Go',
    icon: <DeploymentUnitOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'rpm',
    title: 'RPM',
    icon: <SettingOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'debian',
    title: 'Debian',
    icon: <FileZipOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
  {
    format: 'generic',
    title: 'Generic',
    icon: <FileOutlined style={{ fontSize: 24 }} />,
    supportedTypes: ['local', 'remote', 'virtual'],
  },
];

export const PackageTypeSelector: React.FC<PackageTypeSelectorProps> = ({
  value,
  onChange,
  repoType,
}) => {
  const isFormatAvailable = (option: PackageFormatOption): boolean => {
    if (!repoType) return true;
    return option.supportedTypes.includes(repoType);
  };

  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Title level={4} style={{ marginBottom: spacing.lg, textAlign: 'center' }}>
        Select Package Format
      </Title>
      <Row gutter={[spacing.sm, spacing.sm]} justify="center">
        {packageFormatOptions.map((option) => {
          const isSelected = value === option.format;
          const isAvailable = isFormatAvailable(option);

          const card = (
            <Card
              hoverable={isAvailable}
              onClick={() => isAvailable && onChange(option.format)}
              style={{
                borderRadius: borderRadius.md,
                borderColor: isSelected ? colors.primary : colors.border,
                borderWidth: isSelected ? 2 : 1,
                backgroundColor: isSelected
                  ? colors.bgContainerLight
                  : !isAvailable
                  ? colors.bgLayout
                  : colors.bgContainer,
                cursor: isAvailable ? 'pointer' : 'not-allowed',
                opacity: isAvailable ? 1 : 0.5,
                transition: 'all 0.2s ease',
                height: '100%',
              }}
              styles={{
                body: {
                  padding: spacing.md,
                  textAlign: 'center',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  minHeight: 100,
                },
              }}
            >
              <div
                style={{
                  width: 48,
                  height: 48,
                  borderRadius: borderRadius.lg,
                  backgroundColor: isSelected ? colors.primary : colors.bgLayout,
                  color: isSelected ? '#fff' : colors.textSecondary,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginBottom: spacing.xs,
                  transition: 'all 0.2s ease',
                }}
              >
                {option.icon}
              </div>
              <Text
                strong
                style={{
                  fontSize: 13,
                  color: isSelected ? colors.primary : colors.textPrimary,
                }}
              >
                {option.title}
              </Text>
            </Card>
          );

          return (
            <Col key={option.format} xs={8} sm={6} md={4} lg={4}>
              {!isAvailable ? (
                <Tooltip title={`Not available for ${repoType} repositories`}>
                  {card}
                </Tooltip>
              ) : (
                card
              )}
            </Col>
          );
        })}
      </Row>
    </div>
  );
};

export default PackageTypeSelector;
