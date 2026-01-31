import React from 'react';
import { Card, Typography, Row, Col, Tooltip, Divider } from 'antd';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { RepositoryFormat, RepositoryType } from '../../../types';
import { getFormatIcon } from '../../../constants/formatIcons';
import { packageTypeLabels } from '../../../constants/packages';

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

interface CategoryGroup {
  label: string;
  formats: RepositoryFormat[];
}

const categories: CategoryGroup[] = [
  {
    label: 'Language Packages',
    formats: [
      'maven',
      'gradle',
      'npm',
      'pypi',
      'nuget',
      'go',
      'rubygems',
      'cargo',
      'hex',
      'swift',
      'pub',
      'sbt',
      'cran',
      'composer',
      'cocoapods',
    ],
  },
  {
    label: 'JS Ecosystem',
    formats: ['yarn', 'bower', 'pnpm'],
  },
  {
    label: 'Python Ecosystem',
    formats: ['poetry', 'conda', 'conda_native'],
  },
  {
    label: '.NET Ecosystem',
    formats: ['chocolatey', 'powershell'],
  },
  {
    label: 'Containers & OCI',
    formats: ['docker', 'podman', 'buildx', 'helm', 'helm_oci', 'oras', 'wasm_oci'],
  },
  {
    label: 'Linux Distros',
    formats: ['debian', 'rpm', 'alpine', 'opkg'],
  },
  {
    label: 'Infrastructure',
    formats: ['terraform', 'opentofu', 'ansible', 'puppet', 'chef', 'vagrant', 'bazel'],
  },
  {
    label: 'Editor Extensions',
    formats: ['vscode', 'jetbrains'],
  },
  {
    label: 'ML/AI',
    formats: ['huggingface', 'mlmodel'],
  },
  {
    label: 'Other',
    formats: ['gitlfs', 'conan', 'p2', 'generic'],
  },
];

// Build packageFormatOptions from all categories
const packageFormatOptions: PackageFormatOption[] = categories.flatMap((category) =>
  category.formats.map((format) => ({
    format,
    title: packageTypeLabels[format],
    icon: getFormatIcon(format, 24),
    supportedTypes: ['local', 'remote', 'virtual'] as RepositoryType[],
  }))
);

export const PackageTypeSelector: React.FC<PackageTypeSelectorProps> = ({
  value,
  onChange,
  repoType,
}) => {
  const isFormatAvailable = (option: PackageFormatOption): boolean => {
    if (!repoType) return true;
    return option.supportedTypes.includes(repoType);
  };

  const renderFormatCard = (option: PackageFormatOption) => {
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
  };

  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Title level={4} style={{ marginBottom: spacing.lg, textAlign: 'center' }}>
        Select Package Format
      </Title>
      {categories.map((category, index) => {
        const categoryOptions = packageFormatOptions.filter((opt) =>
          category.formats.includes(opt.format)
        );

        return (
          <div key={category.label}>
            {index > 0 && <Divider style={{ margin: `${spacing.lg}px 0` }} />}
            <Title
              level={5}
              style={{
                marginBottom: spacing.md,
                marginTop: index === 0 ? 0 : spacing.md,
                color: colors.textSecondary,
              }}
            >
              {category.label}
            </Title>
            <Row gutter={[spacing.sm, spacing.sm]}>
              {categoryOptions.map((option) => renderFormatCard(option))}
            </Row>
          </div>
        );
      })}
    </div>
  );
};

export default PackageTypeSelector;
