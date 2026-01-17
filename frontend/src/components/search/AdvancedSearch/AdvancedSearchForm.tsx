import React, { useState } from 'react';
import { Tabs, Form, Button, Space, Typography } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import type { FormInstance } from 'antd';
import { colors, spacing } from '../../../styles/tokens';
import { PackageSearchTab } from './PackageSearchTab';
import { PropertySearchTab } from './PropertySearchTab';
import { ChecksumSearchTab } from './ChecksumSearchTab';
import { GAVCSearchTab } from './GAVCSearchTab';

const { Title } = Typography;

export type SearchTabType = 'package' | 'property' | 'checksum' | 'gavc';

export interface AdvancedSearchValues {
  package?: {
    name?: string;
    version?: string;
    repository?: string;
    format?: string;
  };
  property?: {
    matchType: 'exact' | 'contains' | 'regex';
    filters: Array<{ key: string; value: string }>;
  };
  checksum?: {
    type: 'md5' | 'sha1' | 'sha256' | 'sha512';
    value?: string;
  };
  gavc?: {
    groupId?: string;
    artifactId?: string;
    version?: string;
    classifier?: string;
  };
}

export interface AdvancedSearchFormProps {
  onSearch: (values: AdvancedSearchValues, activeTab: SearchTabType) => void;
  loading?: boolean;
  defaultTab?: SearchTabType;
}

const tabItems = [
  {
    key: 'package' as SearchTabType,
    label: 'Package',
  },
  {
    key: 'property' as SearchTabType,
    label: 'Property',
  },
  {
    key: 'checksum' as SearchTabType,
    label: 'Checksum',
  },
  {
    key: 'gavc' as SearchTabType,
    label: 'GAVC',
  },
];

export const AdvancedSearchForm: React.FC<AdvancedSearchFormProps> = ({
  onSearch,
  loading = false,
  defaultTab = 'package',
}) => {
  const [form] = Form.useForm<AdvancedSearchValues>();
  const [activeTab, setActiveTab] = useState<SearchTabType>(defaultTab);

  const handleTabChange = (key: string) => {
    setActiveTab(key as SearchTabType);
  };

  const handleSubmit = (values: AdvancedSearchValues) => {
    onSearch(values, activeTab);
  };

  const renderTabContent = (tabKey: SearchTabType) => {
    switch (tabKey) {
      case 'package':
        return <PackageSearchTab form={form} />;
      case 'property':
        return <PropertySearchTab form={form} />;
      case 'checksum':
        return <ChecksumSearchTab form={form} />;
      case 'gavc':
        return <GAVCSearchTab form={form} />;
      default:
        return null;
    }
  };

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={handleSubmit}
      initialValues={{
        checksum: { type: 'sha256' },
        property: { matchType: 'exact', filters: [] },
      }}
    >
      <Tabs
        activeKey={activeTab}
        onChange={handleTabChange}
        items={tabItems.map((item) => ({
          key: item.key,
          label: item.label,
          children: renderTabContent(item.key),
        }))}
      />

      <Form.Item style={{ marginTop: spacing.lg, marginBottom: 0 }}>
        <Button
          type="primary"
          htmlType="submit"
          icon={<SearchOutlined />}
          loading={loading}
          size="large"
        >
          Search
        </Button>
      </Form.Item>
    </Form>
  );
};

export default AdvancedSearchForm;
