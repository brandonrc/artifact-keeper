import React from 'react';
import { Form, Input, Switch, Typography, Space, Alert } from 'antd';
import type { FormInstance } from 'antd';
import {
  KeyOutlined,
  EditOutlined,
  FileTextOutlined,
  GlobalOutlined,
  LockOutlined,
} from '@ant-design/icons';
import { colors, spacing } from '../../../styles/tokens';
import type { RepositoryFormat, RepositoryType } from '../../../types';

const { Title, Text } = Typography;
const { TextArea } = Input;

export interface BasicConfigFormValues {
  key: string;
  name: string;
  description?: string;
  is_public: boolean;
}

export interface BasicConfigStepProps {
  form: FormInstance<BasicConfigFormValues>;
  repoType?: RepositoryType;
  packageType?: RepositoryFormat;
}

const repoTypeLabels: Record<RepositoryType, string> = {
  local: 'Local',
  remote: 'Remote',
  virtual: 'Virtual',
};

export const BasicConfigStep: React.FC<BasicConfigStepProps> = ({
  form,
  repoType,
  packageType,
}) => {
  const handleKeyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
      .toLowerCase()
      .replace(/[^a-z0-9-_]/g, '-')
      .replace(/--+/g, '-')
      .replace(/^-/, '');
    form.setFieldValue('key', value);
  };

  return (
    <div style={{ padding: `${spacing.md}px 0`, maxWidth: 600, margin: '0 auto' }}>
      <Title level={4} style={{ marginBottom: spacing.lg, textAlign: 'center' }}>
        Basic Configuration
      </Title>

      {repoType && packageType && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: spacing.lg }}
          message={
            <Space>
              <Text>
                Creating a <Text strong>{repoTypeLabels[repoType]}</Text> repository
                for <Text strong>{packageType.toUpperCase()}</Text> packages
              </Text>
            </Space>
          }
        />
      )}

      <Form
        form={form}
        layout="vertical"
        initialValues={{
          is_public: false,
        }}
      >
        <Form.Item
          name="key"
          label={
            <Space>
              <KeyOutlined />
              <span>Repository Key</span>
            </Space>
          }
          rules={[
            { required: true, message: 'Please enter a repository key' },
            { min: 2, message: 'Key must be at least 2 characters' },
            { max: 64, message: 'Key must be at most 64 characters' },
            {
              pattern: /^[a-z0-9][a-z0-9-_]*[a-z0-9]$|^[a-z0-9]$/,
              message: 'Key must start and end with alphanumeric characters, and contain only lowercase letters, numbers, hyphens, and underscores',
            },
          ]}
          extra="A unique identifier for this repository. Used in URLs and API calls."
        >
          <Input
            placeholder="my-repo"
            onChange={handleKeyChange}
            prefix={<KeyOutlined style={{ color: colors.textTertiary }} />}
            autoComplete="off"
          />
        </Form.Item>

        <Form.Item
          name="name"
          label={
            <Space>
              <EditOutlined />
              <span>Display Name</span>
            </Space>
          }
          rules={[
            { required: true, message: 'Please enter a display name' },
            { max: 128, message: 'Name must be at most 128 characters' },
          ]}
          extra="A human-readable name for this repository."
        >
          <Input
            placeholder="My Repository"
            prefix={<EditOutlined style={{ color: colors.textTertiary }} />}
            autoComplete="off"
          />
        </Form.Item>

        <Form.Item
          name="description"
          label={
            <Space>
              <FileTextOutlined />
              <span>Description</span>
            </Space>
          }
          rules={[
            { max: 500, message: 'Description must be at most 500 characters' },
          ]}
          extra="Optional description to help users understand the purpose of this repository."
        >
          <TextArea
            placeholder="Enter a description for this repository..."
            rows={3}
            showCount
            maxLength={500}
          />
        </Form.Item>

        <Form.Item
          name="is_public"
          label={
            <Space>
              {form.getFieldValue('is_public') ? <GlobalOutlined /> : <LockOutlined />}
              <span>Visibility</span>
            </Space>
          }
          valuePropName="checked"
          extra={
            <Text type="secondary" style={{ fontSize: 12 }}>
              {form.getFieldValue('is_public')
                ? 'Anyone can browse and download artifacts from this repository.'
                : 'Only users with explicit permissions can access this repository.'}
            </Text>
          }
        >
          <Switch
            checkedChildren={
              <Space size={4}>
                <GlobalOutlined />
                <span>Public</span>
              </Space>
            }
            unCheckedChildren={
              <Space size={4}>
                <LockOutlined />
                <span>Private</span>
              </Space>
            }
          />
        </Form.Item>
      </Form>
    </div>
  );
};

export default BasicConfigStep;
