import React, { useState, useEffect } from 'react';
import { Form, Transfer, Select, Typography, Space, Alert, Card, Empty } from 'antd';
import type { FormInstance, TransferProps } from 'antd';
import {
  ClusterOutlined,
  OrderedListOutlined,
  DeploymentUnitOutlined,
  ArrowUpOutlined,
  ArrowDownOutlined,
} from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';
import type { Repository } from '../../../types';

const { Title, Text } = Typography;

export interface VirtualRepoConfigFormValues {
  included_repositories: string[];
  repository_order: string[];
  default_deployment_repo?: string;
}

export interface VirtualRepoConfigProps {
  form: FormInstance<VirtualRepoConfigFormValues>;
  availableRepos: Repository[];
}

interface TransferItem {
  key: string;
  title: string;
  description: string;
  format: string;
}

export const VirtualRepoConfig: React.FC<VirtualRepoConfigProps> = ({
  form,
  availableRepos,
}) => {
  const [targetKeys, setTargetKeys] = useState<string[]>([]);
  const [repoOrder, setRepoOrder] = useState<string[]>([]);

  const selectedRepos = Form.useWatch('included_repositories', form) || [];

  useEffect(() => {
    setTargetKeys(selectedRepos);
    setRepoOrder(selectedRepos);
  }, [selectedRepos]);

  const transferDataSource: TransferItem[] = availableRepos
    .filter((repo) => repo.repo_type !== 'virtual')
    .map((repo) => ({
      key: repo.key,
      title: repo.name,
      description: `${repo.format.toUpperCase()} - ${repo.repo_type}`,
      format: repo.format,
    }));

  const handleTransferChange: TransferProps['onChange'] = (newTargetKeys) => {
    const stringKeys = newTargetKeys as string[];
    setTargetKeys(stringKeys);
    form.setFieldValue('included_repositories', stringKeys);

    const newOrder = stringKeys.filter((key) => !repoOrder.includes(key));
    const updatedOrder = [...repoOrder.filter((key) => stringKeys.includes(key)), ...newOrder];
    setRepoOrder(updatedOrder);
    form.setFieldValue('repository_order', updatedOrder);
  };

  const moveRepoUp = (index: number) => {
    if (index <= 0) return;
    const newOrder = [...repoOrder];
    [newOrder[index - 1], newOrder[index]] = [newOrder[index], newOrder[index - 1]];
    setRepoOrder(newOrder);
    form.setFieldValue('repository_order', newOrder);
  };

  const moveRepoDown = (index: number) => {
    if (index >= repoOrder.length - 1) return;
    const newOrder = [...repoOrder];
    [newOrder[index], newOrder[index + 1]] = [newOrder[index + 1], newOrder[index]];
    setRepoOrder(newOrder);
    form.setFieldValue('repository_order', newOrder);
  };

  const deploymentRepoOptions = repoOrder
    .filter((key) => {
      const repo = availableRepos.find((r) => r.key === key);
      return repo?.repo_type === 'local';
    })
    .map((key) => {
      const repo = availableRepos.find((r) => r.key === key);
      return {
        label: repo?.name || key,
        value: key,
      };
    });

  const renderTransferItem = (item: TransferItem) => (
    <span>
      <Text strong>{item.title}</Text>
      <Text type="secondary" style={{ marginLeft: spacing.xs, fontSize: 12 }}>
        ({item.description})
      </Text>
    </span>
  );

  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Title level={4} style={{ marginBottom: spacing.lg, textAlign: 'center' }}>
        <Space>
          <ClusterOutlined />
          <span>Virtual Repository Settings</span>
        </Space>
      </Title>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: spacing.lg, maxWidth: 800, margin: `0 auto ${spacing.lg}px` }}
        message="Virtual Repository Configuration"
        description="A virtual repository aggregates multiple repositories under a single URL. Select which repositories to include and define their resolution order."
      />

      <Form
        form={form}
        layout="vertical"
        initialValues={{
          included_repositories: [],
          repository_order: [],
        }}
      >
        <Form.Item
          name="included_repositories"
          label={
            <Space>
              <DeploymentUnitOutlined />
              <span>Select Repositories</span>
            </Space>
          }
          rules={[
            { required: true, message: 'Please select at least one repository' },
            {
              validator: (_, value) =>
                value && value.length > 0
                  ? Promise.resolve()
                  : Promise.reject(new Error('At least one repository is required')),
            },
          ]}
          extra="Choose which repositories to include in this virtual repository."
        >
          <Transfer
            dataSource={transferDataSource}
            targetKeys={targetKeys}
            onChange={handleTransferChange}
            render={renderTransferItem}
            titles={['Available', 'Included']}
            listStyle={{
              width: 350,
              height: 300,
            }}
            showSearch
            filterOption={(inputValue, item) =>
              item.title.toLowerCase().includes(inputValue.toLowerCase()) ||
              item.description.toLowerCase().includes(inputValue.toLowerCase())
            }
            style={{ justifyContent: 'center' }}
          />
        </Form.Item>

        <Form.Item
          name="repository_order"
          label={
            <Space>
              <OrderedListOutlined />
              <span>Repository Resolution Order</span>
            </Space>
          }
          extra="Artifacts are resolved in the order shown below. Drag to reorder or use the arrows."
          style={{ maxWidth: 600, margin: '0 auto' }}
        >
          {repoOrder.length > 0 ? (
            <div
              style={{
                border: `1px solid ${colors.border}`,
                borderRadius: borderRadius.md,
                backgroundColor: colors.bgContainer,
              }}
            >
              {repoOrder.map((key, index) => {
                const repo = availableRepos.find((r) => r.key === key);
                return (
                  <div
                    key={key}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      padding: `${spacing.sm}px ${spacing.md}px`,
                      borderBottom:
                        index < repoOrder.length - 1 ? `1px solid ${colors.borderLight}` : 'none',
                    }}
                  >
                    <Text
                      style={{
                        width: 24,
                        color: colors.textTertiary,
                        fontWeight: 500,
                      }}
                    >
                      {index + 1}.
                    </Text>
                    <div style={{ flex: 1 }}>
                      <Text strong>{repo?.name || key}</Text>
                      <Text type="secondary" style={{ marginLeft: spacing.xs, fontSize: 12 }}>
                        ({repo?.format.toUpperCase()} - {repo?.repo_type})
                      </Text>
                    </div>
                    <Space size="small">
                      <ArrowUpOutlined
                        style={{
                          cursor: index > 0 ? 'pointer' : 'not-allowed',
                          color: index > 0 ? colors.textSecondary : colors.textDisabled,
                        }}
                        onClick={() => moveRepoUp(index)}
                      />
                      <ArrowDownOutlined
                        style={{
                          cursor: index < repoOrder.length - 1 ? 'pointer' : 'not-allowed',
                          color:
                            index < repoOrder.length - 1
                              ? colors.textSecondary
                              : colors.textDisabled,
                        }}
                        onClick={() => moveRepoDown(index)}
                      />
                    </Space>
                  </div>
                );
              })}
            </div>
          ) : (
            <Card
              style={{
                borderRadius: borderRadius.md,
                textAlign: 'center',
              }}
            >
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="No repositories selected"
              />
            </Card>
          )}
        </Form.Item>

        {deploymentRepoOptions.length > 0 && (
          <Form.Item
            name="default_deployment_repo"
            label={
              <Space>
                <DeploymentUnitOutlined />
                <span>Default Deployment Repository</span>
              </Space>
            }
            extra="When deploying artifacts to this virtual repository, they will be stored in the selected local repository."
            style={{ maxWidth: 600, margin: `${spacing.lg}px auto 0` }}
          >
            <Select
              placeholder="Select a local repository for deployments"
              options={deploymentRepoOptions}
              allowClear
              style={{ width: '100%' }}
            />
          </Form.Item>
        )}

        {repoOrder.length > 0 && deploymentRepoOptions.length === 0 && (
          <Alert
            type="warning"
            showIcon
            style={{ maxWidth: 600, margin: `${spacing.lg}px auto 0` }}
            message="No Local Repositories"
            description="To enable deployment to this virtual repository, include at least one local repository."
          />
        )}
      </Form>
    </div>
  );
};

export default VirtualRepoConfig;
