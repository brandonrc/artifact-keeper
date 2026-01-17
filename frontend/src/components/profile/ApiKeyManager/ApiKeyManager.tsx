import React, { useState } from 'react';
import {
  Card,
  Table,
  Button,
  Space,
  Typography,
  Modal,
  Form,
  Input,
  InputNumber,
  Tooltip,
  Tag,
  message,
  Alert,
} from 'antd';
import {
  KeyOutlined,
  PlusOutlined,
  CopyOutlined,
  DeleteOutlined,
  ExclamationCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { ApiKey, CreateApiKeyRequest } from '../../../api';
import { colors } from '../../../styles/tokens';

const { Text, Paragraph } = Typography;

export interface ApiKeyManagerProps {
  apiKeys: ApiKey[];
  onCreate: (data: CreateApiKeyRequest) => Promise<{ key: string; api_key: ApiKey }>;
  onRevoke: (keyId: string) => Promise<void>;
  loading?: boolean;
}

export const ApiKeyManager: React.FC<ApiKeyManagerProps> = ({
  apiKeys,
  onCreate,
  onRevoke,
  loading = false,
}) => {
  const [form] = Form.useForm();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null);
  const [revokeConfirm, setRevokeConfirm] = useState<{ open: boolean; keyId: string; keyName: string }>({
    open: false,
    keyId: '',
    keyName: '',
  });
  const [isRevoking, setIsRevoking] = useState(false);

  const formatDate = (dateString?: string): string => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const isExpired = (expiresAt?: string): boolean => {
    if (!expiresAt) return false;
    return new Date(expiresAt) < new Date();
  };

  const handleCreate = async (values: { name: string; expires_in_days?: number }) => {
    setIsCreating(true);
    try {
      const result = await onCreate({
        name: values.name,
        expires_in_days: values.expires_in_days,
      });
      setNewlyCreatedKey(result.key);
      message.success('API key created successfully');
      form.resetFields();
    } catch (error) {
      message.error('Failed to create API key');
    } finally {
      setIsCreating(false);
    }
  };

  const handleCopyKey = async () => {
    if (newlyCreatedKey) {
      try {
        await navigator.clipboard.writeText(newlyCreatedKey);
        message.success('API key copied to clipboard');
      } catch {
        message.error('Failed to copy API key');
      }
    }
  };

  const handleCloseCreateModal = () => {
    setIsCreateModalOpen(false);
    setNewlyCreatedKey(null);
    form.resetFields();
  };

  const handleRevoke = async () => {
    setIsRevoking(true);
    try {
      await onRevoke(revokeConfirm.keyId);
      message.success('API key revoked successfully');
      setRevokeConfirm({ open: false, keyId: '', keyName: '' });
    } catch (error) {
      message.error('Failed to revoke API key');
    } finally {
      setIsRevoking(false);
    }
  };

  const columns: ColumnsType<ApiKey> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: ApiKey) => (
        <Space>
          <KeyOutlined style={{ color: colors.primary }} />
          <Text strong>{name}</Text>
          {isExpired(record.expires_at) && (
            <Tag color="error">Expired</Tag>
          )}
        </Space>
      ),
    },
    {
      title: 'Key Prefix',
      dataIndex: 'key_prefix',
      key: 'key_prefix',
      render: (prefix: string) => (
        <Text code>{prefix}...</Text>
      ),
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: formatDate,
    },
    {
      title: 'Expires',
      dataIndex: 'expires_at',
      key: 'expires_at',
      render: (date?: string) => (
        <Text type={isExpired(date) ? 'danger' : undefined}>
          {date ? formatDate(date) : 'Never'}
        </Text>
      ),
    },
    {
      title: 'Last Used',
      dataIndex: 'last_used_at',
      key: 'last_used_at',
      render: (date?: string) => (
        <Text type="secondary">{formatDate(date)}</Text>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (_: unknown, record: ApiKey) => (
        <Tooltip title="Revoke key">
          <Button
            type="text"
            danger
            icon={<DeleteOutlined />}
            onClick={() => setRevokeConfirm({
              open: true,
              keyId: record.id,
              keyName: record.name,
            })}
          />
        </Tooltip>
      ),
    },
  ];

  return (
    <>
      <Card
        title={
          <Space>
            <KeyOutlined />
            <span>API Keys</span>
          </Space>
        }
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setIsCreateModalOpen(true)}
          >
            Create API Key
          </Button>
        }
      >
        <Paragraph type="secondary" style={{ marginBottom: 16 }}>
          API keys allow you to authenticate with the API without using your password.
          Keep your API keys secure and never share them publicly.
        </Paragraph>

        <Table
          columns={columns}
          dataSource={apiKeys}
          rowKey="id"
          loading={loading}
          pagination={false}
          locale={{ emptyText: 'No API keys created yet' }}
        />
      </Card>

      {/* Create API Key Modal */}
      <Modal
        title="Create API Key"
        open={isCreateModalOpen}
        onCancel={handleCloseCreateModal}
        footer={
          newlyCreatedKey ? (
            <Button type="primary" onClick={handleCloseCreateModal}>
              Done
            </Button>
          ) : null
        }
        destroyOnClose
      >
        {newlyCreatedKey ? (
          <div>
            <Alert
              type="warning"
              icon={<ExclamationCircleOutlined />}
              message="Save your API key"
              description="This is the only time the full API key will be shown. Please copy and save it securely."
              showIcon
              style={{ marginBottom: 16 }}
            />
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: 12,
                backgroundColor: '#f5f5f5',
                borderRadius: 6,
              }}
            >
              <Text code style={{ flex: 1, wordBreak: 'break-all' }}>
                {newlyCreatedKey}
              </Text>
              <Button
                icon={<CopyOutlined />}
                onClick={handleCopyKey}
              >
                Copy
              </Button>
            </div>
          </div>
        ) : (
          <Form
            form={form}
            layout="vertical"
            onFinish={handleCreate}
          >
            <Form.Item
              label="Name"
              name="name"
              rules={[
                { required: true, message: 'Please enter a name for the API key' },
                { max: 100, message: 'Name must be at most 100 characters' },
              ]}
            >
              <Input placeholder="e.g., CI/CD Pipeline, Local Development" />
            </Form.Item>

            <Form.Item
              label="Expires In (days)"
              name="expires_in_days"
              extra="Leave empty for a key that never expires"
            >
              <InputNumber
                min={1}
                max={365}
                placeholder="Optional"
                style={{ width: '100%' }}
              />
            </Form.Item>

            <Form.Item style={{ marginBottom: 0, marginTop: 24 }}>
              <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
                <Button onClick={handleCloseCreateModal}>Cancel</Button>
                <Button type="primary" htmlType="submit" loading={isCreating}>
                  Create
                </Button>
              </Space>
            </Form.Item>
          </Form>
        )}
      </Modal>

      {/* Revoke Confirmation Modal */}
      <Modal
        title={
          <Space>
            <ExclamationCircleOutlined style={{ color: colors.error }} />
            <span>Revoke API Key</span>
          </Space>
        }
        open={revokeConfirm.open}
        onCancel={() => setRevokeConfirm({ open: false, keyId: '', keyName: '' })}
        onOk={handleRevoke}
        okText="Revoke"
        okButtonProps={{ danger: true, loading: isRevoking }}
        cancelButtonProps={{ disabled: isRevoking }}
      >
        <Paragraph>
          Are you sure you want to revoke the API key <Text strong>"{revokeConfirm.keyName}"</Text>?
        </Paragraph>
        <Paragraph type="secondary">
          Any applications using this key will no longer be able to authenticate.
          This action cannot be undone.
        </Paragraph>
      </Modal>
    </>
  );
};

export default ApiKeyManager;
