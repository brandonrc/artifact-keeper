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
  Select,
  Tooltip,
  Tag,
  message,
  Alert,
} from 'antd';
import {
  SafetyOutlined,
  PlusOutlined,
  CopyOutlined,
  DeleteOutlined,
  ExclamationCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { AccessToken, CreateAccessTokenRequest } from '../../../api';
import { colors } from '../../../styles/tokens';

const { Text, Paragraph } = Typography;

export interface AccessTokenManagerProps {
  accessTokens: AccessToken[];
  onCreate: (data: CreateAccessTokenRequest) => Promise<{ token: string; access_token: AccessToken }>;
  onRevoke: (tokenId: string) => Promise<void>;
  loading?: boolean;
}

const AVAILABLE_SCOPES = [
  { value: 'read:artifacts', label: 'Read Artifacts' },
  { value: 'write:artifacts', label: 'Write Artifacts' },
  { value: 'delete:artifacts', label: 'Delete Artifacts' },
  { value: 'read:repositories', label: 'Read Repositories' },
  { value: 'admin:repositories', label: 'Admin Repositories' },
  { value: 'read:builds', label: 'Read Builds' },
  { value: 'write:builds', label: 'Write Builds' },
];

export const AccessTokenManager: React.FC<AccessTokenManagerProps> = ({
  accessTokens,
  onCreate,
  onRevoke,
  loading = false,
}) => {
  const [form] = Form.useForm();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [newlyCreatedToken, setNewlyCreatedToken] = useState<string | null>(null);
  const [revokeConfirm, setRevokeConfirm] = useState<{ open: boolean; tokenId: string; tokenName: string }>({
    open: false,
    tokenId: '',
    tokenName: '',
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

  const getExpiryStatus = (expiresAt?: string): { color: string; text: string } => {
    if (!expiresAt) return { color: 'default', text: 'Never expires' };

    const expiryDate = new Date(expiresAt);
    const now = new Date();
    const daysUntilExpiry = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

    if (daysUntilExpiry < 0) {
      return { color: 'error', text: 'Expired' };
    } else if (daysUntilExpiry <= 7) {
      return { color: 'warning', text: `Expires in ${daysUntilExpiry} day${daysUntilExpiry === 1 ? '' : 's'}` };
    } else if (daysUntilExpiry <= 30) {
      return { color: 'gold', text: formatDate(expiresAt) };
    }
    return { color: 'default', text: formatDate(expiresAt) };
  };

  const handleCreate = async (values: { name: string; expires_in_days?: number; scopes?: string[] }) => {
    setIsCreating(true);
    try {
      const result = await onCreate({
        name: values.name,
        expires_in_days: values.expires_in_days,
        scopes: values.scopes,
      });
      setNewlyCreatedToken(result.token);
      message.success('Access token created successfully');
      form.resetFields();
    } catch (error) {
      message.error('Failed to create access token');
    } finally {
      setIsCreating(false);
    }
  };

  const handleCopyToken = async () => {
    if (newlyCreatedToken) {
      try {
        await navigator.clipboard.writeText(newlyCreatedToken);
        message.success('Access token copied to clipboard');
      } catch {
        message.error('Failed to copy access token');
      }
    }
  };

  const handleCloseCreateModal = () => {
    setIsCreateModalOpen(false);
    setNewlyCreatedToken(null);
    form.resetFields();
  };

  const handleRevoke = async () => {
    setIsRevoking(true);
    try {
      await onRevoke(revokeConfirm.tokenId);
      message.success('Access token revoked successfully');
      setRevokeConfirm({ open: false, tokenId: '', tokenName: '' });
    } catch (error) {
      message.error('Failed to revoke access token');
    } finally {
      setIsRevoking(false);
    }
  };

  const columns: ColumnsType<AccessToken> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: AccessToken) => (
        <Space>
          <SafetyOutlined style={{ color: colors.info }} />
          <Text strong>{name}</Text>
          {isExpired(record.expires_at) && (
            <Tag color="error">Expired</Tag>
          )}
        </Space>
      ),
    },
    {
      title: 'Token Prefix',
      dataIndex: 'token_prefix',
      key: 'token_prefix',
      render: (prefix: string) => (
        <Text code>{prefix}...</Text>
      ),
    },
    {
      title: 'Scopes',
      dataIndex: 'scopes',
      key: 'scopes',
      render: (scopes?: string[]) => (
        <Space wrap size={[4, 4]}>
          {scopes && scopes.length > 0 ? (
            scopes.map((scope) => (
              <Tag key={scope} color="blue">{scope}</Tag>
            ))
          ) : (
            <Text type="secondary">All scopes</Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Expires',
      dataIndex: 'expires_at',
      key: 'expires_at',
      render: (date?: string) => {
        const status = getExpiryStatus(date);
        return <Tag color={status.color}>{status.text}</Tag>;
      },
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
      render: (_: unknown, record: AccessToken) => (
        <Tooltip title="Revoke token">
          <Button
            type="text"
            danger
            icon={<DeleteOutlined />}
            onClick={() => setRevokeConfirm({
              open: true,
              tokenId: record.id,
              tokenName: record.name,
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
            <SafetyOutlined />
            <span>Access Tokens</span>
          </Space>
        }
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setIsCreateModalOpen(true)}
          >
            Create Access Token
          </Button>
        }
      >
        <Paragraph type="secondary" style={{ marginBottom: 16 }}>
          Access tokens provide scoped access to the API. Use them for applications
          that need limited permissions.
        </Paragraph>

        <Table
          columns={columns}
          dataSource={accessTokens}
          rowKey="id"
          loading={loading}
          pagination={false}
          locale={{ emptyText: 'No access tokens created yet' }}
        />
      </Card>

      {/* Create Access Token Modal */}
      <Modal
        title="Create Access Token"
        open={isCreateModalOpen}
        onCancel={handleCloseCreateModal}
        footer={
          newlyCreatedToken ? (
            <Button type="primary" onClick={handleCloseCreateModal}>
              Done
            </Button>
          ) : null
        }
        destroyOnClose
        width={520}
      >
        {newlyCreatedToken ? (
          <div>
            <Alert
              type="warning"
              icon={<ExclamationCircleOutlined />}
              message="Save your access token"
              description="This is the only time the full access token will be shown. Please copy and save it securely."
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
                {newlyCreatedToken}
              </Text>
              <Button
                icon={<CopyOutlined />}
                onClick={handleCopyToken}
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
                { required: true, message: 'Please enter a name for the access token' },
                { max: 100, message: 'Name must be at most 100 characters' },
              ]}
            >
              <Input placeholder="e.g., Build Server Token, Read-Only Access" />
            </Form.Item>

            <Form.Item
              label="Scopes"
              name="scopes"
              extra="Select specific scopes or leave empty for full access"
            >
              <Select
                mode="multiple"
                placeholder="Select scopes (optional)"
                options={AVAILABLE_SCOPES}
                allowClear
              />
            </Form.Item>

            <Form.Item
              label="Expires In (days)"
              name="expires_in_days"
              extra="Leave empty for a token that never expires"
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
            <span>Revoke Access Token</span>
          </Space>
        }
        open={revokeConfirm.open}
        onCancel={() => setRevokeConfirm({ open: false, tokenId: '', tokenName: '' })}
        onOk={handleRevoke}
        okText="Revoke"
        okButtonProps={{ danger: true, loading: isRevoking }}
        cancelButtonProps={{ disabled: isRevoking }}
      >
        <Paragraph>
          Are you sure you want to revoke the access token <Text strong>"{revokeConfirm.tokenName}"</Text>?
        </Paragraph>
        <Paragraph type="secondary">
          Any applications using this token will no longer be able to authenticate.
          This action cannot be undone.
        </Paragraph>
      </Modal>
    </>
  );
};

export default AccessTokenManager;
