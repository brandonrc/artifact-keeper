import React from 'react';
import { Descriptions, Button, Space, Typography, Tooltip, message } from 'antd';
import { CopyOutlined } from '@ant-design/icons';
import type { Artifact } from '../../../types';
import { colors } from '../../../styles/tokens';

const { Text } = Typography;

export interface GeneralTabProps {
  artifact: Artifact;
}

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

const CopyableValue: React.FC<{ value: string; label: string }> = ({
  value,
  label,
}) => {
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      message.success(`${label} copied to clipboard`);
    } catch {
      message.error('Failed to copy to clipboard');
    }
  };

  return (
    <Space>
      <Text
        style={{
          fontFamily: 'monospace',
          fontSize: 13,
          wordBreak: 'break-all',
        }}
      >
        {value}
      </Text>
      <Tooltip title={`Copy ${label.toLowerCase()}`}>
        <Button
          type="text"
          size="small"
          icon={<CopyOutlined />}
          onClick={handleCopy}
          style={{ color: colors.textSecondary }}
        />
      </Tooltip>
    </Space>
  );
};

export const GeneralTab: React.FC<GeneralTabProps> = ({ artifact }) => {
  return (
    <Descriptions
      bordered
      column={1}
      size="small"
      labelStyle={{
        width: 150,
        fontWeight: 500,
        backgroundColor: colors.bgLayout,
      }}
      contentStyle={{
        backgroundColor: colors.bgContainer,
      }}
    >
      <Descriptions.Item label="Path">
        <CopyableValue value={artifact.path} label="Path" />
      </Descriptions.Item>

      <Descriptions.Item label="Size">
        <Text>{formatBytes(artifact.size_bytes)}</Text>
        <Text type="secondary" style={{ marginLeft: 8 }}>
          ({artifact.size_bytes.toLocaleString()} bytes)
        </Text>
      </Descriptions.Item>

      <Descriptions.Item label="Checksum (SHA256)">
        <CopyableValue value={artifact.checksum_sha256} label="Checksum" />
      </Descriptions.Item>

      <Descriptions.Item label="Content Type">
        <Text>{artifact.content_type}</Text>
      </Descriptions.Item>

      <Descriptions.Item label="Download Count">
        <Text>{artifact.download_count.toLocaleString()}</Text>
      </Descriptions.Item>

      <Descriptions.Item label="Created At">
        <Text>{formatDate(artifact.created_at)}</Text>
      </Descriptions.Item>

      {artifact.version && (
        <Descriptions.Item label="Version">
          <Text>{artifact.version}</Text>
        </Descriptions.Item>
      )}

      <Descriptions.Item label="Repository">
        <Text>{artifact.repository_key}</Text>
      </Descriptions.Item>
    </Descriptions>
  );
};

export default GeneralTab;
