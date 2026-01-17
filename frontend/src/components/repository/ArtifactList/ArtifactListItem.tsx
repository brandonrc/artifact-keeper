import React, { useCallback } from 'react';
import { Button, Space, Tooltip, Typography, message } from 'antd';
import {
  DownloadOutlined,
  CopyOutlined,
  DeleteOutlined,
  FileOutlined,
  FileImageOutlined,
  FileZipOutlined,
  FileTextOutlined,
  FilePdfOutlined,
  CodeOutlined,
} from '@ant-design/icons';
import type { Artifact } from '../../../types';
import { colors } from '../../../styles/tokens';

const { Text } = Typography;

/**
 * Format bytes into human-readable file size
 */
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const size = bytes / Math.pow(k, i);

  return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
};

/**
 * Format date string into relative time
 */
export const formatRelativeTime = (dateString: string): string => {
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
    return `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
  } else if (diffHours < 24) {
    return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
  } else if (diffDays < 7) {
    return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
  } else if (diffWeeks < 4) {
    return `${diffWeeks} week${diffWeeks === 1 ? '' : 's'} ago`;
  } else if (diffMonths < 12) {
    return `${diffMonths} month${diffMonths === 1 ? '' : 's'} ago`;
  } else {
    return `${diffYears} year${diffYears === 1 ? '' : 's'} ago`;
  }
};

/**
 * Get appropriate file icon based on content type
 */
export const getFileIcon = (contentType: string): React.ReactNode => {
  const iconStyle = { fontSize: 20, color: colors.textSecondary };

  if (contentType.startsWith('image/')) {
    return <FileImageOutlined style={iconStyle} />;
  }
  if (contentType.includes('zip') || contentType.includes('tar') || contentType.includes('gzip') || contentType.includes('compressed')) {
    return <FileZipOutlined style={iconStyle} />;
  }
  if (contentType.includes('pdf')) {
    return <FilePdfOutlined style={iconStyle} />;
  }
  if (contentType.includes('text') || contentType.includes('xml') || contentType.includes('json')) {
    return <FileTextOutlined style={iconStyle} />;
  }
  if (contentType.includes('javascript') || contentType.includes('typescript') || contentType.includes('java') || contentType.includes('python')) {
    return <CodeOutlined style={iconStyle} />;
  }

  return <FileOutlined style={iconStyle} />;
};

export interface ArtifactListItemProps {
  artifact: Artifact;
  onDownload: (artifact: Artifact) => void;
  onDelete: (artifact: Artifact) => void;
  disabled?: boolean;
}

export const ArtifactListItem: React.FC<ArtifactListItemProps> = ({
  artifact,
  onDownload,
  onDelete,
  disabled = false,
}) => {
  const handleCopyPath = useCallback(async () => {
    const fullPath = `${artifact.repository_key}/${artifact.path}`;
    try {
      await navigator.clipboard.writeText(fullPath);
      message.success('Path copied to clipboard');
    } catch {
      message.error('Failed to copy path');
    }
  }, [artifact]);

  const handleDownload = useCallback(() => {
    onDownload(artifact);
  }, [artifact, onDownload]);

  const handleDelete = useCallback(() => {
    onDelete(artifact);
  }, [artifact, onDelete]);

  return (
    <Space size="small">
      <Tooltip title="Download">
        <Button
          type="text"
          icon={<DownloadOutlined />}
          onClick={handleDownload}
          disabled={disabled}
          aria-label={`Download ${artifact.name}`}
        />
      </Tooltip>
      <Tooltip title="Copy Path">
        <Button
          type="text"
          icon={<CopyOutlined />}
          onClick={handleCopyPath}
          disabled={disabled}
          aria-label={`Copy path for ${artifact.name}`}
        />
      </Tooltip>
      <Tooltip title="Delete">
        <Button
          type="text"
          danger
          icon={<DeleteOutlined />}
          onClick={handleDelete}
          disabled={disabled}
          aria-label={`Delete ${artifact.name}`}
        />
      </Tooltip>
    </Space>
  );
};

/**
 * Render artifact name with icon
 */
export const renderArtifactName = (artifact: Artifact): React.ReactNode => {
  return (
    <Space>
      {getFileIcon(artifact.content_type)}
      <Text strong style={{ color: colors.textPrimary }}>
        {artifact.name}
      </Text>
    </Space>
  );
};

/**
 * Render formatted file size
 */
export const renderFileSize = (sizeBytes: number): React.ReactNode => {
  return <Text type="secondary">{formatFileSize(sizeBytes)}</Text>;
};

/**
 * Render relative time with tooltip showing full date
 */
export const renderRelativeTime = (dateString: string): React.ReactNode => {
  const fullDate = new Date(dateString).toLocaleString();
  return (
    <Tooltip title={fullDate}>
      <Text type="secondary">{formatRelativeTime(dateString)}</Text>
    </Tooltip>
  );
};

export default ArtifactListItem;
