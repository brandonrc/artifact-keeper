import React from 'react';
import { Typography, Tooltip } from 'antd';
import {
  FolderOutlined,
  FolderOpenOutlined,
  FileOutlined,
  DatabaseOutlined,
  CodeOutlined,
  BoxPlotOutlined,
  AppstoreOutlined,
} from '@ant-design/icons';
import { TreeNode } from '../../../types';
import { colors } from '../../../styles/tokens';
import { getRepoTypeColor, getPackageTypeColor } from '../../../styles/theme';

const { Text } = Typography;

/**
 * Props for RepositoryTreeNode component
 */
export interface RepositoryTreeNodeProps {
  /** The tree node data */
  node: TreeNode;
  /** Whether the node is currently expanded */
  isExpanded?: boolean;
  /** Whether to show file size for artifacts */
  showSize?: boolean;
  /** Context menu handler */
  onContextMenu?: (event: React.MouseEvent, node: TreeNode) => void;
}

/**
 * Format file size in human-readable format
 */
const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const size = bytes / Math.pow(1024, i);
  return `${size.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
};

/**
 * Get icon for package format (maven, npm, docker, etc.)
 */
const getFormatIcon = (format: string): React.ReactNode => {
  const iconStyle = { color: getPackageTypeColor(format) };

  switch (format.toLowerCase()) {
    case 'maven':
      return <CodeOutlined style={iconStyle} />;
    case 'npm':
      return <BoxPlotOutlined style={iconStyle} />;
    case 'docker':
      return <AppstoreOutlined style={iconStyle} />;
    case 'pypi':
      return <CodeOutlined style={iconStyle} />;
    case 'go':
      return <CodeOutlined style={iconStyle} />;
    case 'cargo':
      return <BoxPlotOutlined style={iconStyle} />;
    case 'nuget':
      return <AppstoreOutlined style={iconStyle} />;
    case 'helm':
      return <AppstoreOutlined style={iconStyle} />;
    default:
      return <DatabaseOutlined style={iconStyle} />;
  }
};

/**
 * Get icon for tree node based on type
 */
const getNodeIcon = (node: TreeNode, isExpanded: boolean): React.ReactNode => {
  const metadata = node.metadata;

  // Repository node - show format-specific icon
  if (node.type === 'repository' && metadata?.repository) {
    return getFormatIcon(metadata.repository.format);
  }

  // Folder node
  if (node.type === 'folder' || node.type === 'root') {
    return isExpanded ? (
      <FolderOpenOutlined style={{ color: colors.warning }} />
    ) : (
      <FolderOutlined style={{ color: colors.warning }} />
    );
  }

  // Package node
  if (node.type === 'package' && metadata?.package) {
    return getFormatIcon(metadata.package.package_type);
  }

  // Version node
  if (node.type === 'version') {
    return <FolderOutlined style={{ color: colors.info }} />;
  }

  // Artifact/file node
  if (node.type === 'artifact' || node.type === 'metadata') {
    return <FileOutlined style={{ color: colors.textSecondary }} />;
  }

  // Default to file icon
  return <FileOutlined style={{ color: colors.textSecondary }} />;
};

/**
 * Get repository type indicator badge
 */
const getRepoTypeBadge = (repoType: string): React.ReactNode => {
  const color = getRepoTypeColor(repoType);
  const label = repoType.charAt(0).toUpperCase();

  return (
    <Tooltip title={`${repoType.charAt(0).toUpperCase() + repoType.slice(1)} repository`}>
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 16,
          height: 16,
          borderRadius: '50%',
          backgroundColor: color,
          color: '#fff',
          fontSize: 10,
          fontWeight: 600,
          marginLeft: 6,
        }}
      >
        {label}
      </span>
    </Tooltip>
  );
};

/**
 * Custom tree node renderer for repository tree
 *
 * Shows appropriate icons for different node types (folder, file, package),
 * displays file sizes for artifacts, and supports context menu actions.
 */
export const RepositoryTreeNode: React.FC<RepositoryTreeNodeProps> = ({
  node,
  isExpanded = false,
  showSize = true,
  onContextMenu,
}) => {
  const metadata = node.metadata;
  const artifactMetadata = metadata?.artifact;
  const repositoryMetadata = metadata?.repository;

  const handleContextMenu = (event: React.MouseEvent) => {
    if (onContextMenu) {
      event.preventDefault();
      event.stopPropagation();
      onContextMenu(event, node);
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '2px 0',
        width: '100%',
      }}
      onContextMenu={handleContextMenu}
    >
      <span style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
        {getNodeIcon(node, isExpanded)}
      </span>

      <span
        style={{
          flex: 1,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {node.name}
      </span>

      {/* Repository type badge (local/remote/virtual) */}
      {node.type === 'repository' && repositoryMetadata?.repo_type && (
        getRepoTypeBadge(repositoryMetadata.repo_type)
      )}

      {/* File size for artifacts */}
      {showSize && artifactMetadata?.size_bytes !== undefined && (
        <Text
          type="secondary"
          style={{
            fontSize: 12,
            flexShrink: 0,
            marginLeft: 8,
          }}
        >
          {formatFileSize(artifactMetadata.size_bytes)}
        </Text>
      )}

      {/* Children count for folders */}
      {node.children_count !== undefined && node.children_count > 0 && (
        <Text
          type="secondary"
          style={{
            fontSize: 12,
            flexShrink: 0,
            marginLeft: 8,
          }}
        >
          ({node.children_count})
        </Text>
      )}
    </div>
  );
};

export default RepositoryTreeNode;
