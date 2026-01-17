import React from 'react';
import { Tabs, Button, Space, Typography, Divider } from 'antd';
import { DownloadOutlined, DeleteOutlined } from '@ant-design/icons';
import type { Artifact, Build, PermissionAssignment } from '../../../types';
import { colors } from '../../../styles/tokens';
import { GeneralTab } from './GeneralTab';
import { PropertiesTab } from './PropertiesTab';
import { BuildsTab } from './BuildsTab';
import { PermissionsTab } from './PermissionsTab';

const { Title, Text } = Typography;

export interface ArtifactProperty {
  key: string;
  value: string;
}

export interface ArtifactDetailProps {
  artifact: Artifact;
  properties?: ArtifactProperty[];
  builds?: Build[];
  permissions?: PermissionAssignment[];
  onDownload?: (artifact: Artifact) => void;
  onDelete?: (artifact: Artifact) => void;
  onPropertyAdd?: (key: string, value: string) => void;
  onPropertyEdit?: (key: string, value: string) => void;
  onPropertyDelete?: (key: string) => void;
  loading?: boolean;
  canDelete?: boolean;
  canEditProperties?: boolean;
}

export const ArtifactDetail: React.FC<ArtifactDetailProps> = ({
  artifact,
  properties = [],
  builds = [],
  permissions = [],
  onDownload,
  onDelete,
  onPropertyAdd,
  onPropertyEdit,
  onPropertyDelete,
  loading = false,
  canDelete = false,
  canEditProperties = false,
}) => {
  const handleDownload = () => {
    if (onDownload) {
      onDownload(artifact);
    }
  };

  const handleDelete = () => {
    if (onDelete) {
      onDelete(artifact);
    }
  };

  const tabItems = [
    {
      key: 'general',
      label: 'General',
      children: <GeneralTab artifact={artifact} />,
    },
    {
      key: 'properties',
      label: 'Properties',
      children: (
        <PropertiesTab
          properties={properties}
          onAdd={onPropertyAdd}
          onEdit={onPropertyEdit}
          onDelete={onPropertyDelete}
          canEdit={canEditProperties}
        />
      ),
    },
    {
      key: 'builds',
      label: 'Builds',
      children: <BuildsTab builds={builds} />,
    },
    {
      key: 'permissions',
      label: 'Permissions',
      children: <PermissionsTab permissions={permissions} />,
    },
  ];

  return (
    <div style={{ padding: '16px 24px' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: 16,
        }}
      >
        <div>
          <Title level={4} style={{ margin: 0, marginBottom: 4 }}>
            {artifact.name}
          </Title>
          <Text type="secondary" style={{ fontSize: 13 }}>
            {artifact.path}
          </Text>
        </div>
        <Space>
          <Button
            type="primary"
            icon={<DownloadOutlined />}
            onClick={handleDownload}
            disabled={loading}
          >
            Download
          </Button>
          {canDelete && (
            <Button
              danger
              icon={<DeleteOutlined />}
              onClick={handleDelete}
              disabled={loading}
            >
              Delete
            </Button>
          )}
        </Space>
      </div>

      <Divider style={{ margin: '16px 0' }} />

      <Tabs
        defaultActiveKey="general"
        items={tabItems}
        style={{
          minHeight: 300,
        }}
      />
    </div>
  );
};

export default ArtifactDetail;
