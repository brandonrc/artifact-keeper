import React from 'react';
import { Button, Result, Typography } from 'antd';
import {
  InboxOutlined,
  SearchOutlined,
  FileOutlined,
  DatabaseOutlined,
  UserOutlined,
  SettingOutlined,
} from '@ant-design/icons';

const { Text } = Typography;

type EmptyStateType =
  | 'default'
  | 'search'
  | 'artifacts'
  | 'repositories'
  | 'users'
  | 'settings'
  | 'custom';

export interface EmptyStateAction {
  label: string;
  onClick: () => void;
  type?: 'primary' | 'default' | 'link';
}

export interface EmptyStateProps {
  type?: EmptyStateType;
  title?: string;
  description?: string;
  illustration?: React.ReactNode;
  action?: EmptyStateAction;
  secondaryAction?: EmptyStateAction;
  className?: string;
  style?: React.CSSProperties;
}

const defaultIcons: Record<EmptyStateType, React.ReactNode> = {
  default: <InboxOutlined style={{ fontSize: 64, color: '#bfbfbf' }} />,
  search: <SearchOutlined style={{ fontSize: 64, color: '#bfbfbf' }} />,
  artifacts: <FileOutlined style={{ fontSize: 64, color: '#bfbfbf' }} />,
  repositories: <DatabaseOutlined style={{ fontSize: 64, color: '#bfbfbf' }} />,
  users: <UserOutlined style={{ fontSize: 64, color: '#bfbfbf' }} />,
  settings: <SettingOutlined style={{ fontSize: 64, color: '#bfbfbf' }} />,
  custom: null,
};

const defaultTitles: Record<EmptyStateType, string> = {
  default: 'No data',
  search: 'No results found',
  artifacts: 'No artifacts yet',
  repositories: 'No repositories yet',
  users: 'No users found',
  settings: 'No settings configured',
  custom: '',
};

const defaultDescriptions: Record<EmptyStateType, string> = {
  default: 'There is no data to display.',
  search: 'Try adjusting your search criteria.',
  artifacts: 'Upload your first artifact to get started.',
  repositories: 'Create your first repository to get started.',
  users: 'Add users to your organization.',
  settings: 'Configure your settings to get started.',
  custom: '',
};

export const EmptyState: React.FC<EmptyStateProps> = ({
  type = 'default',
  title,
  description,
  illustration,
  action,
  secondaryAction,
  className,
  style,
}) => {
  const icon = illustration ?? defaultIcons[type];
  const displayTitle = title ?? defaultTitles[type];
  const displayDescription = description ?? defaultDescriptions[type];

  const extra: React.ReactNode[] = [];

  if (action) {
    extra.push(
      <Button
        key="primary"
        type={action.type ?? 'primary'}
        onClick={action.onClick}
      >
        {action.label}
      </Button>
    );
  }

  if (secondaryAction) {
    extra.push(
      <Button
        key="secondary"
        type={secondaryAction.type ?? 'default'}
        onClick={secondaryAction.onClick}
      >
        {secondaryAction.label}
      </Button>
    );
  }

  return (
    <Result
      icon={icon}
      title={displayTitle}
      subTitle={
        displayDescription && (
          <Text type="secondary">{displayDescription}</Text>
        )
      }
      extra={extra.length > 0 ? extra : undefined}
      className={className}
      style={{
        padding: '48px 32px',
        ...style,
      }}
    />
  );
};

export default EmptyState;
