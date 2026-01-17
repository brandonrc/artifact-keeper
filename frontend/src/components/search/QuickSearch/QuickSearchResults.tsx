import React, { useMemo } from 'react';
import { List, Typography, Spin, Empty, Button } from 'antd';
import {
  FileOutlined,
  FolderOutlined,
  DatabaseOutlined,
} from '@ant-design/icons';
import type { SearchResult } from '../../../api/search';
import { colors, spacing, borderRadius, typography } from '../../../styles/tokens';

const { Text } = Typography;

export interface QuickSearchResultsProps {
  results: SearchResult[];
  loading: boolean;
  onSelect: (result: SearchResult) => void;
  onViewAll: () => void;
}

interface GroupedResults {
  [repositoryKey: string]: SearchResult[];
}

const getResultIcon = (type: SearchResult['type']): React.ReactNode => {
  switch (type) {
    case 'artifact':
      return <FileOutlined style={{ color: colors.primary }} />;
    case 'package':
      return <FolderOutlined style={{ color: colors.info }} />;
    case 'repository':
      return <DatabaseOutlined style={{ color: colors.warning }} />;
    default:
      return <FileOutlined style={{ color: colors.textSecondary }} />;
  }
};

export const QuickSearchResults: React.FC<QuickSearchResultsProps> = ({
  results,
  loading,
  onSelect,
  onViewAll,
}) => {
  const groupedResults = useMemo<GroupedResults>(() => {
    return results.reduce<GroupedResults>((groups, result) => {
      const key = result.repository_key;
      if (!groups[key]) {
        groups[key] = [];
      }
      groups[key].push(result);
      return groups;
    }, {});
  }, [results]);

  const repositoryKeys = useMemo(() => Object.keys(groupedResults), [groupedResults]);

  if (loading) {
    return (
      <div
        style={{
          padding: spacing.lg,
          textAlign: 'center',
          minWidth: 320,
        }}
      >
        <Spin size="default" />
        <div style={{ marginTop: spacing.sm }}>
          <Text type="secondary">Searching...</Text>
        </div>
      </div>
    );
  }

  if (results.length === 0) {
    return (
      <div
        style={{
          padding: spacing.lg,
          minWidth: 320,
        }}
      >
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="No results found"
          style={{ margin: 0 }}
        />
      </div>
    );
  }

  return (
    <div
      style={{
        minWidth: 400,
        maxWidth: 500,
        maxHeight: 400,
        overflow: 'auto',
      }}
    >
      {repositoryKeys.map((repoKey) => (
        <div key={repoKey} style={{ marginBottom: spacing.xs }}>
          <div
            style={{
              padding: `${spacing.xs}px ${spacing.md}px`,
              backgroundColor: colors.bgLayout,
              borderBottom: `1px solid ${colors.borderLight}`,
            }}
          >
            <Text
              strong
              style={{
                fontSize: typography.fontSizeSm,
                color: colors.textSecondary,
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
              }}
            >
              <DatabaseOutlined style={{ marginRight: spacing.xs }} />
              {repoKey}
            </Text>
          </div>
          <List
            dataSource={groupedResults[repoKey]}
            renderItem={(result) => (
              <List.Item
                onClick={() => onSelect(result)}
                style={{
                  padding: `${spacing.sm}px ${spacing.md}px`,
                  cursor: 'pointer',
                  transition: 'background-color 0.2s',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = colors.bgContainerLight;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                }}
              >
                <List.Item.Meta
                  avatar={
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        width: 32,
                        height: 32,
                        backgroundColor: colors.bgLayout,
                        borderRadius: borderRadius.sm,
                        fontSize: typography.fontSizeLg,
                      }}
                    >
                      {getResultIcon(result.type)}
                    </div>
                  }
                  title={
                    <Text
                      ellipsis={{ tooltip: result.name }}
                      style={{ fontWeight: typography.fontWeightMedium }}
                    >
                      {result.name}
                    </Text>
                  }
                  description={
                    <Text
                      type="secondary"
                      ellipsis={{ tooltip: result.path }}
                      style={{ fontSize: typography.fontSizeSm }}
                    >
                      {result.path || '/'}
                    </Text>
                  }
                />
                {result.version && (
                  <Text
                    type="secondary"
                    style={{
                      fontSize: typography.fontSizeSm,
                      backgroundColor: colors.bgLayout,
                      padding: `2px ${spacing.xs}px`,
                      borderRadius: borderRadius.sm,
                    }}
                  >
                    v{result.version}
                  </Text>
                )}
              </List.Item>
            )}
            split={false}
          />
        </div>
      ))}
      <div
        style={{
          padding: spacing.md,
          borderTop: `1px solid ${colors.border}`,
          textAlign: 'center',
        }}
      >
        <Button type="link" onClick={onViewAll}>
          View All Results
        </Button>
      </div>
    </div>
  );
};

export default QuickSearchResults;
