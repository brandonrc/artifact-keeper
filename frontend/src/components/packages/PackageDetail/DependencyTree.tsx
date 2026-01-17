import React, { useState, useCallback, useMemo } from 'react';
import { Tree, Typography, Tag, Space, Input, Empty, Alert } from 'antd';
import type { DataNode } from 'antd/es/tree';
import {
  FolderOutlined,
  FolderOpenOutlined,
  FileOutlined,
  WarningOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import type { PackageDependency } from '../../../types';
import { colors, spacing, borderRadius } from '../../../styles/tokens';

const { Text } = Typography;

export interface DependencyTreeProps {
  dependencies: PackageDependency[];
  onSelect?: (dependency: PackageDependency) => void;
}

interface DependencyNode extends PackageDependency {
  children?: DependencyNode[];
  hasConflict?: boolean;
  conflictWith?: string;
}

const dependencyTypeColors: Record<string, string> = {
  runtime: colors.primary,
  development: colors.info,
  build: colors.warning,
  optional: colors.textSecondary,
  peer: '#722ED1',
};

const dependencyTypeLabels: Record<string, string> = {
  runtime: 'Runtime',
  development: 'Dev',
  build: 'Build',
  optional: 'Optional',
  peer: 'Peer',
};

const detectConflicts = (
  dependencies: PackageDependency[]
): Map<string, PackageDependency[]> => {
  const packageVersions = new Map<string, PackageDependency[]>();

  dependencies.forEach((dep) => {
    const existing = packageVersions.get(dep.name) || [];
    packageVersions.set(dep.name, [...existing, dep]);
  });

  const conflicts = new Map<string, PackageDependency[]>();
  packageVersions.forEach((deps, name) => {
    if (deps.length > 1) {
      const uniqueVersions = new Set(deps.map((d) => d.version_constraint));
      if (uniqueVersions.size > 1) {
        conflicts.set(name, deps);
      }
    }
  });

  return conflicts;
};

const buildDependencyTree = (
  dependencies: PackageDependency[],
  conflicts: Map<string, PackageDependency[]>
): DependencyNode[] => {
  const directDeps = dependencies.filter((dep) => dep.is_direct);
  const transitiveDeps = dependencies.filter((dep) => !dep.is_direct);

  const transitiveByParent = new Map<string, PackageDependency[]>();
  transitiveDeps.forEach((dep) => {
    directDeps.forEach((direct) => {
      if (dep.name.includes(direct.name.split('/')[0])) {
        const existing = transitiveByParent.get(direct.name) || [];
        transitiveByParent.set(direct.name, [...existing, dep]);
      }
    });
  });

  return directDeps.map((dep): DependencyNode => {
    const conflictVersions = conflicts.get(dep.name);
    const hasConflict = !!conflictVersions;
    const conflictWith =
      conflictVersions && conflictVersions.length > 1
        ? conflictVersions
            .filter((c) => c.version_constraint !== dep.version_constraint)
            .map((c) => c.version_constraint)
            .join(', ')
        : undefined;

    return {
      ...dep,
      hasConflict,
      conflictWith,
      children: (transitiveByParent.get(dep.name) || []).map(
        (child): DependencyNode => ({
          ...child,
          hasConflict: conflicts.has(child.name),
          conflictWith: conflicts.has(child.name)
            ? conflicts
                .get(child.name)
                ?.filter((c) => c.version_constraint !== child.version_constraint)
                .map((c) => c.version_constraint)
                .join(', ')
            : undefined,
        })
      ),
    };
  });
};

const convertToTreeData = (
  nodes: DependencyNode[],
  searchTerm: string
): DataNode[] => {
  const filterNodes = (node: DependencyNode): boolean => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      node.name.toLowerCase().includes(term) ||
      node.version_constraint.toLowerCase().includes(term)
    );
  };

  return nodes
    .filter(filterNodes)
    .map((node): DataNode => {
      const typeColor = dependencyTypeColors[node.dependency_type] || colors.textSecondary;
      const typeLabel = dependencyTypeLabels[node.dependency_type] || node.dependency_type;

      const title = (
        <Space size="small">
          <Text strong={node.is_direct}>{node.name}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {node.version_constraint}
          </Text>
          <Tag
            color={typeColor}
            style={{ fontSize: 10, lineHeight: '16px', padding: '0 4px' }}
          >
            {typeLabel}
          </Tag>
          {node.resolved_version && (
            <Text type="secondary" style={{ fontSize: 11 }}>
              (resolved: {node.resolved_version})
            </Text>
          )}
          {node.hasConflict && (
            <Tag color="error" icon={<WarningOutlined />}>
              Conflict{node.conflictWith ? `: ${node.conflictWith}` : ''}
            </Tag>
          )}
        </Space>
      );

      return {
        key: `${node.name}@${node.version_constraint}`,
        title,
        icon: node.children?.length ? undefined : <FileOutlined />,
        children:
          node.children && node.children.length > 0
            ? convertToTreeData(node.children, searchTerm)
            : undefined,
      };
    });
};

export const DependencyTree: React.FC<DependencyTreeProps> = ({
  dependencies,
  onSelect,
}) => {
  const [expandedKeys, setExpandedKeys] = useState<React.Key[]>([]);
  const [searchTerm, setSearchTerm] = useState('');

  const conflicts = useMemo(() => detectConflicts(dependencies), [dependencies]);
  const hasConflicts = conflicts.size > 0;

  const dependencyNodes = useMemo(
    () => buildDependencyTree(dependencies, conflicts),
    [dependencies, conflicts]
  );

  const treeData = useMemo(
    () => convertToTreeData(dependencyNodes, searchTerm),
    [dependencyNodes, searchTerm]
  );

  const directCount = dependencies.filter((d) => d.is_direct).length;
  const transitiveCount = dependencies.filter((d) => !d.is_direct).length;

  const handleExpand = useCallback((keys: React.Key[]) => {
    setExpandedKeys(keys);
  }, []);

  const handleExpandAll = useCallback(() => {
    const allKeys = dependencyNodes.map(
      (node) => `${node.name}@${node.version_constraint}`
    );
    setExpandedKeys(allKeys);
  }, [dependencyNodes]);

  const handleCollapseAll = useCallback(() => {
    setExpandedKeys([]);
  }, []);

  const handleSearchChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setSearchTerm(e.target.value);
    },
    []
  );

  const handleSelect = useCallback(
    (selectedKeys: React.Key[]) => {
      if (onSelect && selectedKeys.length > 0) {
        const [name, version] = (selectedKeys[0] as string).split('@');
        const dep = dependencies.find(
          (d) => d.name === name && d.version_constraint === version
        );
        if (dep) {
          onSelect(dep);
        }
      }
    },
    [dependencies, onSelect]
  );

  if (dependencies.length === 0) {
    return (
      <Empty
        description="No dependencies"
        image={Empty.PRESENTED_IMAGE_SIMPLE}
      />
    );
  }

  return (
    <div>
      {hasConflicts && (
        <Alert
          type="warning"
          message={`${conflicts.size} version conflict${conflicts.size > 1 ? 's' : ''} detected`}
          description="Some dependencies have conflicting version requirements. Review the highlighted items below."
          style={{ marginBottom: spacing.md }}
          showIcon
        />
      )}

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: spacing.md,
          flexWrap: 'wrap',
          gap: spacing.sm,
        }}
      >
        <Space>
          <Tag>{directCount} direct</Tag>
          <Tag>{transitiveCount} transitive</Tag>
          <Tag>{dependencies.length} total</Tag>
        </Space>

        <Space>
          <Input
            placeholder="Search dependencies..."
            prefix={<SearchOutlined />}
            value={searchTerm}
            onChange={handleSearchChange}
            allowClear
            style={{ width: 200 }}
          />
          <Text
            type="secondary"
            style={{ cursor: 'pointer', fontSize: 12 }}
            onClick={handleExpandAll}
          >
            Expand All
          </Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            |
          </Text>
          <Text
            type="secondary"
            style={{ cursor: 'pointer', fontSize: 12 }}
            onClick={handleCollapseAll}
          >
            Collapse All
          </Text>
        </Space>
      </div>

      <div
        style={{
          backgroundColor: colors.bgLayout,
          borderRadius: borderRadius.md,
          padding: spacing.md,
        }}
      >
        <Tree
          treeData={treeData}
          expandedKeys={expandedKeys}
          onExpand={handleExpand}
          onSelect={handleSelect}
          showIcon
          switcherIcon={({ expanded }) =>
            expanded ? <FolderOpenOutlined /> : <FolderOutlined />
          }
          style={{ backgroundColor: 'transparent' }}
        />
      </div>
    </div>
  );
};

export default DependencyTree;
