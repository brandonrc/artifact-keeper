import { useState, useMemo } from 'react';
import { Modal, Alert, Spin, Input, Typography, message } from 'antd';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ExclamationCircleOutlined } from '@ant-design/icons';
import { permissionsApi, groupsApi, adminApi } from '../../api';
import { useAuth } from '../../contexts';
import { useDocumentTitle } from '../../hooks';
import PermissionTargetTable, {
  type PermissionTargetData,
} from '../../components/admin/PermissionTargets/PermissionTargetTable';
import PermissionTargetWizard from '../../components/admin/PermissionTargets/PermissionTargetWizard';
import type { Permission, PermissionAction } from '../../api';
import { colors, spacing } from '../../styles/tokens';

const { Text } = Typography;

interface ApiError extends Error {
  response?: {
    data?: {
      message?: string;
    };
  };
}

const Permissions = () => {
  useDocumentTitle('Permissions');
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();

  const [wizardVisible, setWizardVisible] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<PermissionTargetData | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  const { data: permissionsData, isLoading: permissionsLoading, error: permissionsError } = useQuery({
    queryKey: ['admin-permissions'],
    queryFn: () => permissionsApi.list({ per_page: 1000 }),
    enabled: currentUser?.is_admin,
  });

  const { data: groupsData, isLoading: groupsLoading } = useQuery({
    queryKey: ['admin-groups'],
    queryFn: () => groupsApi.list({ per_page: 1000 }),
    enabled: currentUser?.is_admin,
  });

  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => adminApi.listUsers(),
    enabled: currentUser?.is_admin,
  });

  const permissions = permissionsData?.items || [];
  const groups = groupsData?.items || [];
  const users = usersData || [];

  const permissionTargets: PermissionTargetData[] = useMemo(() => {
    const targetMap = new Map<string, PermissionTargetData>();

    permissions.forEach((permission: Permission) => {
      const targetKey = `${permission.target_type}-${permission.target_id}`;

      if (!targetMap.has(targetKey)) {
        targetMap.set(targetKey, {
          id: permission.id,
          name: permission.target_name || permission.target_id,
          description: `${permission.target_type} permission target`,
          repository_pattern: permission.target_type === 'repository' ? permission.target_id : undefined,
          actions: permission.actions,
          assigned_users: [],
          assigned_groups: [],
          created_at: permission.created_at,
          updated_at: permission.updated_at,
        });
      }

      const target = targetMap.get(targetKey)!;

      if (permission.principal_type === 'user') {
        const user = users.find(u => u.id === permission.principal_id);
        target.assigned_users.push({
          id: permission.principal_id,
          name: permission.principal_name || user?.display_name || user?.username || permission.principal_id,
        });
      } else if (permission.principal_type === 'group') {
        const group = groups.find(g => g.id === permission.principal_id);
        target.assigned_groups.push({
          id: permission.principal_id,
          name: permission.principal_name || group?.name || permission.principal_id,
        });
      }

      target.actions = [...new Set([...target.actions, ...permission.actions])] as PermissionAction[];
    });

    return Array.from(targetMap.values());
  }, [permissions, users, groups]);

  const deletePermissionMutation = useMutation({
    mutationFn: async (permissionId: string) => {
      await permissionsApi.delete(permissionId);
    },
    onSuccess: () => {
      message.success('Permission target deleted successfully');
      setDeleteModalOpen(false);
      setSelectedTarget(null);
      setDeleteConfirmText('');
      queryClient.invalidateQueries({ queryKey: ['admin-permissions'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to delete permission target');
    },
  });

  const handleCreate = () => {
    setSelectedTarget(null);
    setWizardVisible(true);
  };

  const handleEdit = (target: PermissionTargetData) => {
    setSelectedTarget(target);
    setWizardVisible(true);
  };

  const handleDelete = (target: PermissionTargetData) => {
    setSelectedTarget(target);
    setDeleteConfirmText('');
    setDeleteModalOpen(true);
  };

  const handleWizardClose = () => {
    setWizardVisible(false);
    setSelectedTarget(null);
  };

  const handleWizardSuccess = () => {
    setWizardVisible(false);
    setSelectedTarget(null);
    queryClient.invalidateQueries({ queryKey: ['admin-permissions'] });
  };

  const handleDeleteConfirm = () => {
    if (selectedTarget && deleteConfirmText === selectedTarget.name) {
      deletePermissionMutation.mutate(selectedTarget.id);
    }
  };

  const isLoading = permissionsLoading || groupsLoading || usersLoading;

  if (!currentUser?.is_admin) {
    return (
      <div>
        <h1>Permissions</h1>
        <Alert
          message="Access Denied"
          description="You must be an administrator to view this page."
          type="error"
          showIcon
        />
      </div>
    );
  }

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 50 }}>
        <Spin size="large" />
      </div>
    );
  }

  if (permissionsError) {
    return (
      <div>
        <h1>Permissions</h1>
        <Alert
          message="Error loading permissions"
          description="Failed to fetch permission list from the server."
          type="error"
          showIcon
        />
      </div>
    );
  }

  return (
    <div>
      <h1 style={{ marginBottom: spacing.lg }}>Permissions</h1>

      <PermissionTargetTable
        targets={permissionTargets}
        loading={isLoading}
        onEdit={handleEdit}
        onDelete={handleDelete}
        onCreate={handleCreate}
      />

      <PermissionTargetWizard
        visible={wizardVisible}
        onClose={handleWizardClose}
        onSuccess={handleWizardSuccess}
        initialValues={selectedTarget || undefined}
      />

      <Modal
        title={
          <span>
            <ExclamationCircleOutlined style={{ color: colors.error, marginRight: 8 }} />
            Delete Permission Target
          </span>
        }
        open={deleteModalOpen}
        onCancel={() => {
          setDeleteModalOpen(false);
          setSelectedTarget(null);
          setDeleteConfirmText('');
        }}
        onOk={handleDeleteConfirm}
        okText="Delete"
        okButtonProps={{
          danger: true,
          disabled: deleteConfirmText !== selectedTarget?.name,
          loading: deletePermissionMutation.isPending,
        }}
        destroyOnClose
      >
        <Alert
          message="This action cannot be undone"
          description={
            <>
              Deleting this permission target will revoke all associated permissions.
              Users and groups will lose access to the affected resources.
            </>
          }
          type="warning"
          showIcon
          style={{ marginBottom: spacing.md }}
        />
        <div style={{ marginBottom: spacing.sm }}>
          <Text>
            To confirm deletion, please type the permission target name:{' '}
            <Text strong code>{selectedTarget?.name}</Text>
          </Text>
        </div>
        <Input
          placeholder="Type permission target name to confirm"
          value={deleteConfirmText}
          onChange={(e) => setDeleteConfirmText(e.target.value)}
          status={deleteConfirmText && deleteConfirmText !== selectedTarget?.name ? 'error' : undefined}
        />
      </Modal>
    </div>
  );
};

export default Permissions;
