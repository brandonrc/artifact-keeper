import { useState } from 'react';
import { Modal, Alert, Spin, Input, Typography, message } from 'antd';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ExclamationCircleOutlined } from '@ant-design/icons';
import { groupsApi } from '../../api';
import { useAuth } from '../../contexts';
import { useDocumentTitle } from '../../hooks';
import GroupTable from '../../components/admin/GroupManagement/GroupTable';
import GroupForm, { type GroupFormValues } from '../../components/admin/GroupManagement/GroupForm';
import GroupMemberManager from '../../components/admin/GroupManagement/GroupMemberManager';
import type { Group } from '../../types';
import { colors, spacing } from '../../styles/tokens';

const { Text } = Typography;

interface ApiError extends Error {
  response?: {
    data?: {
      message?: string;
    };
  };
}

const Groups = () => {
  useDocumentTitle('Groups');
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();

  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [membersModalOpen, setMembersModalOpen] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  const { data: groupsData, isLoading, error } = useQuery({
    queryKey: ['admin-groups'],
    queryFn: () => groupsApi.list({ per_page: 1000 }),
    enabled: currentUser?.is_admin,
  });

  const groups = groupsData?.items || [];

  const createGroupMutation = useMutation({
    mutationFn: async (data: GroupFormValues) => {
      const response = await groupsApi.create({
        name: data.name,
        description: data.description,
      });
      return response;
    },
    onSuccess: () => {
      message.success('Group created successfully');
      setCreateModalOpen(false);
      queryClient.invalidateQueries({ queryKey: ['admin-groups'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to create group');
    },
  });

  const updateGroupMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<GroupFormValues> }) => {
      const response = await groupsApi.update(id, {
        description: data.description,
      });
      return response;
    },
    onSuccess: () => {
      message.success('Group updated successfully');
      setEditModalOpen(false);
      setSelectedGroup(null);
      queryClient.invalidateQueries({ queryKey: ['admin-groups'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to update group');
    },
  });

  const deleteGroupMutation = useMutation({
    mutationFn: async (groupId: string) => {
      await groupsApi.delete(groupId);
    },
    onSuccess: () => {
      message.success('Group deleted successfully');
      setDeleteModalOpen(false);
      setSelectedGroup(null);
      setDeleteConfirmText('');
      queryClient.invalidateQueries({ queryKey: ['admin-groups'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to delete group');
    },
  });

  const handleCreate = () => {
    setCreateModalOpen(true);
  };

  const handleEdit = (group: Group) => {
    setSelectedGroup(group);
    setEditModalOpen(true);
  };

  const handleDelete = (group: Group) => {
    setSelectedGroup(group);
    setDeleteConfirmText('');
    setDeleteModalOpen(true);
  };

  const handleManageMembers = (group: Group) => {
    setSelectedGroup(group);
    setMembersModalOpen(true);
  };

  const handleCreateSubmit = (values: GroupFormValues) => {
    createGroupMutation.mutate(values);
  };

  const handleEditSubmit = (values: GroupFormValues) => {
    if (selectedGroup) {
      updateGroupMutation.mutate({ id: selectedGroup.id, data: values });
    }
  };

  const handleDeleteConfirm = () => {
    if (selectedGroup && deleteConfirmText === selectedGroup.name) {
      deleteGroupMutation.mutate(selectedGroup.id);
    }
  };

  const handleMembersClose = () => {
    setMembersModalOpen(false);
    setSelectedGroup(null);
    queryClient.invalidateQueries({ queryKey: ['admin-groups'] });
  };

  if (!currentUser?.is_admin) {
    return (
      <div>
        <h1>Groups</h1>
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

  if (error) {
    return (
      <div>
        <h1>Groups</h1>
        <Alert
          message="Error loading groups"
          description="Failed to fetch group list from the server."
          type="error"
          showIcon
        />
      </div>
    );
  }

  return (
    <div>
      <h1 style={{ marginBottom: spacing.lg }}>Groups</h1>

      <GroupTable
        groups={groups}
        loading={isLoading}
        onEdit={handleEdit}
        onDelete={handleDelete}
        onManageMembers={handleManageMembers}
        onCreate={handleCreate}
      />

      <Modal
        title="Create Group"
        open={createModalOpen}
        onCancel={() => setCreateModalOpen(false)}
        footer={null}
        destroyOnClose
      >
        <GroupForm
          mode="create"
          onSubmit={handleCreateSubmit}
          onCancel={() => setCreateModalOpen(false)}
          loading={createGroupMutation.isPending}
        />
      </Modal>

      <Modal
        title={`Edit Group: ${selectedGroup?.name}`}
        open={editModalOpen}
        onCancel={() => {
          setEditModalOpen(false);
          setSelectedGroup(null);
        }}
        footer={null}
        destroyOnClose
      >
        {selectedGroup && (
          <GroupForm
            mode="edit"
            initialValues={{
              name: selectedGroup.name,
              description: selectedGroup.description,
              auto_join: selectedGroup.auto_join,
            }}
            onSubmit={handleEditSubmit}
            onCancel={() => {
              setEditModalOpen(false);
              setSelectedGroup(null);
            }}
            loading={updateGroupMutation.isPending}
          />
        )}
      </Modal>

      <Modal
        title={
          <span>
            <ExclamationCircleOutlined style={{ color: colors.error, marginRight: 8 }} />
            Delete Group
          </span>
        }
        open={deleteModalOpen}
        onCancel={() => {
          setDeleteModalOpen(false);
          setSelectedGroup(null);
          setDeleteConfirmText('');
        }}
        onOk={handleDeleteConfirm}
        okText="Delete"
        okButtonProps={{
          danger: true,
          disabled: deleteConfirmText !== selectedGroup?.name,
          loading: deleteGroupMutation.isPending,
        }}
        destroyOnClose
      >
        <Alert
          message="This action cannot be undone"
          description={
            <>
              Deleting this group will remove all member associations.
              Members will lose any permissions granted through this group.
            </>
          }
          type="warning"
          showIcon
          style={{ marginBottom: spacing.md }}
        />
        <div style={{ marginBottom: spacing.sm }}>
          <Text>
            To confirm deletion, please type the group name:{' '}
            <Text strong code>{selectedGroup?.name}</Text>
          </Text>
        </div>
        <Input
          placeholder="Type group name to confirm"
          value={deleteConfirmText}
          onChange={(e) => setDeleteConfirmText(e.target.value)}
          status={deleteConfirmText && deleteConfirmText !== selectedGroup?.name ? 'error' : undefined}
        />
      </Modal>

      {membersModalOpen && selectedGroup && (
        <GroupMemberManager
          groupId={selectedGroup.id}
          groupName={selectedGroup.name}
          onClose={handleMembersClose}
        />
      )}
    </div>
  );
};

export default Groups;
