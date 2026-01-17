import { useState } from 'react';
import { Modal, Alert, Spin, Typography, message, Button } from 'antd';
import { CopyOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api';
import apiClient from '../api/client';
import { useAuth } from '../contexts';
import { useDocumentTitle } from '../hooks';
import UserTable from '../components/admin/UserManagement/UserTable';
import UserForm, { type UserFormValues } from '../components/admin/UserManagement/UserForm';
import type { User, CreateUserResponse } from '../types';
import { spacing } from '../styles/tokens';

const { Text } = Typography;

interface ApiError extends Error {
  response?: {
    data?: {
      message?: string;
    };
  };
}

const Users = () => {
  useDocumentTitle('Users');
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();

  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [passwordModalOpen, setPasswordModalOpen] = useState(false);
  const [generatedPassword, setGeneratedPassword] = useState<string | null>(null);
  const [createdUsername, setCreatedUsername] = useState<string | null>(null);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  const { data: users, isLoading, error } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => adminApi.listUsers(),
    enabled: currentUser?.is_admin,
  });

  const createUserMutation = useMutation({
    mutationFn: async (data: UserFormValues) => {
      const payload: Record<string, unknown> = {
        username: data.username,
        email: data.email,
        display_name: data.display_name,
        is_admin: data.is_admin,
      };
      if (!data.auto_generate_password && data.password) {
        payload.password = data.password;
      }
      const response = await apiClient.post<CreateUserResponse>('/api/v1/users', payload);
      return response.data;
    },
    onSuccess: (data) => {
      setCreateModalOpen(false);
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });

      if (data.generated_password) {
        setGeneratedPassword(data.generated_password);
        setCreatedUsername(data.user.username);
        setPasswordModalOpen(true);
      } else {
        message.success('User created successfully');
      }
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to create user');
    },
  });

  const updateUserMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<UserFormValues> }) => {
      const response = await apiClient.patch(`/api/v1/users/${id}`, {
        email: data.email,
        display_name: data.display_name,
        is_admin: data.is_admin,
        is_active: data.is_active,
      });
      return response.data;
    },
    onSuccess: () => {
      message.success('User updated successfully');
      setEditModalOpen(false);
      setSelectedUser(null);
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to update user');
    },
  });

  const toggleUserStatusMutation = useMutation({
    mutationFn: async ({ id, is_active }: { id: string; is_active: boolean }) => {
      const response = await apiClient.patch(`/api/v1/users/${id}`, { is_active });
      return response.data;
    },
    onSuccess: (_, variables) => {
      message.success(`User ${variables.is_active ? 'enabled' : 'disabled'} successfully`);
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to update user status');
    },
  });

  const resetPasswordMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiClient.post<{ temporary_password: string }>(`/api/v1/users/${id}/password/reset`);
      return response.data;
    },
    onSuccess: (data, userId) => {
      const user = users?.find(u => u.id === userId);
      setGeneratedPassword(data.temporary_password);
      setCreatedUsername(user?.username || 'User');
      setPasswordModalOpen(true);
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to reset password');
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/api/v1/users/${id}`);
    },
    onSuccess: () => {
      message.success('User deleted successfully');
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
    onError: (error: ApiError) => {
      message.error(error.response?.data?.message || 'Failed to delete user');
    },
  });

  const handleCreate = () => {
    setCreateModalOpen(true);
  };

  const handleEdit = (user: User) => {
    setSelectedUser(user);
    setEditModalOpen(true);
  };

  const handleDelete = (user: User) => {
    if (user.id === currentUser?.id) {
      message.error('You cannot delete your own account');
      return;
    }
    deleteUserMutation.mutate(user.id);
  };

  const handleResetPassword = (user: User) => {
    if (user.id === currentUser?.id) {
      message.error('You cannot reset your own password from here');
      return;
    }
    resetPasswordMutation.mutate(user.id);
  };

  const handleToggleStatus = (user: User) => {
    if (user.id === currentUser?.id) {
      message.error('You cannot disable your own account');
      return;
    }
    toggleUserStatusMutation.mutate({ id: user.id, is_active: !user.is_active });
  };

  const handleCreateSubmit = async (values: UserFormValues) => {
    createUserMutation.mutate(values);
  };

  const handleEditSubmit = async (values: UserFormValues) => {
    if (selectedUser) {
      updateUserMutation.mutate({ id: selectedUser.id, data: values });
    }
  };

  const copyPassword = () => {
    if (generatedPassword) {
      navigator.clipboard.writeText(generatedPassword);
      message.success('Password copied to clipboard');
    }
  };

  const closePasswordModal = () => {
    setPasswordModalOpen(false);
    setGeneratedPassword(null);
    setCreatedUsername(null);
  };

  if (!currentUser?.is_admin) {
    return (
      <div>
        <h1>Users</h1>
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
        <h1>Users</h1>
        <Alert
          message="Error loading users"
          description="Failed to fetch user list from the server."
          type="error"
          showIcon
        />
      </div>
    );
  }

  return (
    <div>
      <h1 style={{ marginBottom: spacing.lg }}>Users</h1>

      <UserTable
        users={users || []}
        loading={isLoading}
        onEdit={handleEdit}
        onDelete={handleDelete}
        onResetPassword={handleResetPassword}
        onToggleStatus={handleToggleStatus}
        onCreate={handleCreate}
      />

      <Modal
        title="Create User"
        open={createModalOpen}
        onCancel={() => setCreateModalOpen(false)}
        footer={null}
        width={600}
        destroyOnClose
      >
        <Alert
          message="Password will be auto-generated"
          description="A secure password will be generated and displayed after creation. The user will be required to change it on first login."
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <UserForm
          mode="create"
          onSubmit={handleCreateSubmit}
          onCancel={() => setCreateModalOpen(false)}
          loading={createUserMutation.isPending}
        />
      </Modal>

      <Modal
        title="Temporary Password"
        open={passwordModalOpen}
        onCancel={closePasswordModal}
        footer={[
          <Button key="copy" icon={<CopyOutlined />} onClick={copyPassword}>
            Copy Password
          </Button>,
          <Button key="close" type="primary" onClick={closePasswordModal}>
            Done
          </Button>,
        ]}
      >
        <Alert
          message="Save this password!"
          description="This password will only be shown once. Make sure to save it or share it with the user securely."
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <div style={{ marginBottom: 16 }}>
          <Text strong>Username: </Text>
          <Text code>{createdUsername}</Text>
        </div>
        <div style={{ marginBottom: 16 }}>
          <Text strong>Temporary Password: </Text>
          <Text code copyable>{generatedPassword}</Text>
        </div>
        <Alert
          message="The user will be required to change this password on next login."
          type="info"
          showIcon
        />
      </Modal>

      <Modal
        title={`Edit User: ${selectedUser?.username}`}
        open={editModalOpen}
        onCancel={() => {
          setEditModalOpen(false);
          setSelectedUser(null);
        }}
        footer={null}
        width={600}
        destroyOnClose
      >
        {selectedUser && (
          <UserForm
            mode="edit"
            initialValues={{
              username: selectedUser.username,
              email: selectedUser.email,
              display_name: selectedUser.display_name,
              is_admin: selectedUser.is_admin,
              is_active: selectedUser.is_active,
            }}
            onSubmit={handleEditSubmit}
            onCancel={() => {
              setEditModalOpen(false);
              setSelectedUser(null);
            }}
            loading={updateUserMutation.isPending}
          />
        )}
      </Modal>
    </div>
  );
};

export default Users;
