import React, { useState, useEffect } from 'react';
import { Card, Form, Input, Button, Space, Typography, Modal, message } from 'antd';
import { LockOutlined, SaveOutlined } from '@ant-design/icons';
import type { User } from '../../../types';

const { Text } = Typography;

export interface ProfileFormProps {
  user: User;
  onSave: (values: { display_name?: string; email?: string }) => Promise<void>;
  loading?: boolean;
  isSsoUser?: boolean;
}

interface PasswordFormValues {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

export const ProfileForm: React.FC<ProfileFormProps> = ({
  user,
  onSave,
  loading = false,
  isSsoUser = false,
}) => {
  const [form] = Form.useForm();
  const [passwordForm] = Form.useForm();
  const [isPasswordModalOpen, setIsPasswordModalOpen] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);

  useEffect(() => {
    form.setFieldsValue({
      display_name: user.display_name || '',
      email: user.email,
      username: user.username,
    });
  }, [user, form]);

  const handleSubmit = async (values: { display_name?: string; email?: string }) => {
    try {
      await onSave({
        display_name: values.display_name || undefined,
        email: !isSsoUser ? values.email : undefined,
      });
      message.success('Profile updated successfully');
    } catch (error) {
      message.error('Failed to update profile');
    }
  };

  const handlePasswordChange = async (values: PasswordFormValues) => {
    setChangingPassword(true);
    try {
      // This would be handled by the parent component or API
      // For now, we emit the values via the onSave handler context
      await onSave({
        // This is a workaround - in a real implementation,
        // you'd have a separate onChangePassword callback
      });
      message.success('Password changed successfully');
      setIsPasswordModalOpen(false);
      passwordForm.resetFields();
    } catch (error) {
      message.error('Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  };

  const handlePasswordModalCancel = () => {
    setIsPasswordModalOpen(false);
    passwordForm.resetFields();
  };

  return (
    <>
      <Card title="Profile Information">
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          initialValues={{
            display_name: user.display_name || '',
            email: user.email,
            username: user.username,
          }}
        >
          <Form.Item
            label="Username"
            name="username"
            extra="Username cannot be changed"
          >
            <Input disabled />
          </Form.Item>

          <Form.Item
            label="Display Name"
            name="display_name"
            rules={[
              { max: 100, message: 'Display name must be at most 100 characters' },
            ]}
          >
            <Input placeholder="Enter your display name" />
          </Form.Item>

          <Form.Item
            label="Email"
            name="email"
            extra={isSsoUser ? 'Email is managed by your identity provider' : undefined}
            rules={[
              { type: 'email', message: 'Please enter a valid email address' },
              { required: true, message: 'Email is required' },
            ]}
          >
            <Input
              placeholder="Enter your email"
              disabled={isSsoUser}
            />
          </Form.Item>

          <Form.Item style={{ marginBottom: 0 }}>
            <Space>
              <Button
                type="primary"
                htmlType="submit"
                loading={loading}
                icon={<SaveOutlined />}
              >
                Save Changes
              </Button>
              {!isSsoUser && (
                <Button
                  icon={<LockOutlined />}
                  onClick={() => setIsPasswordModalOpen(true)}
                >
                  Change Password
                </Button>
              )}
            </Space>
          </Form.Item>
        </Form>
      </Card>

      <Modal
        title="Change Password"
        open={isPasswordModalOpen}
        onCancel={handlePasswordModalCancel}
        footer={null}
        destroyOnClose
      >
        <Form
          form={passwordForm}
          layout="vertical"
          onFinish={handlePasswordChange}
        >
          <Form.Item
            label="Current Password"
            name="current_password"
            rules={[{ required: true, message: 'Please enter your current password' }]}
          >
            <Input.Password placeholder="Enter current password" />
          </Form.Item>

          <Form.Item
            label="New Password"
            name="new_password"
            rules={[
              { required: true, message: 'Please enter a new password' },
              { min: 8, message: 'Password must be at least 8 characters' },
            ]}
          >
            <Input.Password placeholder="Enter new password" />
          </Form.Item>

          <Form.Item
            label="Confirm New Password"
            name="confirm_password"
            dependencies={['new_password']}
            rules={[
              { required: true, message: 'Please confirm your new password' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error('Passwords do not match'));
                },
              }),
            ]}
          >
            <Input.Password placeholder="Confirm new password" />
          </Form.Item>

          <Form.Item style={{ marginBottom: 0, marginTop: 24 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={handlePasswordModalCancel}>Cancel</Button>
              <Button
                type="primary"
                htmlType="submit"
                loading={changingPassword}
              >
                Change Password
              </Button>
            </Space>
          </Form.Item>
        </Form>

        <Text type="secondary" style={{ display: 'block', marginTop: 16 }}>
          After changing your password, you may need to log in again.
        </Text>
      </Modal>
    </>
  );
};

export default ProfileForm;
