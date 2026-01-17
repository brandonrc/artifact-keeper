import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Modal,
  Transfer,
  Input,
  List,
  Button,
  Space,
  Typography,
  Avatar,
  Spin,
  Empty,
  message,
  Popconfirm,
} from 'antd';
import type { TransferProps } from 'antd';
import {
  UserOutlined,
  DeleteOutlined,
  SearchOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import { groupsApi, adminApi } from '../../../api';
import type { User } from '../../../types';
import type { GroupMember } from '../../../api';
import { colors, spacing } from '../../../styles/tokens';

const { Text, Title } = Typography;

export interface GroupMemberManagerProps {
  groupId: string;
  groupName: string;
  onClose: () => void;
}

interface TransferItem {
  key: string;
  title: string;
  description: string;
  disabled?: boolean;
}

export const GroupMemberManager: React.FC<GroupMemberManagerProps> = ({
  groupId,
  groupName,
  onClose,
}) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [members, setMembers] = useState<GroupMember[]>([]);
  const [targetKeys, setTargetKeys] = useState<string[]>([]);
  const [searchText, setSearchText] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [allUsers, groupData] = await Promise.all([
        adminApi.listUsers(),
        groupsApi.get(groupId),
      ]);

      setUsers(allUsers);

      const memberIds = (groupData as { members?: GroupMember[] }).members?.map(m => m.user_id) || [];
      setMembers((groupData as { members?: GroupMember[] }).members || []);
      setTargetKeys(memberIds);
    } catch (error) {
      message.error('Failed to load group data');
      console.error('Error fetching group data:', error);
    } finally {
      setLoading(false);
    }
  }, [groupId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const transferData: TransferItem[] = useMemo(() => {
    return users.map((user) => ({
      key: user.id,
      title: user.display_name || user.username,
      description: user.email,
      disabled: !user.is_active,
    }));
  }, [users]);

  const handleTransferChange: TransferProps['onChange'] = async (newTargetKeys) => {
    const currentMembers = new Set(targetKeys);
    const newMembers = new Set(newTargetKeys as string[]);

    const toAdd = [...newMembers].filter(key => !currentMembers.has(key));
    const toRemove = [...currentMembers].filter(key => !newMembers.has(key));

    setSaving(true);
    try {
      if (toAdd.length > 0) {
        await groupsApi.addMembers(groupId, toAdd);
      }
      if (toRemove.length > 0) {
        await groupsApi.removeMembers(groupId, toRemove);
      }

      setTargetKeys(newTargetKeys as string[]);
      message.success('Members updated successfully');
    } catch (error) {
      message.error('Failed to update members');
      console.error('Error updating members:', error);
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveMember = async (userId: string) => {
    setSaving(true);
    try {
      await groupsApi.removeMembers(groupId, [userId]);
      setTargetKeys(prev => prev.filter(key => key !== userId));
      setMembers(prev => prev.filter(m => m.user_id !== userId));
      message.success('Member removed successfully');
    } catch (error) {
      message.error('Failed to remove member');
      console.error('Error removing member:', error);
    } finally {
      setSaving(false);
    }
  };

  const filterOption = (inputValue: string, option: TransferItem) => {
    return (
      option.title.toLowerCase().includes(inputValue.toLowerCase()) ||
      option.description.toLowerCase().includes(inputValue.toLowerCase())
    );
  };

  const renderItem = (item: TransferItem) => {
    const user = users.find(u => u.id === item.key);
    return (
      <Space>
        <Avatar size="small" icon={<UserOutlined />} />
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <Text strong={!item.disabled} type={item.disabled ? 'secondary' : undefined}>
            {item.title}
          </Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {item.description}
          </Text>
        </div>
        {user?.is_admin && (
          <Text type="warning" style={{ fontSize: 11 }}>
            Admin
          </Text>
        )}
      </Space>
    );
  };

  const filteredMembers = useMemo(() => {
    if (!searchText) return members;
    const search = searchText.toLowerCase();
    return members.filter(
      (m) =>
        m.username.toLowerCase().includes(search) ||
        (m.display_name?.toLowerCase().includes(search) ?? false)
    );
  }, [members, searchText]);

  return (
    <Modal
      title={
        <Space>
          <TeamOutlined style={{ color: colors.primary }} />
          <span>Manage Members: {groupName}</span>
        </Space>
      }
      open={true}
      onCancel={onClose}
      width={800}
      footer={[
        <Button key="close" type="primary" onClick={onClose}>
          Done
        </Button>,
      ]}
    >
      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: spacing.xxl }}>
          <Spin size="large" />
        </div>
      ) : (
        <div>
          <div style={{ marginBottom: spacing.lg }}>
            <Title level={5} style={{ marginBottom: spacing.sm }}>
              Add or Remove Members
            </Title>
            <Transfer
              dataSource={transferData}
              showSearch
              filterOption={filterOption}
              targetKeys={targetKeys}
              onChange={handleTransferChange}
              render={renderItem}
              listStyle={{
                width: 340,
                height: 300,
              }}
              titles={['Available Users', 'Group Members']}
              disabled={saving}
              locale={{
                itemUnit: 'user',
                itemsUnit: 'users',
                notFoundContent: 'No users found',
                searchPlaceholder: 'Search users...',
              }}
            />
          </div>

          <div style={{ marginTop: spacing.xl }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: spacing.sm,
              }}
            >
              <Title level={5} style={{ margin: 0 }}>
                Current Members ({members.length})
              </Title>
              <Input
                placeholder="Search members..."
                prefix={<SearchOutlined />}
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                style={{ width: 200 }}
                allowClear
              />
            </div>

            <List
              size="small"
              bordered
              dataSource={filteredMembers}
              locale={{
                emptyText: (
                  <Empty
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                    description="No members in this group"
                  />
                ),
              }}
              style={{ maxHeight: 250, overflow: 'auto' }}
              renderItem={(member) => (
                <List.Item
                  actions={[
                    <Popconfirm
                      key="remove"
                      title="Remove member"
                      description={`Are you sure you want to remove ${member.display_name || member.username} from this group?`}
                      onConfirm={() => handleRemoveMember(member.user_id)}
                      okText="Remove"
                      cancelText="Cancel"
                      okButtonProps={{ danger: true }}
                    >
                      <Button
                        type="text"
                        danger
                        icon={<DeleteOutlined />}
                        size="small"
                        loading={saving}
                      >
                        Remove
                      </Button>
                    </Popconfirm>,
                  ]}
                >
                  <List.Item.Meta
                    avatar={<Avatar size="small" icon={<UserOutlined />} />}
                    title={member.display_name || member.username}
                    description={
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        @{member.username} &middot; Joined{' '}
                        {new Date(member.joined_at).toLocaleDateString()}
                      </Text>
                    }
                  />
                </List.Item>
              )}
            />
          </div>
        </div>
      )}
    </Modal>
  );
};

export default GroupMemberManager;
