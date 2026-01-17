// Group-related types for user group management

export interface Group {
  id: string;
  name: string;
  description?: string;
  auto_join: boolean;
  member_count: number;
  is_external: boolean;
  created_at: string;
  updated_at: string;
}

export interface GroupDetail extends Group {
  members: GroupMember[];
}

export interface GroupMember {
  user_id: string;
  username: string;
  display_name?: string;
  joined_at: string;
}

export interface CreateGroupRequest {
  name: string;
  description?: string;
  auto_join?: boolean;
}

export interface UpdateGroupRequest {
  description?: string;
  auto_join?: boolean;
}
