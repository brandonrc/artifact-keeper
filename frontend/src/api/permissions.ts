import apiClient from './client';
import type { PaginatedResponse } from '../types';

export type PermissionAction = 'read' | 'write' | 'delete' | 'admin';
export type PermissionTargetType = 'repository' | 'group' | 'artifact';
export type PermissionPrincipalType = 'user' | 'group';

export interface Permission {
  id: string;
  principal_type: PermissionPrincipalType;
  principal_id: string;
  principal_name?: string;
  target_type: PermissionTargetType;
  target_id: string;
  target_name?: string;
  actions: PermissionAction[];
  created_at: string;
  updated_at: string;
}

export interface CreatePermissionRequest {
  principal_type: PermissionPrincipalType;
  principal_id: string;
  target_type: PermissionTargetType;
  target_id: string;
  actions: PermissionAction[];
}

export interface ListPermissionsParams {
  page?: number;
  per_page?: number;
  principal_type?: PermissionPrincipalType;
  principal_id?: string;
  target_type?: PermissionTargetType;
  target_id?: string;
}

export const permissionsApi = {
  list: async (params: ListPermissionsParams = {}): Promise<PaginatedResponse<Permission>> => {
    const response = await apiClient.get<PaginatedResponse<Permission>>('/api/v1/permissions', {
      params,
    });
    return response.data;
  },

  get: async (permissionId: string): Promise<Permission> => {
    const response = await apiClient.get<Permission>(`/api/v1/permissions/${permissionId}`);
    return response.data;
  },

  create: async (data: CreatePermissionRequest): Promise<Permission> => {
    const response = await apiClient.post<Permission>('/api/v1/permissions', data);
    return response.data;
  },

  update: async (
    permissionId: string,
    data: Partial<CreatePermissionRequest>
  ): Promise<Permission> => {
    const response = await apiClient.put<Permission>(
      `/api/v1/permissions/${permissionId}`,
      data
    );
    return response.data;
  },

  delete: async (permissionId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/permissions/${permissionId}`);
  },
};

export default permissionsApi;
