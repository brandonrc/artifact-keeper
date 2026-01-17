import apiClient from './client';
import type { User } from '../types';

export interface UpdateProfileRequest {
  display_name?: string;
  email?: string;
  current_password?: string;
  new_password?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  scopes?: string[];
}

export interface CreateApiKeyRequest {
  name: string;
  expires_in_days?: number;
  scopes?: string[];
}

export interface CreateApiKeyResponse {
  api_key: ApiKey;
  key: string; // Full key, only shown once
}

export interface AccessToken {
  id: string;
  name: string;
  token_prefix: string;
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  scopes?: string[];
}

export interface CreateAccessTokenRequest {
  name: string;
  expires_in_days?: number;
  scopes?: string[];
}

export interface CreateAccessTokenResponse {
  access_token: AccessToken;
  token: string; // Full token, only shown once
}

export const profileApi = {
  get: async (): Promise<User> => {
    const response = await apiClient.get<User>('/api/v1/profile');
    return response.data;
  },

  update: async (data: UpdateProfileRequest): Promise<User> => {
    const response = await apiClient.put<User>('/api/v1/profile', data);
    return response.data;
  },

  // API Keys
  listApiKeys: async (): Promise<ApiKey[]> => {
    const response = await apiClient.get<{ api_keys: ApiKey[] }>('/api/v1/profile/api-keys');
    return response.data.api_keys;
  },

  createApiKey: async (data: CreateApiKeyRequest): Promise<CreateApiKeyResponse> => {
    const response = await apiClient.post<CreateApiKeyResponse>(
      '/api/v1/profile/api-keys',
      data
    );
    return response.data;
  },

  deleteApiKey: async (keyId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/profile/api-keys/${keyId}`);
  },

  // Access Tokens
  listAccessTokens: async (): Promise<AccessToken[]> => {
    const response = await apiClient.get<{ access_tokens: AccessToken[] }>(
      '/api/v1/profile/access-tokens'
    );
    return response.data.access_tokens;
  },

  createAccessToken: async (
    data: CreateAccessTokenRequest
  ): Promise<CreateAccessTokenResponse> => {
    const response = await apiClient.post<CreateAccessTokenResponse>(
      '/api/v1/profile/access-tokens',
      data
    );
    return response.data;
  },

  deleteAccessToken: async (tokenId: string): Promise<void> => {
    await apiClient.delete(`/api/v1/profile/access-tokens/${tokenId}`);
  },
};

export default profileApi;
