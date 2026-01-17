import apiClient from './client';
import type { PaginatedResponse } from '../types';

export interface Package {
  id: string;
  repository_key: string;
  name: string;
  version: string;
  format: string;
  description?: string;
  size_bytes: number;
  download_count: number;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
}

export interface PackageVersion {
  version: string;
  size_bytes: number;
  download_count: number;
  created_at: string;
  checksum_sha256: string;
}

export interface ListPackagesParams {
  page?: number;
  per_page?: number;
  repository_key?: string;
  format?: string;
  search?: string;
}

export const packagesApi = {
  list: async (params: ListPackagesParams = {}): Promise<PaginatedResponse<Package>> => {
    const response = await apiClient.get<PaginatedResponse<Package>>('/api/v1/packages', {
      params,
    });
    return response.data;
  },

  get: async (packageId: string): Promise<Package> => {
    const response = await apiClient.get<Package>(`/api/v1/packages/${packageId}`);
    return response.data;
  },

  getVersions: async (packageId: string): Promise<PackageVersion[]> => {
    const response = await apiClient.get<{ versions: PackageVersion[] }>(
      `/api/v1/packages/${packageId}/versions`
    );
    return response.data.versions;
  },
};

export default packagesApi;
