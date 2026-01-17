import apiClient from './client';
import type { PaginatedResponse } from '../types';

export type BuildStatus = 'pending' | 'running' | 'success' | 'failed' | 'cancelled';

export interface Build {
  id: string;
  name: string;
  number: number;
  status: BuildStatus;
  started_at?: string;
  finished_at?: string;
  duration_ms?: number;
  agent?: string;
  created_at: string;
  updated_at: string;
  artifact_count?: number;
  modules?: BuildModule[];
}

export interface BuildModule {
  id: string;
  name: string;
  artifacts: BuildArtifact[];
}

export interface BuildArtifact {
  name: string;
  path: string;
  checksum_sha256: string;
  size_bytes: number;
}

export interface BuildDiff {
  build_a: string;
  build_b: string;
  added: BuildArtifact[];
  removed: BuildArtifact[];
  modified: BuildArtifactDiff[];
}

export interface BuildArtifactDiff {
  name: string;
  path: string;
  old_checksum: string;
  new_checksum: string;
  old_size_bytes: number;
  new_size_bytes: number;
}

export interface ListBuildsParams {
  page?: number;
  per_page?: number;
  status?: BuildStatus;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export const buildsApi = {
  list: async (params: ListBuildsParams = {}): Promise<PaginatedResponse<Build>> => {
    const response = await apiClient.get<PaginatedResponse<Build>>('/api/v1/builds', {
      params,
    });
    return response.data;
  },

  get: async (buildId: string): Promise<Build> => {
    const response = await apiClient.get<Build>(`/api/v1/builds/${buildId}`);
    return response.data;
  },

  diff: async (buildIdA: string, buildIdB: string): Promise<BuildDiff> => {
    const response = await apiClient.get<BuildDiff>('/api/v1/builds/diff', {
      params: {
        build_a: buildIdA,
        build_b: buildIdB,
      },
    });
    return response.data;
  },
};

export default buildsApi;
