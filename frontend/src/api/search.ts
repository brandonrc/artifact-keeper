import apiClient from './client';
import type { Artifact, PaginatedResponse } from '../types';

export interface SearchResult {
  id: string;
  type: 'artifact' | 'package' | 'repository';
  name: string;
  path?: string;
  repository_key: string;
  format?: string;
  version?: string;
  size_bytes?: number;
  created_at: string;
  highlights?: string[];
}

export interface QuickSearchParams {
  query: string;
  limit?: number;
  types?: ('artifact' | 'package' | 'repository')[];
}

export interface AdvancedSearchParams {
  page?: number;
  per_page?: number;
  query?: string;
  repository_key?: string;
  format?: string;
  name?: string;
  path?: string;
  version?: string;
  min_size?: number;
  max_size?: number;
  created_after?: string;
  created_before?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export interface ChecksumSearchParams {
  checksum: string;
  algorithm?: 'sha256' | 'sha1' | 'md5';
}

export const searchApi = {
  quickSearch: async (params: QuickSearchParams): Promise<SearchResult[]> => {
    const response = await apiClient.get<{ results: SearchResult[] }>('/api/v1/search/quick', {
      params: {
        q: params.query,
        limit: params.limit,
        types: params.types?.join(','),
      },
    });
    return response.data.results;
  },

  advancedSearch: async (
    params: AdvancedSearchParams
  ): Promise<PaginatedResponse<SearchResult>> => {
    const response = await apiClient.get<PaginatedResponse<SearchResult>>(
      '/api/v1/search/advanced',
      { params }
    );
    return response.data;
  },

  checksumSearch: async (params: ChecksumSearchParams): Promise<Artifact[]> => {
    const response = await apiClient.get<{ artifacts: Artifact[] }>('/api/v1/search/checksum', {
      params: {
        checksum: params.checksum,
        algorithm: params.algorithm || 'sha256',
      },
    });
    return response.data.artifacts;
  },
};

export default searchApi;
