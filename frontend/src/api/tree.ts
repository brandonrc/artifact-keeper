import apiClient from './client';

export type TreeNodeType = 'folder' | 'file' | 'repository';

export interface TreeNode {
  id: string;
  name: string;
  path: string;
  type: TreeNodeType;
  size_bytes?: number;
  children_count?: number;
  has_children: boolean;
  repository_key?: string;
  created_at?: string;
  updated_at?: string;
}

export interface GetChildrenParams {
  repository_key?: string;
  path?: string;
  include_metadata?: boolean;
}

export const treeApi = {
  getChildren: async (params: GetChildrenParams = {}): Promise<TreeNode[]> => {
    const response = await apiClient.get<{ nodes: TreeNode[] }>('/api/v1/tree', {
      params: {
        repository_key: params.repository_key,
        path: params.path,
        include_metadata: params.include_metadata,
      },
    });
    return response.data.nodes;
  },
};

export default treeApi;
