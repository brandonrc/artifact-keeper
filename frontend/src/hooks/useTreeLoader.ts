import { useState, useCallback, useMemo } from 'react';

/**
 * Represents a node in the tree structure
 */
export interface TreeNode<T = unknown> {
  /** Unique identifier for this node */
  id: string;
  /** The data associated with this node */
  data: T;
  /** Child nodes (undefined if not loaded yet) */
  children?: TreeNode<T>[];
  /** Whether this node has children that can be loaded */
  hasChildren: boolean;
  /** Parent node ID (null for root nodes) */
  parentId: string | null;
}

/**
 * State of a tree node's expansion and loading
 */
export interface TreeNodeState {
  /** Whether the node is currently expanded */
  isExpanded: boolean;
  /** Whether the node's children are currently loading */
  isLoading: boolean;
  /** Error message if loading failed */
  error: string | null;
  /** Whether children have been loaded at least once */
  isLoaded: boolean;
}

/**
 * Function type for loading children of a node
 */
export type LoadChildrenFn<T> = (nodeId: string, node: TreeNode<T>) => Promise<TreeNode<T>[]>;

/**
 * Return type for the useTreeLoader hook
 */
export interface UseTreeLoaderReturn<T> {
  /** Current tree nodes (root level) */
  nodes: TreeNode<T>[];
  /** Map of node states by node ID */
  nodeStates: Map<string, TreeNodeState>;
  /** Expand a node and load its children if not already loaded */
  expandNode: (nodeId: string) => Promise<void>;
  /** Collapse a node */
  collapseNode: (nodeId: string) => void;
  /** Toggle a node's expansion state */
  toggleNode: (nodeId: string) => Promise<void>;
  /** Check if a node is expanded */
  isExpanded: (nodeId: string) => boolean;
  /** Check if a node is loading */
  isLoading: (nodeId: string) => boolean;
  /** Get error for a node */
  getError: (nodeId: string) => string | null;
  /** Reload children for a node */
  reloadNode: (nodeId: string) => Promise<void>;
  /** Set root nodes */
  setNodes: (nodes: TreeNode<T>[]) => void;
  /** Get a node by ID */
  getNode: (nodeId: string) => TreeNode<T> | undefined;
  /** Get all expanded node IDs */
  expandedNodeIds: string[];
  /** Expand all nodes to a certain depth */
  expandToDepth: (depth: number) => Promise<void>;
  /** Collapse all nodes */
  collapseAll: () => void;
}

/**
 * Options for the useTreeLoader hook
 */
export interface UseTreeLoaderOptions<T> {
  /** Initial tree nodes */
  initialNodes?: TreeNode<T>[];
  /** Function to load children for a node */
  loadChildren: LoadChildrenFn<T>;
  /** Initially expanded node IDs */
  initialExpandedIds?: string[];
  /** Callback when a node is expanded */
  onExpand?: (nodeId: string, node: TreeNode<T>) => void;
  /** Callback when a node is collapsed */
  onCollapse?: (nodeId: string, node: TreeNode<T>) => void;
  /** Callback when children are loaded */
  onChildrenLoaded?: (nodeId: string, children: TreeNode<T>[]) => void;
  /** Callback when loading fails */
  onLoadError?: (nodeId: string, error: Error) => void;
}

/**
 * Default node state
 */
const DEFAULT_NODE_STATE: TreeNodeState = {
  isExpanded: false,
  isLoading: false,
  error: null,
  isLoaded: false,
};

/**
 * Hook for lazy tree loading
 *
 * Manages tree expansion state and loads children on expand (one level at a time).
 *
 * @example
 * ```tsx
 * const {
 *   nodes,
 *   expandNode,
 *   collapseNode,
 *   isExpanded,
 *   isLoading,
 *   getError,
 * } = useTreeLoader({
 *   initialNodes: rootNodes,
 *   loadChildren: async (nodeId, node) => {
 *     const children = await api.getChildren(nodeId);
 *     return children.map(child => ({
 *       id: child.id,
 *       data: child,
 *       hasChildren: child.hasChildren,
 *       parentId: nodeId,
 *     }));
 *   },
 * });
 *
 * // Render tree
 * const renderNode = (node: TreeNode) => (
 *   <TreeItem
 *     key={node.id}
 *     label={node.data.name}
 *     expanded={isExpanded(node.id)}
 *     loading={isLoading(node.id)}
 *     error={getError(node.id)}
 *     onExpand={() => expandNode(node.id)}
 *     onCollapse={() => collapseNode(node.id)}
 *   >
 *     {node.children?.map(renderNode)}
 *   </TreeItem>
 * );
 * ```
 */
export function useTreeLoader<T = unknown>(
  options: UseTreeLoaderOptions<T>
): UseTreeLoaderReturn<T> {
  const {
    initialNodes = [],
    loadChildren,
    initialExpandedIds = [],
    onExpand,
    onCollapse,
    onChildrenLoaded,
    onLoadError,
  } = options;

  const [nodes, setNodes] = useState<TreeNode<T>[]>(initialNodes);
  const [nodeStates, setNodeStates] = useState<Map<string, TreeNodeState>>(() => {
    const initialStates = new Map<string, TreeNodeState>();
    initialExpandedIds.forEach((id) => {
      initialStates.set(id, { ...DEFAULT_NODE_STATE, isExpanded: true });
    });
    return initialStates;
  });

  // Build a map of all nodes for quick lookup
  const nodeMap = useMemo(() => {
    const map = new Map<string, TreeNode<T>>();

    const addToMap = (nodeList: TreeNode<T>[]) => {
      nodeList.forEach((node) => {
        map.set(node.id, node);
        if (node.children) {
          addToMap(node.children);
        }
      });
    };

    addToMap(nodes);
    return map;
  }, [nodes]);

  /**
   * Get state for a node
   */
  const getNodeState = useCallback(
    (nodeId: string): TreeNodeState => {
      return nodeStates.get(nodeId) || DEFAULT_NODE_STATE;
    },
    [nodeStates]
  );

  /**
   * Update state for a node
   */
  const updateNodeState = useCallback(
    (nodeId: string, updates: Partial<TreeNodeState>) => {
      setNodeStates((prev) => {
        const newStates = new Map(prev);
        const currentState = newStates.get(nodeId) || DEFAULT_NODE_STATE;
        newStates.set(nodeId, { ...currentState, ...updates });
        return newStates;
      });
    },
    []
  );

  /**
   * Update a node's children in the tree
   */
  const updateNodeChildren = useCallback(
    (nodeId: string, children: TreeNode<T>[]) => {
      setNodes((prevNodes) => {
        const updateInTree = (nodeList: TreeNode<T>[]): TreeNode<T>[] => {
          return nodeList.map((node) => {
            if (node.id === nodeId) {
              return { ...node, children };
            }
            if (node.children) {
              return { ...node, children: updateInTree(node.children) };
            }
            return node;
          });
        };

        return updateInTree(prevNodes);
      });
    },
    []
  );

  /**
   * Expand a node and load its children if needed
   */
  const expandNode = useCallback(
    async (nodeId: string) => {
      const node = nodeMap.get(nodeId);
      if (!node) return;

      const state = getNodeState(nodeId);

      // If already expanded, do nothing
      if (state.isExpanded) return;

      // Mark as expanded
      updateNodeState(nodeId, { isExpanded: true });
      onExpand?.(nodeId, node);

      // If children are already loaded, we're done
      if (state.isLoaded || node.children !== undefined) {
        return;
      }

      // If node has no children to load, we're done
      if (!node.hasChildren) {
        updateNodeState(nodeId, { isLoaded: true });
        return;
      }

      // Load children
      updateNodeState(nodeId, { isLoading: true, error: null });

      try {
        const children = await loadChildren(nodeId, node);
        updateNodeChildren(nodeId, children);
        updateNodeState(nodeId, { isLoading: false, isLoaded: true });
        onChildrenLoaded?.(nodeId, children);
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        updateNodeState(nodeId, {
          isLoading: false,
          error: error.message,
        });
        onLoadError?.(nodeId, error);
      }
    },
    [
      nodeMap,
      getNodeState,
      updateNodeState,
      updateNodeChildren,
      loadChildren,
      onExpand,
      onChildrenLoaded,
      onLoadError,
    ]
  );

  /**
   * Collapse a node
   */
  const collapseNode = useCallback(
    (nodeId: string) => {
      const node = nodeMap.get(nodeId);
      if (!node) return;

      updateNodeState(nodeId, { isExpanded: false });
      onCollapse?.(nodeId, node);
    },
    [nodeMap, updateNodeState, onCollapse]
  );

  /**
   * Toggle a node's expansion state
   */
  const toggleNode = useCallback(
    async (nodeId: string) => {
      const state = getNodeState(nodeId);
      if (state.isExpanded) {
        collapseNode(nodeId);
      } else {
        await expandNode(nodeId);
      }
    },
    [getNodeState, collapseNode, expandNode]
  );

  /**
   * Check if a node is expanded
   */
  const isExpanded = useCallback(
    (nodeId: string): boolean => {
      return getNodeState(nodeId).isExpanded;
    },
    [getNodeState]
  );

  /**
   * Check if a node is loading
   */
  const isLoading = useCallback(
    (nodeId: string): boolean => {
      return getNodeState(nodeId).isLoading;
    },
    [getNodeState]
  );

  /**
   * Get error for a node
   */
  const getError = useCallback(
    (nodeId: string): string | null => {
      return getNodeState(nodeId).error;
    },
    [getNodeState]
  );

  /**
   * Reload children for a node
   */
  const reloadNode = useCallback(
    async (nodeId: string) => {
      const node = nodeMap.get(nodeId);
      if (!node || !node.hasChildren) return;

      updateNodeState(nodeId, { isLoading: true, error: null });

      try {
        const children = await loadChildren(nodeId, node);
        updateNodeChildren(nodeId, children);
        updateNodeState(nodeId, { isLoading: false, isLoaded: true });
        onChildrenLoaded?.(nodeId, children);
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        updateNodeState(nodeId, {
          isLoading: false,
          error: error.message,
        });
        onLoadError?.(nodeId, error);
      }
    },
    [nodeMap, updateNodeState, updateNodeChildren, loadChildren, onChildrenLoaded, onLoadError]
  );

  /**
   * Get a node by ID
   */
  const getNode = useCallback(
    (nodeId: string): TreeNode<T> | undefined => {
      return nodeMap.get(nodeId);
    },
    [nodeMap]
  );

  /**
   * Get all expanded node IDs
   */
  const expandedNodeIds = useMemo(() => {
    const ids: string[] = [];
    nodeStates.forEach((state, id) => {
      if (state.isExpanded) {
        ids.push(id);
      }
    });
    return ids;
  }, [nodeStates]);

  /**
   * Expand all nodes to a certain depth
   */
  const expandToDepth = useCallback(
    async (depth: number) => {
      if (depth < 1) return;

      const expandLevel = async (nodeList: TreeNode<T>[], currentDepth: number) => {
        if (currentDepth > depth) return;

        for (const node of nodeList) {
          if (node.hasChildren || node.children) {
            await expandNode(node.id);
            // After expansion, the node might have children
            const updatedNode = nodeMap.get(node.id);
            if (updatedNode?.children && currentDepth < depth) {
              await expandLevel(updatedNode.children, currentDepth + 1);
            }
          }
        }
      };

      await expandLevel(nodes, 1);
    },
    [nodes, expandNode, nodeMap]
  );

  /**
   * Collapse all nodes
   */
  const collapseAll = useCallback(() => {
    setNodeStates((prev) => {
      const newStates = new Map(prev);
      newStates.forEach((state, id) => {
        newStates.set(id, { ...state, isExpanded: false });
      });
      return newStates;
    });
  }, []);

  return {
    nodes,
    nodeStates,
    expandNode,
    collapseNode,
    toggleNode,
    isExpanded,
    isLoading,
    getError,
    reloadNode,
    setNodes,
    getNode,
    expandedNodeIds,
    expandToDepth,
    collapseAll,
  };
}

export default useTreeLoader;
