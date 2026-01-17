import { useState, useCallback, useRef, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

/**
 * Represents a queued action that was interrupted by session expiry
 */
interface QueuedAction<T = unknown> {
  id: string;
  action: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
}

/**
 * Session guard state and handlers
 */
export interface UseSessionGuardReturn {
  /** Whether the session has expired and re-login is required */
  isSessionExpired: boolean;
  /** Whether the re-login prompt should be shown */
  showReLoginPrompt: boolean;
  /** Number of queued actions waiting for re-authentication */
  queuedActionsCount: number;
  /** Set session as expired and show re-login prompt */
  handleSessionExpiry: () => void;
  /** Dismiss the re-login prompt without re-authenticating */
  dismissPrompt: () => void;
  /** Handle successful re-authentication and resume queued actions */
  handleReAuthentication: () => Promise<void>;
  /** Queue an action to be executed after re-authentication */
  queueAction: <T>(action: () => Promise<T>) => Promise<T>;
  /** Clear all queued actions (rejects them with session error) */
  clearQueue: () => void;
  /** Execute an action with session guard protection */
  withSessionGuard: <T>(action: () => Promise<T>) => Promise<T>;
}

let actionIdCounter = 0;

/**
 * Hook for session expiry handling
 *
 * Features:
 * - Queues pending actions when session expires
 * - Shows re-login prompt
 * - Resumes queued actions after re-authentication
 *
 * @example
 * ```tsx
 * const { withSessionGuard, showReLoginPrompt, handleReAuthentication } = useSessionGuard();
 *
 * // Wrap API calls with session guard
 * const handleSubmit = async () => {
 *   await withSessionGuard(() => api.createItem(data));
 * };
 *
 * // Show re-login modal when needed
 * {showReLoginPrompt && (
 *   <ReLoginModal onSuccess={handleReAuthentication} />
 * )}
 * ```
 */
export function useSessionGuard(): UseSessionGuardReturn {
  const { isAuthenticated, login } = useAuth();
  const [isSessionExpired, setIsSessionExpired] = useState(false);
  const [showReLoginPrompt, setShowReLoginPrompt] = useState(false);
  const actionQueueRef = useRef<QueuedAction[]>([]);
  const [queuedActionsCount, setQueuedActionsCount] = useState(0);

  // Reset session expired state when user becomes authenticated
  useEffect(() => {
    if (isAuthenticated && isSessionExpired) {
      setIsSessionExpired(false);
    }
  }, [isAuthenticated, isSessionExpired]);

  /**
   * Mark the session as expired and show re-login prompt
   */
  const handleSessionExpiry = useCallback(() => {
    setIsSessionExpired(true);
    setShowReLoginPrompt(true);
  }, []);

  /**
   * Dismiss the re-login prompt without re-authenticating
   * Clears all queued actions
   */
  const dismissPrompt = useCallback(() => {
    setShowReLoginPrompt(false);
    // Reject all queued actions
    const queue = actionQueueRef.current;
    actionQueueRef.current = [];
    setQueuedActionsCount(0);

    queue.forEach(({ reject }) => {
      reject(new Error('Session expired and re-authentication was cancelled'));
    });
  }, []);

  /**
   * Handle successful re-authentication
   * Resumes all queued actions
   */
  const handleReAuthentication = useCallback(async () => {
    setIsSessionExpired(false);
    setShowReLoginPrompt(false);

    // Execute all queued actions
    const queue = [...actionQueueRef.current];
    actionQueueRef.current = [];
    setQueuedActionsCount(0);

    for (const { action, resolve, reject } of queue) {
      try {
        const result = await action();
        resolve(result);
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    }
  }, []);

  /**
   * Queue an action to be executed after re-authentication
   */
  const queueAction = useCallback(<T,>(action: () => Promise<T>): Promise<T> => {
    return new Promise<T>((resolve, reject) => {
      const id = `action-${++actionIdCounter}`;
      actionQueueRef.current.push({
        id,
        action: action as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      setQueuedActionsCount(actionQueueRef.current.length);
    });
  }, []);

  /**
   * Clear all queued actions
   */
  const clearQueue = useCallback(() => {
    const queue = actionQueueRef.current;
    actionQueueRef.current = [];
    setQueuedActionsCount(0);

    queue.forEach(({ reject }) => {
      reject(new Error('Queued actions cleared'));
    });
  }, []);

  /**
   * Execute an action with session guard protection
   * If session is expired, queues the action for later execution
   */
  const withSessionGuard = useCallback(
    async <T,>(action: () => Promise<T>): Promise<T> => {
      // If session is already expired, queue the action
      if (isSessionExpired) {
        return queueAction(action);
      }

      try {
        return await action();
      } catch (error) {
        // Check if error is due to session expiry (401 Unauthorized)
        if (
          error &&
          typeof error === 'object' &&
          'response' in error &&
          (error as { response?: { status?: number } }).response?.status === 401
        ) {
          handleSessionExpiry();
          return queueAction(action);
        }
        throw error;
      }
    },
    [isSessionExpired, queueAction, handleSessionExpiry]
  );

  return {
    isSessionExpired,
    showReLoginPrompt,
    queuedActionsCount,
    handleSessionExpiry,
    dismissPrompt,
    handleReAuthentication,
    queueAction,
    clearQueue,
    withSessionGuard,
  };
}

export default useSessionGuard;
