import React from 'react';
import { message, notification } from 'antd';
import type { ArgsProps as NotificationArgsProps } from 'antd/es/notification';
import type { ArgsProps as MessageArgsProps } from 'antd/es/message';
import { toast as toastConfig } from '../../../styles/tokens';

type ToastType = 'success' | 'error' | 'warning' | 'info';

interface ToastOptions {
  duration?: number;
  key?: string;
  onClick?: () => void;
}

interface RichToastOptions extends ToastOptions {
  description?: string;
  btn?: React.ReactNode;
  onClose?: () => void;
}

/**
 * Simple toast notifications using Ant Design message API
 */
export const toast = {
  success: (content: string, options?: ToastOptions) => {
    message.success({
      content,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      onClick: options?.onClick,
    } as MessageArgsProps);
  },

  error: (content: string, options?: ToastOptions) => {
    message.error({
      content,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      onClick: options?.onClick,
    } as MessageArgsProps);
  },

  warning: (content: string, options?: ToastOptions) => {
    message.warning({
      content,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      onClick: options?.onClick,
    } as MessageArgsProps);
  },

  info: (content: string, options?: ToastOptions) => {
    message.info({
      content,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      onClick: options?.onClick,
    } as MessageArgsProps);
  },

  loading: (content: string, options?: ToastOptions) => {
    message.loading({
      content,
      duration: options?.duration ?? 0, // Loading messages don't auto-dismiss
      key: options?.key,
    } as MessageArgsProps);
  },

  destroy: (key?: string) => {
    if (key) {
      message.destroy(key);
    } else {
      message.destroy();
    }
  },
};

/**
 * Rich toast notifications using Ant Design notification API
 * Use for important messages that need more context or actions
 */
export const richToast = {
  success: (title: string, options?: RichToastOptions) => {
    notification.success({
      message: title,
      description: options?.description,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      btn: options?.btn,
      onClick: options?.onClick,
      onClose: options?.onClose,
      placement: 'topRight',
    } as NotificationArgsProps);
  },

  error: (title: string, options?: RichToastOptions) => {
    notification.error({
      message: title,
      description: options?.description,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      btn: options?.btn,
      onClick: options?.onClick,
      onClose: options?.onClose,
      placement: 'topRight',
    } as NotificationArgsProps);
  },

  warning: (title: string, options?: RichToastOptions) => {
    notification.warning({
      message: title,
      description: options?.description,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      btn: options?.btn,
      onClick: options?.onClick,
      onClose: options?.onClose,
      placement: 'topRight',
    } as NotificationArgsProps);
  },

  info: (title: string, options?: RichToastOptions) => {
    notification.info({
      message: title,
      description: options?.description,
      duration: options?.duration ?? toastConfig.duration,
      key: options?.key,
      btn: options?.btn,
      onClick: options?.onClick,
      onClose: options?.onClose,
      placement: 'topRight',
    } as NotificationArgsProps);
  },

  destroy: (key?: string) => {
    if (key) {
      notification.destroy(key);
    } else {
      notification.destroy();
    }
  },
};

/**
 * Hook-based toast for use in components
 */
export const useToast = () => {
  return {
    toast,
    richToast,
  };
};

export default toast;
