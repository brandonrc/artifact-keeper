import React, { useState, useCallback } from 'react';
import { Modal, Input, Typography, Alert } from 'antd';
import { ExclamationCircleOutlined, WarningOutlined, DeleteOutlined } from '@ant-design/icons';

const { Text, Paragraph } = Typography;

type ConfirmType = 'warning' | 'danger' | 'info';

export interface ConfirmDialogProps {
  open: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
  title: string;
  description?: string;
  confirmText?: string;
  cancelText?: string;
  type?: ConfirmType;
  loading?: boolean;
  requireTypeToConfirm?: boolean;
  typeToConfirmValue?: string;
  typeToConfirmLabel?: string;
}

const typeIcons: Record<ConfirmType, React.ReactNode> = {
  warning: <ExclamationCircleOutlined style={{ color: '#faad14' }} />,
  danger: <DeleteOutlined style={{ color: '#ff4d4f' }} />,
  info: <ExclamationCircleOutlined style={{ color: '#1677ff' }} />,
};

const typeColors: Record<ConfirmType, string> = {
  warning: '#faad14',
  danger: '#ff4d4f',
  info: '#1677ff',
};

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  onConfirm,
  onCancel,
  title,
  description,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  type = 'warning',
  loading = false,
  requireTypeToConfirm = false,
  typeToConfirmValue = '',
  typeToConfirmLabel,
}) => {
  const [inputValue, setInputValue] = useState('');
  const [isConfirming, setIsConfirming] = useState(false);

  const isInputValid = !requireTypeToConfirm || inputValue === typeToConfirmValue;

  const handleConfirm = useCallback(async () => {
    if (!isInputValid) return;

    setIsConfirming(true);
    try {
      await onConfirm();
    } finally {
      setIsConfirming(false);
      setInputValue('');
    }
  }, [isInputValid, onConfirm]);

  const handleCancel = useCallback(() => {
    setInputValue('');
    onCancel();
  }, [onCancel]);

  return (
    <Modal
      open={open}
      title={
        <span>
          {typeIcons[type]} {title}
        </span>
      }
      onOk={handleConfirm}
      onCancel={handleCancel}
      okText={confirmText}
      cancelText={cancelText}
      okButtonProps={{
        danger: type === 'danger',
        loading: loading || isConfirming,
        disabled: !isInputValid,
      }}
      maskClosable={false}
      destroyOnClose
    >
      {description && (
        <Paragraph style={{ marginBottom: 16 }}>{description}</Paragraph>
      )}

      {type === 'danger' && (
        <Alert
          type="warning"
          icon={<WarningOutlined />}
          message="This action cannot be undone"
          style={{ marginBottom: 16 }}
          showIcon
        />
      )}

      {requireTypeToConfirm && (
        <div style={{ marginTop: 16 }}>
          <Text type="secondary">
            {typeToConfirmLabel ||
              `To confirm, type "${typeToConfirmValue}" in the field below:`}
          </Text>
          <Input
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={typeToConfirmValue}
            style={{ marginTop: 8 }}
            status={inputValue && !isInputValid ? 'error' : undefined}
            autoFocus
          />
          {inputValue && !isInputValid && (
            <Text type="danger" style={{ fontSize: 12 }}>
              Input does not match. Please type exactly: {typeToConfirmValue}
            </Text>
          )}
        </div>
      )}
    </Modal>
  );
};

/**
 * Hook for using confirm dialogs imperatively
 */
export const useConfirmDialog = () => {
  const [modal, contextHolder] = Modal.useModal();

  const confirm = useCallback(
    (options: {
      title: string;
      content?: React.ReactNode;
      type?: ConfirmType;
      okText?: string;
      cancelText?: string;
      onOk?: () => void | Promise<void>;
      onCancel?: () => void;
    }) => {
      const { title, content, type = 'warning', okText, cancelText, onOk, onCancel } = options;

      return modal.confirm({
        title,
        icon: typeIcons[type],
        content,
        okText: okText ?? 'Confirm',
        cancelText: cancelText ?? 'Cancel',
        okButtonProps: {
          danger: type === 'danger',
        },
        onOk,
        onCancel,
      });
    },
    [modal]
  );

  return { confirm, contextHolder };
};

export default ConfirmDialog;
