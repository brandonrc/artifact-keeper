import React from 'react';
import { Alert, Button, Space, Typography } from 'antd';
import { ReloadOutlined, WarningOutlined } from '@ant-design/icons';

const { Text } = Typography;

export interface ErrorRetryProps {
  error: Error | string | null | undefined;
  onRetry: () => void;
  loading?: boolean;
  title?: string;
  children?: React.ReactNode;
  inline?: boolean;
  showIcon?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

/**
 * Error display component with retry button
 * Follows the clarified requirement: "Show inline error with manual retry button"
 */
export const ErrorRetry: React.FC<ErrorRetryProps> = ({
  error,
  onRetry,
  loading = false,
  title = 'Error',
  children,
  inline = true,
  showIcon = true,
  className,
  style,
}) => {
  // If no error, render children
  if (!error) {
    return <>{children}</>;
  }

  const errorMessage = error instanceof Error ? error.message : String(error);

  const retryButton = (
    <Button
      size="small"
      icon={<ReloadOutlined />}
      onClick={onRetry}
      loading={loading}
    >
      Retry
    </Button>
  );

  if (inline) {
    return (
      <Alert
        type="error"
        message={title}
        description={errorMessage}
        showIcon={showIcon}
        icon={showIcon ? <WarningOutlined /> : undefined}
        action={retryButton}
        className={className}
        style={style}
      />
    );
  }

  // Full block error display
  return (
    <div
      className={className}
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 48,
        textAlign: 'center',
        ...style,
      }}
    >
      <WarningOutlined style={{ fontSize: 48, color: '#ff4d4f', marginBottom: 16 }} />
      <Text strong style={{ fontSize: 18, marginBottom: 8 }}>
        {title}
      </Text>
      <Text type="secondary" style={{ marginBottom: 16, maxWidth: 400 }}>
        {errorMessage}
      </Text>
      <Space>
        {retryButton}
      </Space>
    </div>
  );
};

/**
 * Higher-order component for wrapping components with error boundary
 */
export const withErrorRetry = <P extends object>(
  WrappedComponent: React.ComponentType<P>,
  getError: (props: P) => Error | string | null | undefined,
  getOnRetry: (props: P) => () => void,
  getLoading?: (props: P) => boolean
) => {
  const WithErrorRetry: React.FC<P> = (props) => {
    const error = getError(props);
    const onRetry = getOnRetry(props);
    const loading = getLoading?.(props) ?? false;

    return (
      <ErrorRetry error={error} onRetry={onRetry} loading={loading}>
        <WrappedComponent {...props} />
      </ErrorRetry>
    );
  };

  WithErrorRetry.displayName = `WithErrorRetry(${WrappedComponent.displayName || WrappedComponent.name || 'Component'})`;

  return WithErrorRetry;
};

export default ErrorRetry;
