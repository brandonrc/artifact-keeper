import React, { useState, useCallback } from 'react';
import { Button, Typography, message, Tooltip } from 'antd';
import { CopyOutlined, CheckOutlined } from '@ant-design/icons';
import { colors, spacing, borderRadius } from '../../../styles/tokens';

const { Text } = Typography;

export interface CodeBlockProps {
  code: string;
  language?: string;
  title?: string;
  showLineNumbers?: boolean;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  language,
  title,
  showLineNumbers = false,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      message.success('Copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      message.error('Failed to copy to clipboard');
    }
  }, [code]);

  const lines = code.split('\n');

  return (
    <div
      style={{
        position: 'relative',
        backgroundColor: '#1e1e1e',
        borderRadius: borderRadius.md,
        overflow: 'hidden',
      }}
    >
      {title && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: `${spacing.xs}px ${spacing.md}px`,
            backgroundColor: '#2d2d2d',
            borderBottom: '1px solid #3d3d3d',
          }}
        >
          <Text style={{ color: '#cccccc', fontSize: 12 }}>
            {title}
            {language && (
              <Text
                style={{
                  marginLeft: spacing.xs,
                  color: '#888888',
                  fontSize: 11,
                }}
              >
                ({language})
              </Text>
            )}
          </Text>
          <Tooltip title={copied ? 'Copied!' : 'Copy to clipboard'}>
            <Button
              type="text"
              size="small"
              icon={copied ? <CheckOutlined /> : <CopyOutlined />}
              onClick={handleCopy}
              style={{
                color: copied ? colors.success : '#cccccc',
              }}
            />
          </Tooltip>
        </div>
      )}
      <div
        style={{
          display: 'flex',
          padding: spacing.md,
          overflowX: 'auto',
        }}
      >
        {showLineNumbers && (
          <div
            style={{
              paddingRight: spacing.md,
              marginRight: spacing.md,
              borderRight: '1px solid #3d3d3d',
              color: '#6e7681',
              userSelect: 'none',
              fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
              fontSize: 13,
              lineHeight: '1.5',
              textAlign: 'right',
            }}
          >
            {lines.map((_, index) => (
              <div key={index}>{index + 1}</div>
            ))}
          </div>
        )}
        <pre
          style={{
            margin: 0,
            fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
            fontSize: 13,
            lineHeight: '1.5',
            color: '#d4d4d4',
            whiteSpace: 'pre',
            flex: 1,
          }}
        >
          {code}
        </pre>
      </div>
      {!title && (
        <div
          style={{
            position: 'absolute',
            top: spacing.xs,
            right: spacing.xs,
          }}
        >
          <Tooltip title={copied ? 'Copied!' : 'Copy to clipboard'}>
            <Button
              type="text"
              size="small"
              icon={copied ? <CheckOutlined /> : <CopyOutlined />}
              onClick={handleCopy}
              style={{
                color: copied ? colors.success : '#cccccc',
                backgroundColor: 'rgba(0, 0, 0, 0.3)',
              }}
            />
          </Tooltip>
        </div>
      )}
    </div>
  );
};

export default CodeBlock;
