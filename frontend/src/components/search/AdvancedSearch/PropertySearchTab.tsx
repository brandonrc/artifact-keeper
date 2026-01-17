import React from 'react';
import { Form, Input, Select, Button, Space, Typography } from 'antd';
import { PlusOutlined, MinusCircleOutlined } from '@ant-design/icons';
import type { FormInstance } from 'antd';
import { colors, spacing } from '../../../styles/tokens';

const { Text } = Typography;
const { Option } = Select;

export interface PropertySearchTabProps {
  form: FormInstance;
}

type MatchType = 'exact' | 'contains' | 'regex';

const matchTypeOptions: { value: MatchType; label: string }[] = [
  { value: 'exact', label: 'Exact Match' },
  { value: 'contains', label: 'Contains' },
  { value: 'regex', label: 'Regular Expression' },
];

export const PropertySearchTab: React.FC<PropertySearchTabProps> = ({ form }) => {
  return (
    <div style={{ padding: `${spacing.md}px 0` }}>
      <Form.Item
        name={['property', 'matchType']}
        label="Match Type"
        initialValue="exact"
        style={{ marginBottom: spacing.md }}
      >
        <Select
          options={matchTypeOptions}
          style={{ width: 200 }}
        />
      </Form.Item>

      <Text
        type="secondary"
        style={{ display: 'block', marginBottom: spacing.sm }}
      >
        Add property filters to search by key-value pairs
      </Text>

      <Form.List name={['property', 'filters']}>
        {(fields, { add, remove }) => (
          <>
            {fields.map(({ key, name, ...restField }) => (
              <Space
                key={key}
                style={{ display: 'flex', marginBottom: spacing.xs }}
                align="baseline"
              >
                <Form.Item
                  {...restField}
                  name={[name, 'key']}
                  rules={[{ required: true, message: 'Property key is required' }]}
                  style={{ marginBottom: 0, width: 200 }}
                >
                  <Input placeholder="Property key" />
                </Form.Item>
                <Form.Item
                  {...restField}
                  name={[name, 'value']}
                  rules={[{ required: true, message: 'Property value is required' }]}
                  style={{ marginBottom: 0, width: 300 }}
                >
                  <Input placeholder="Property value" />
                </Form.Item>
                <MinusCircleOutlined
                  onClick={() => remove(name)}
                  style={{ color: colors.error, cursor: 'pointer' }}
                />
              </Space>
            ))}
            <Form.Item style={{ marginBottom: 0, marginTop: spacing.sm }}>
              <Button
                type="dashed"
                onClick={() => add()}
                icon={<PlusOutlined />}
                style={{ width: '100%', maxWidth: 524 }}
              >
                Add Property Filter
              </Button>
            </Form.Item>
          </>
        )}
      </Form.List>
    </div>
  );
};

export default PropertySearchTab;
