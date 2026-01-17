import { useState } from 'react'
import { Form, Input, Button, Card, message, Alert, Modal, Divider } from 'antd'
import { UserOutlined, LockOutlined } from '@ant-design/icons'
import { useAuth } from '../contexts'
import { useDocumentTitle } from '../hooks'
import { SSOButtons, MFAVerify, SSOProvider, SSOProviderConfig } from '../components/auth'
import { colors } from '../styles/tokens'

interface LoginValues {
  username: string
  password: string
}

// Available SSO providers - this would normally come from the backend
const SSO_PROVIDERS: SSOProviderConfig[] = [
  { id: 'google', name: 'Google', enabled: true },
  { id: 'github', name: 'GitHub', enabled: true },
  { id: 'saml', name: 'SAML', enabled: false },
  { id: 'ldap', name: 'LDAP', enabled: false },
]

interface ChangePasswordValues {
  current_password: string
  new_password: string
  confirm_password: string
}

const Login = () => {
  useDocumentTitle('Login')
  const { login, mustChangePassword, changePassword, clearMustChangePassword } = useAuth()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [changePasswordModalOpen, setChangePasswordModalOpen] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [changePasswordForm] = Form.useForm<ChangePasswordValues>()

  // MFA state
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaError, setMfaError] = useState<string | null>(null)
  const [mfaSessionToken, setMfaSessionToken] = useState<string | null>(null)

  // SSO state
  const [ssoLoading, setSsoLoading] = useState<SSOProvider | null>(null)

  const onFinish = async (values: LoginValues) => {
    setLoading(true)
    setError(null)
    try {
      setCurrentPassword(values.password) // Store for password change
      const needsPasswordChange = await login(values.username, values.password)
      if (needsPasswordChange) {
        setChangePasswordModalOpen(true)
        message.info('You must change your password before continuing.')
      } else {
        message.success('Login successful!')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed. Please check your credentials.'
      setError(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const handleChangePassword = async (values: ChangePasswordValues) => {
    if (values.new_password !== values.confirm_password) {
      message.error('Passwords do not match')
      return
    }
    setLoading(true)
    try {
      await changePassword(values.current_password, values.new_password)
      message.success('Password changed successfully!')
      setChangePasswordModalOpen(false)
      changePasswordForm.resetFields()
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to change password.'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const handleCancelPasswordChange = () => {
    setChangePasswordModalOpen(false)
    clearMustChangePassword()
    changePasswordForm.resetFields()
  }

  // Handle SSO provider selection
  const handleSSOSelect = async (provider: SSOProvider) => {
    setSsoLoading(provider)
    setError(null)
    try {
      // Redirect to SSO provider - this would normally call a backend endpoint
      // that returns the OAuth redirect URL
      window.location.href = `/api/v1/auth/sso/${provider}`
    } catch (err) {
      setError('Failed to initiate SSO login')
      setSsoLoading(null)
    }
  }

  // Handle MFA verification
  const handleMFAVerify = async (code: string) => {
    setMfaError(null)
    setLoading(true)
    try {
      // This would call the MFA verification endpoint
      // await authApi.verifyMFA(mfaSessionToken, code)
      message.success('MFA verification successful!')
      setMfaRequired(false)
    } catch (err) {
      setMfaError('Invalid verification code. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // Handle MFA cancel
  const handleMFACancel = () => {
    setMfaRequired(false)
    setMfaSessionToken(null)
    setMfaError(null)
  }

  // Handle MFA resend
  const handleMFAResend = async () => {
    try {
      // This would call the resend MFA code endpoint
      message.success('Verification code resent')
    } catch (err) {
      message.error('Failed to resend code')
    }
  }

  // Show MFA verification if required
  if (mfaRequired) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        background: colors.bgLayout
      }}>
        <MFAVerify
          onSubmit={handleMFAVerify}
          onCancel={handleMFACancel}
          onResend={handleMFAResend}
          loading={loading}
          error={mfaError || undefined}
        />
      </div>
    )
  }

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '100vh',
      background: '#f0f2f5'
    }}>
      <Card style={{ width: 400 }}>
        <h1 style={{ textAlign: 'center', marginBottom: 24 }}>Artifact Keeper</h1>
        <h3 style={{ textAlign: 'center', marginBottom: 24, color: '#666' }}>
          Artifact Registry
        </h3>
        {error && (
          <Alert
            message={error}
            type="error"
            showIcon
            style={{ marginBottom: 24 }}
            closable
            onClose={() => setError(null)}
          />
        )}
        <Form
          name="login"
          onFinish={onFinish}
          autoComplete="off"
        >
          <Form.Item
            name="username"
            rules={[{ required: true, message: 'Please input your username!' }]}
          >
            <Input prefix={<UserOutlined />} placeholder="Username" size="large" disabled={loading} />
          </Form.Item>

          <Form.Item
            name="password"
            rules={[{ required: true, message: 'Please input your password!' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Password" size="large" disabled={loading} />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" block size="large" loading={loading}>
              Log in
            </Button>
          </Form.Item>
        </Form>

        {/* SSO Login Options */}
        {SSO_PROVIDERS.some(p => p.enabled) && (
          <>
            <Divider>or continue with</Divider>
            <SSOButtons
              availableProviders={SSO_PROVIDERS}
              onSelect={handleSSOSelect}
              loading={!!ssoLoading}
              loadingProvider={ssoLoading || undefined}
              disabled={loading}
            />
          </>
        )}
      </Card>

      {/* Change Password Modal */}
      <Modal
        title="Change Password Required"
        open={changePasswordModalOpen || mustChangePassword}
        onCancel={handleCancelPasswordChange}
        footer={null}
        closable={true}
      >
        <Alert
          message="Password Change Required"
          description="Your password was auto-generated. Please set a new password to continue."
          type="warning"
          showIcon
          style={{ marginBottom: 24 }}
        />
        <Form
          form={changePasswordForm}
          layout="vertical"
          onFinish={handleChangePassword}
          initialValues={{ current_password: currentPassword }}
        >
          <Form.Item
            name="current_password"
            label="Current Password"
            rules={[{ required: true, message: 'Please enter your current password' }]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="new_password"
            label="New Password"
            rules={[
              { required: true, message: 'Please enter a new password' },
              { min: 8, message: 'Password must be at least 8 characters' },
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label="Confirm New Password"
            dependencies={['new_password']}
            rules={[
              { required: true, message: 'Please confirm your new password' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) {
                    return Promise.resolve()
                  }
                  return Promise.reject(new Error('Passwords do not match'))
                },
              }),
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block loading={loading}>
              Change Password
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Login
