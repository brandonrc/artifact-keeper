import { Button, Result, Space, theme } from 'antd'
import { useNavigate } from 'react-router-dom'
import { HomeOutlined, ArrowLeftOutlined } from '@ant-design/icons'

const NotFound = () => {
  const navigate = useNavigate()
  const { token } = theme.useToken()

  const handleGoHome = () => {
    navigate('/')
  }

  const handleGoBack = () => {
    navigate(-1)
  }

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '60vh',
        padding: token.paddingLG,
      }}
    >
      <Result
        status="404"
        title="Page Not Found"
        subTitle="The page you are looking for does not exist or has been moved."
        extra={
          <Space size="middle">
            <Button
              type="primary"
              icon={<HomeOutlined />}
              onClick={handleGoHome}
            >
              Go Home
            </Button>
            <Button
              icon={<ArrowLeftOutlined />}
              onClick={handleGoBack}
            >
              Go Back
            </Button>
          </Space>
        }
      />
    </div>
  )
}

export default NotFound
