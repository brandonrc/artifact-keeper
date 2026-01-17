import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { Layout } from 'antd'
import { breakpoints, sidebar } from '../../../styles/tokens'

/**
 * AppShell context value type
 */
export interface AppShellContextValue {
  /** Whether the sidebar is collapsed */
  collapsed: boolean
  /** Toggle the sidebar collapsed state */
  toggleCollapsed: () => void
  /** Set the sidebar collapsed state */
  setCollapsed: (collapsed: boolean) => void
  /** Whether the sidebar is visible (for mobile) */
  sidebarVisible: boolean
  /** Toggle sidebar visibility (for mobile) */
  toggleSidebarVisible: () => void
  /** Set sidebar visibility (for mobile) */
  setSidebarVisible: (visible: boolean) => void
  /** Whether the viewport is mobile size */
  isMobile: boolean
  /** Whether the viewport is tablet size */
  isTablet: boolean
  /** Whether the viewport is desktop size */
  isDesktop: boolean
}

const AppShellContext = createContext<AppShellContextValue | undefined>(undefined)

/**
 * Hook to access the AppShell context
 */
export const useAppShell = (): AppShellContextValue => {
  const context = useContext(AppShellContext)
  if (!context) {
    throw new Error('useAppShell must be used within an AppShell component')
  }
  return context
}

export interface AppShellProps {
  children: ReactNode
}

/**
 * AppShell - Responsive app shell wrapper component
 *
 * Provides responsive layout management including:
 * - Mobile/desktop breakpoint handling
 * - Sidebar collapsed state management
 * - Responsive context for child components
 */
const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false)
  const [sidebarVisible, setSidebarVisible] = useState(true)
  const [windowWidth, setWindowWidth] = useState(
    typeof window !== 'undefined' ? window.innerWidth : breakpoints.lg
  )

  // Responsive breakpoint calculations
  const isMobile = windowWidth < sidebar.mobileBreakpoint
  const isTablet = windowWidth >= sidebar.mobileBreakpoint && windowWidth < sidebar.tabletBreakpoint
  const isDesktop = windowWidth >= sidebar.tabletBreakpoint

  // Handle window resize
  useEffect(() => {
    const handleResize = () => {
      setWindowWidth(window.innerWidth)
    }

    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  // Auto-collapse on tablet, hide on mobile
  useEffect(() => {
    if (isMobile) {
      setSidebarVisible(false)
      setCollapsed(true)
    } else if (isTablet) {
      setSidebarVisible(true)
      setCollapsed(true)
    } else {
      setSidebarVisible(true)
      setCollapsed(false)
    }
  }, [isMobile, isTablet])

  const toggleCollapsed = useCallback(() => {
    setCollapsed(prev => !prev)
  }, [])

  const toggleSidebarVisible = useCallback(() => {
    setSidebarVisible(prev => !prev)
  }, [])

  const contextValue: AppShellContextValue = {
    collapsed,
    toggleCollapsed,
    setCollapsed,
    sidebarVisible,
    toggleSidebarVisible,
    setSidebarVisible,
    isMobile,
    isTablet,
    isDesktop,
  }

  return (
    <AppShellContext.Provider value={contextValue}>
      <Layout style={{ minHeight: '100vh' }}>
        {children}
      </Layout>
    </AppShellContext.Provider>
  )
}

export default AppShell
