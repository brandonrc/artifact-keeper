import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { ConfigProvider } from 'antd';
import { antdTheme, antdDarkTheme } from '../styles/theme';
import { colors, sidebar } from '../styles/tokens';

type ThemeMode = 'light' | 'dark';

interface ThemeContextValue {
  mode: ThemeMode;
  sidebarCollapsed: boolean;
  toggleTheme: () => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  colors: typeof colors;
  sidebar: typeof sidebar;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

interface ThemeProviderProps {
  children: React.ReactNode;
  defaultMode?: ThemeMode;
  defaultSidebarCollapsed?: boolean;
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({
  children,
  defaultMode = 'light',
  defaultSidebarCollapsed = false,
}) => {
  const [mode, setMode] = useState<ThemeMode>(defaultMode);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(defaultSidebarCollapsed);

  const toggleTheme = useCallback(() => {
    setMode((prev) => (prev === 'light' ? 'dark' : 'light'));
  }, []);

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => !prev);
  }, []);

  const theme = mode === 'light' ? antdTheme : antdDarkTheme;

  const value = useMemo(
    () => ({
      mode,
      sidebarCollapsed,
      toggleTheme,
      toggleSidebar,
      setSidebarCollapsed,
      colors,
      sidebar,
    }),
    [mode, sidebarCollapsed, toggleTheme, toggleSidebar]
  );

  return (
    <ThemeContext.Provider value={value}>
      <ConfigProvider theme={theme}>{children}</ConfigProvider>
    </ThemeContext.Provider>
  );
};

export const useTheme = (): ThemeContextValue => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

export default ThemeContext;
