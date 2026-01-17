/**
 * Ant Design theme configuration
 * Custom design system for Artifact Keeper
 */

import type { ThemeConfig } from 'antd';
import { colors, borderRadius, typography, sidebar } from './tokens';

/**
 * Ant Design theme configuration with custom styling
 */
export const antdTheme: ThemeConfig = {
  token: {
    // Primary colors
    colorPrimary: colors.primary,
    colorSuccess: colors.success,
    colorWarning: colors.warning,
    colorError: colors.error,
    colorInfo: colors.info,

    // Background colors
    colorBgContainer: colors.bgContainer,
    colorBgLayout: colors.bgLayout,

    // Text colors
    colorText: colors.textPrimary,
    colorTextSecondary: colors.textSecondary,
    colorTextTertiary: colors.textTertiary,
    colorTextDisabled: colors.textDisabled,

    // Border colors
    colorBorder: colors.border,
    colorBorderSecondary: colors.borderLight,

    // Link colors
    colorLink: colors.link,
    colorLinkHover: colors.linkHover,

    // Border radius
    borderRadius: borderRadius.md,
    borderRadiusSM: borderRadius.sm,
    borderRadiusLG: borderRadius.lg,

    // Typography
    fontFamily: typography.fontFamily,
    fontSize: typography.fontSizeBase,
    fontSizeSM: typography.fontSizeSm,
    fontSizeLG: typography.fontSizeLg,
    fontSizeXL: typography.fontSizeXl,
    lineHeight: typography.lineHeight,
  },
  components: {
    Layout: {
      siderBg: colors.siderBg,
      headerBg: colors.bgContainer,
      bodyBg: colors.bgLayout,
    },
    Menu: {
      darkItemBg: colors.siderBg,
      darkItemColor: colors.siderText,
      darkItemSelectedBg: colors.primary,
      darkItemHoverBg: 'rgba(255, 255, 255, 0.08)',
      darkSubMenuItemBg: colors.siderBg,
    },
    Button: {
      primaryColor: '#FFFFFF',
      defaultBorderColor: colors.border,
    },
    Card: {
      headerBg: colors.bgContainer,
    },
    Table: {
      headerBg: colors.bgLayout,
      rowHoverBg: colors.bgContainerLight,
    },
    Tree: {
      directoryNodeSelectedBg: colors.bgContainerLight,
      nodeSelectedBg: colors.bgContainerLight,
    },
    Tabs: {
      inkBarColor: colors.primary,
      itemSelectedColor: colors.primary,
    },
    Tag: {
      defaultBg: colors.bgLayout,
    },
    Modal: {
      headerBg: colors.bgContainer,
      contentBg: colors.bgContainer,
    },
    Notification: {
      width: 384,
    },
    Message: {
      contentBg: colors.bgContainer,
    },
  },
};

/**
 * Dark theme configuration (for future use)
 */
export const antdDarkTheme: ThemeConfig = {
  token: {
    colorPrimary: colors.primary,
    colorBgContainer: '#1F1F1F',
    colorBgLayout: '#141414',
    colorText: 'rgba(255, 255, 255, 0.85)',
    colorTextSecondary: 'rgba(255, 255, 255, 0.65)',
    colorTextTertiary: 'rgba(255, 255, 255, 0.45)',
    colorBorder: '#424242',
    colorBorderSecondary: '#303030',
  },
};

/**
 * Get sidebar style based on collapsed state
 */
export const getSiderStyle = (collapsed: boolean) => ({
  width: collapsed ? sidebar.collapsedWidth : sidebar.width,
  minWidth: collapsed ? sidebar.collapsedWidth : sidebar.width,
  maxWidth: collapsed ? sidebar.collapsedWidth : sidebar.width,
  background: colors.siderBg,
});

/**
 * Status color mapping for severity indicators
 */
export const getStatusColor = (status: string): string => {
  const statusColors: Record<string, string> = {
    critical: colors.severity.critical,
    high: colors.severity.high,
    medium: colors.severity.medium,
    low: colors.severity.low,
    ok: colors.severity.ok,
    success: colors.success,
    error: colors.error,
    warning: colors.warning,
    info: colors.info,
    healthy: colors.success,
    unhealthy: colors.error,
    active: colors.success,
    inactive: colors.textDisabled,
    pending: colors.warning,
  };

  return statusColors[status.toLowerCase()] || colors.textSecondary;
};

/**
 * Repository type color mapping
 */
export const getRepoTypeColor = (type: string): string => {
  const typeColors: Record<string, string> = {
    local: '#52C41A',     // Green
    remote: '#FA8C16',    // Orange
    virtual: '#722ED1',   // Purple
    federated: '#13C2C2', // Cyan
  };

  return typeColors[type.toLowerCase()] || colors.primary;
};

/**
 * Package type icon colors
 */
export const getPackageTypeColor = (type: string): string => {
  const packageColors: Record<string, string> = {
    maven: '#C71A36',
    npm: '#CB3837',
    docker: '#2496ED',
    pypi: '#3776AB',
    go: '#00ADD8',
    cargo: '#DEA584',
    nuget: '#004880',
    helm: '#0F1689',
    rubygems: '#CC342D',
    debian: '#A81D33',
    rpm: '#EE0000',
    generic: colors.textSecondary,
  };

  return packageColors[type.toLowerCase()] || colors.primary;
};

export default antdTheme;
