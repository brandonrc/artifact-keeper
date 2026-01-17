/**
 * Design tokens for Artifact Keeper UI
 */

// Primary color palette
export const colors = {
  // Primary brand colors
  primary: '#3EB065',        // Primary green
  primaryHover: '#7CCF83',   // Lighter green for hover states
  primaryActive: '#2D9050',  // Darker green for active states

  // Sidebar colors
  siderBg: '#152033',        // Dark navy sidebar
  siderText: '#FFFFFF',
  siderTextSecondary: 'rgba(255, 255, 255, 0.65)',
  siderTextMuted: 'rgba(255, 255, 255, 0.45)',
  siderBorder: 'rgba(255, 255, 255, 0.1)',

  // Background colors
  bgContainer: '#FFFFFF',
  bgLayout: '#F5F5F5',
  bgContainerLight: '#F9FFF9', // Light green tint

  // Status/severity colors
  success: '#3EB065',        // Green - OK/Success
  error: '#FF4D4F',          // Red - Critical
  warning: '#FAAD14',        // Orange - High
  info: '#1677FF',           // Blue - Low/Info

  // Severity mapping (for scan results, etc.)
  severity: {
    critical: '#FF4D4F',     // Red
    high: '#FA8C16',         // Orange
    medium: '#FADB14',       // Yellow
    low: '#1677FF',          // Blue
    ok: '#3EB065',           // Green
  },

  // Status indicators for various states
  status: {
    online: '#52C41A',       // Green - Online/Connected
    offline: '#FF4D4F',      // Red - Offline/Disconnected
    syncing: '#1677FF',      // Blue - Syncing/In Progress
    idle: '#8C8C8C',         // Gray - Idle/Inactive
    paused: '#FAAD14',       // Orange - Paused/Waiting
    queued: '#722ED1',       // Purple - Queued
    cancelled: '#BFBFBF',    // Light Gray - Cancelled
    scheduled: '#13C2C2',    // Cyan - Scheduled
  },

  // Build/CI status colors
  build: {
    success: '#52C41A',      // Green - Build passed
    failed: '#FF4D4F',       // Red - Build failed
    running: '#1677FF',      // Blue - Build in progress
    pending: '#FAAD14',      // Orange - Build pending
    cancelled: '#8C8C8C',    // Gray - Build cancelled
    unstable: '#FA8C16',     // Orange - Unstable build
  },

  // Text colors
  textPrimary: 'rgba(0, 0, 0, 0.88)',
  textSecondary: 'rgba(0, 0, 0, 0.65)',
  textTertiary: 'rgba(0, 0, 0, 0.45)',
  textDisabled: 'rgba(0, 0, 0, 0.25)',

  // Border colors
  border: '#D9D9D9',
  borderLight: '#F0F0F0',

  // Link colors
  link: '#1677FF',
  linkHover: '#69B1FF',
};

// Spacing scale (in pixels)
export const spacing = {
  xxs: 4,
  xs: 8,
  sm: 12,
  md: 16,
  lg: 24,
  xl: 32,
  xxl: 48,
};

// Border radius
export const borderRadius = {
  sm: 4,
  md: 6,
  lg: 8,
  xl: 12,
  full: 9999,
};

// Typography
export const typography = {
  fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
  fontSizeBase: 14,
  fontSizeSm: 12,
  fontSizeLg: 16,
  fontSizeXl: 20,
  fontSizeXxl: 24,
  lineHeight: 1.5715,
  fontWeightNormal: 400,
  fontWeightMedium: 500,
  fontWeightSemibold: 600,
  fontWeightBold: 700,
};

// Shadows
export const shadows = {
  sm: '0 1px 2px 0 rgba(0, 0, 0, 0.03), 0 1px 6px -1px rgba(0, 0, 0, 0.02), 0 2px 4px 0 rgba(0, 0, 0, 0.02)',
  md: '0 3px 6px -4px rgba(0, 0, 0, 0.12), 0 6px 16px 0 rgba(0, 0, 0, 0.08), 0 9px 28px 8px rgba(0, 0, 0, 0.05)',
  lg: '0 6px 16px -8px rgba(0, 0, 0, 0.08), 0 9px 28px 0 rgba(0, 0, 0, 0.05), 0 12px 48px 16px rgba(0, 0, 0, 0.03)',
};

// Z-index scale
export const zIndex = {
  dropdown: 1050,
  sticky: 1020,
  fixed: 1030,
  modalBackdrop: 1040,
  modal: 1050,
  popover: 1060,
  tooltip: 1070,
  toast: 1080,
};

// Responsive breakpoints
export const breakpoints = {
  xs: 480,
  sm: 576,
  md: 768,
  lg: 992,
  xl: 1200,
  xxl: 1600,
};

// Sidebar dimensions
export const sidebar = {
  width: 200,
  collapsedWidth: 80,
  mobileBreakpoint: breakpoints.md,  // 768px - hidden with hamburger
  tabletBreakpoint: breakpoints.xl,  // 1200px - collapsible
};

// Animation durations
export const animation = {
  fast: '0.1s',
  normal: '0.2s',
  slow: '0.3s',
};

// Toast notification settings
export const toast = {
  duration: 5, // seconds
  maxCount: 5,
};

// Export combined design tokens
export const designTokens = {
  colors,
  spacing,
  borderRadius,
  typography,
  shadows,
  zIndex,
  breakpoints,
  sidebar,
  animation,
  toast,
};

export default designTokens;
