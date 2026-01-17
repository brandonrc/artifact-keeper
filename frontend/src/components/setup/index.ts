/**
 * Setup Components
 *
 * Re-exports all setup-related components.
 */

// CI/CD Platform Setup
export {
  CICDPlatformWizard,
  JenkinsSetup,
  GitHubActionsSetup,
  GitLabCISetup,
  AzureDevOpsSetup,
  CodeBlock,
} from './CICDPlatform';

export type {
  CICDPlatformWizardProps,
  JenkinsSetupProps,
  GitHubActionsSetupProps,
  GitLabCISetupProps,
  AzureDevOpsSetupProps,
} from './CICDPlatform';

// Package Manager Setup
export {
  PackageManagerWizard,
  MavenSetup,
  NpmSetup,
  DockerSetup,
  PyPISetup,
  CodeBlock as PackageManagerCodeBlock,
} from './PackageManager';

export type {
  PackageManagerWizardProps,
  MavenSetupProps,
  NpmSetupProps,
  DockerSetupProps,
  PyPISetupProps,
  CodeBlockProps as PackageManagerCodeBlockProps,
} from './PackageManager';
