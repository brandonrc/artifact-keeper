/**
 * Package Manager Setup Components
 *
 * Provides setup wizards and configuration guides for various package managers.
 */

// Main wizard component
export { PackageManagerWizard } from './PackageManagerWizard';
export type { PackageManagerWizardProps } from './PackageManagerWizard';

// Package manager specific setup components
export { MavenSetup } from './MavenSetup';
export type { MavenSetupProps } from './MavenSetup';

export { NpmSetup } from './NpmSetup';
export type { NpmSetupProps } from './NpmSetup';

export { DockerSetup } from './DockerSetup';
export type { DockerSetupProps } from './DockerSetup';

export { PyPISetup } from './PyPISetup';
export type { PyPISetupProps } from './PyPISetup';

// Code block component (reusable)
export { CodeBlock } from './CodeBlock';
export type { CodeBlockProps } from './CodeBlock';
