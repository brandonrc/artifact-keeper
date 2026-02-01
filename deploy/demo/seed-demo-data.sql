-- Demo seed data for demo.artifactkeeper.com
-- Idempotent: safe to run multiple times.

-- Create demo users (passwords are bcrypt hashes of "demo")
INSERT INTO users (id, username, email, password_hash, role, is_active, must_change_password, created_at)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'admin', 'admin@demo.artifactkeeper.com',
   '$2b$12$LJ3G3/Q.7Cv7y5XLs9XrQOWV3LXhXV0ZaM7Jj4VQsqKV3lEVRVGi', 'admin', true, false, NOW()),
  ('00000000-0000-0000-0000-000000000002', 'developer', 'dev@demo.artifactkeeper.com',
   '$2b$12$LJ3G3/Q.7Cv7y5XLs9XrQOWV3LXhXV0ZaM7Jj4VQsqKV3lEVRVGi', 'user', true, false, NOW()),
  ('00000000-0000-0000-0000-000000000003', 'viewer', 'viewer@demo.artifactkeeper.com',
   '$2b$12$LJ3G3/Q.7Cv7y5XLs9XrQOWV3LXhXV0ZaM7Jj4VQsqKV3lEVRVGi', 'viewer', true, false, NOW())
ON CONFLICT (username) DO NOTHING;

-- Create demo repositories
INSERT INTO repositories (id, key, name, description, repo_type, package_type, created_by, created_at)
VALUES
  ('10000000-0000-0000-0000-000000000001', 'maven-releases', 'Maven Releases',
   'Production Maven artifacts', 'local', 'maven', '00000000-0000-0000-0000-000000000001', NOW()),
  ('10000000-0000-0000-0000-000000000002', 'npm-internal', 'NPM Internal',
   'Internal npm packages', 'local', 'npm', '00000000-0000-0000-0000-000000000001', NOW()),
  ('10000000-0000-0000-0000-000000000003', 'docker-images', 'Docker Images',
   'Container images', 'local', 'docker', '00000000-0000-0000-0000-000000000001', NOW()),
  ('10000000-0000-0000-0000-000000000004', 'pypi-packages', 'PyPI Packages',
   'Python packages', 'local', 'pypi', '00000000-0000-0000-0000-000000000001', NOW()),
  ('10000000-0000-0000-0000-000000000005', 'helm-charts', 'Helm Charts',
   'Kubernetes Helm charts', 'local', 'helm', '00000000-0000-0000-0000-000000000001', NOW())
ON CONFLICT (key) DO NOTHING;

-- Create demo artifacts for maven-releases
INSERT INTO artifacts (id, repository_id, name, version, path, size, checksum_sha256, content_type, created_by, created_at)
VALUES
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:auth-service', '2.4.1',
   'com/example/auth-service/2.4.1/auth-service-2.4.1.jar', 4521984,
   'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', 'application/java-archive',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '30 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:payment-gateway', '1.8.0',
   'com/example/payment-gateway/1.8.0/payment-gateway-1.8.0.jar', 3145728,
   'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', 'application/java-archive',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '25 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:user-api', '3.1.0',
   'com/example/user-api/3.1.0/user-api-3.1.0.jar', 2097152,
   'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 'application/java-archive',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '20 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:notification-service', '1.2.3',
   'com/example/notification-service/1.2.3/notification-service-1.2.3.jar', 1572864,
   'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5', 'application/java-archive',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '15 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:commons-utils', '5.0.2',
   'com/example/commons-utils/5.0.2/commons-utils-5.0.2.jar', 524288,
   'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6', 'application/java-archive',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '10 days')
ON CONFLICT DO NOTHING;

-- Create demo artifacts for npm-internal
INSERT INTO artifacts (id, repository_id, name, version, path, size, checksum_sha256, content_type, created_by, created_at)
VALUES
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@company/design-system', '4.2.0',
   '@company/design-system/-/design-system-4.2.0.tgz', 1048576,
   'f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1', 'application/gzip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '28 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@company/eslint-config', '2.1.0',
   '@company/eslint-config/-/eslint-config-2.1.0.tgz', 32768,
   'a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2', 'application/gzip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '22 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@company/api-client', '3.5.1',
   '@company/api-client/-/api-client-3.5.1.tgz', 262144,
   'b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2d3d4d5d6d7d8d9d0e1e2', 'application/gzip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '18 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@company/logger', '1.0.8',
   '@company/logger/-/logger-1.0.8.tgz', 65536,
   'c1c2c3c4c5c6c7c8c9c0d1d2d3d4d5d6d7d8d9d0e1e2e3e4e5e6e7e8e9e0f1f2', 'application/gzip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '12 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@company/auth-middleware', '2.0.3',
   '@company/auth-middleware/-/auth-middleware-2.0.3.tgz', 131072,
   'd1d2d3d4d5d6d7d8d9d0e1e2e3e4e5e6e7e8e9e0f1f2f3f4f5f6f7f8f9f0a1a2', 'application/gzip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '5 days')
ON CONFLICT DO NOTHING;

-- Create demo artifacts for docker-images
INSERT INTO artifacts (id, repository_id, name, version, path, size, checksum_sha256, content_type, created_by, created_at)
VALUES
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'api-gateway', 'v2.1.0',
   'api-gateway/v2.1.0/manifest.json', 157286400,
   'e1e2e3e4e5e6e7e8e9e0f1f2f3f4f5f6f7f8f9f0a1a2a3a4a5a6a7a8a9a0b1b2', 'application/vnd.docker.distribution.manifest.v2+json',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '14 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'web-frontend', 'v3.0.0-rc1',
   'web-frontend/v3.0.0-rc1/manifest.json', 209715200,
   'f1f2f3f4f5f6f7f8f9f0a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2', 'application/vnd.docker.distribution.manifest.v2+json',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '7 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'worker-service', 'v1.5.2',
   'worker-service/v1.5.2/manifest.json', 104857600,
   'a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3', 'application/vnd.docker.distribution.manifest.v2+json',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '3 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'postgres-backup', 'v1.0.0',
   'postgres-backup/v1.0.0/manifest.json', 52428800,
   'b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4', 'application/vnd.docker.distribution.manifest.v2+json',
   '00000000-0000-0000-0000-000000000001', NOW() - interval '45 days')
ON CONFLICT DO NOTHING;

-- Create demo artifacts for pypi-packages
INSERT INTO artifacts (id, repository_id, name, version, path, size, checksum_sha256, content_type, created_by, created_at)
VALUES
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000004', 'company-ml-pipeline', '1.3.0',
   'company-ml-pipeline/1.3.0/company_ml_pipeline-1.3.0-py3-none-any.whl', 2097152,
   'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5', 'application/zip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '21 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000004', 'company-data-utils', '2.0.1',
   'company-data-utils/2.0.1/company_data_utils-2.0.1-py3-none-any.whl', 524288,
   'd5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6', 'application/zip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '16 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000004', 'company-auth-sdk', '3.2.0',
   'company-auth-sdk/3.2.0/company_auth_sdk-3.2.0-py3-none-any.whl', 131072,
   'e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7', 'application/zip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '9 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000004', 'company-testing', '1.1.0',
   'company-testing/1.1.0/company_testing-1.1.0-py3-none-any.whl', 65536,
   'f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8', 'application/zip',
   '00000000-0000-0000-0000-000000000002', NOW() - interval '4 days')
ON CONFLICT DO NOTHING;

-- Create demo artifacts for helm-charts
INSERT INTO artifacts (id, repository_id, name, version, path, size, checksum_sha256, content_type, created_by, created_at)
VALUES
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000005', 'api-gateway-chart', '1.5.0',
   'api-gateway-chart-1.5.0.tgz', 32768,
   'a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9', 'application/gzip',
   '00000000-0000-0000-0000-000000000001', NOW() - interval '19 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000005', 'monitoring-stack', '2.0.0',
   'monitoring-stack-2.0.0.tgz', 65536,
   'b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0', 'application/gzip',
   '00000000-0000-0000-0000-000000000001', NOW() - interval '11 days'),
  (gen_random_uuid(), '10000000-0000-0000-0000-000000000005', 'redis-ha', '3.1.2',
   'redis-ha-3.1.2.tgz', 16384,
   'c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1', 'application/gzip',
   '00000000-0000-0000-0000-000000000001', NOW() - interval '6 days')
ON CONFLICT DO NOTHING;

-- Create sample audit log entries
INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details, ip_address, created_at)
VALUES
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000002', 'upload', 'artifact', NULL,
   '{"name": "com.example:auth-service", "version": "2.4.1", "repo": "maven-releases"}',
   '10.0.1.50', NOW() - interval '30 days'),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000002', 'upload', 'artifact', NULL,
   '{"name": "@company/design-system", "version": "4.2.0", "repo": "npm-internal"}',
   '10.0.1.51', NOW() - interval '28 days'),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'create', 'repository', NULL,
   '{"key": "helm-charts", "type": "local"}',
   '10.0.1.1', NOW() - interval '25 days'),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000002', 'upload', 'artifact', NULL,
   '{"name": "api-gateway", "version": "v2.1.0", "repo": "docker-images"}',
   '10.0.1.52', NOW() - interval '14 days'),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000002', 'download', 'artifact', NULL,
   '{"name": "com.example:commons-utils", "version": "5.0.2", "repo": "maven-releases"}',
   '10.0.2.100', NOW() - interval '8 days'),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000003', 'download', 'artifact', NULL,
   '{"name": "@company/api-client", "version": "3.5.1", "repo": "npm-internal"}',
   '10.0.2.101', NOW() - interval '5 days'),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'scan', 'repository', NULL,
   '{"repo": "docker-images", "scanner": "trivy", "findings": 3}',
   '10.0.1.1', NOW() - interval '2 days')
ON CONFLICT DO NOTHING;
