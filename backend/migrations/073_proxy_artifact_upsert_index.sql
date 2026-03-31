-- Partial unique index for proxy artifact upsert.
-- Allows ON CONFLICT (repository_id, path) WHERE is_deleted = false
-- in register_proxied_artifact without conflicting with soft-deleted rows.
CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_repo_path_not_deleted
ON artifacts (repository_id, path) WHERE is_deleted = false;
