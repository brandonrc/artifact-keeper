-- Service account flag on users table.
-- Service accounts are machine identities managed by admins, not tied to
-- any single human. They authenticate only via API tokens (no password,
-- no TOTP, no SSO).
ALTER TABLE users
    ADD COLUMN is_service_account BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX idx_users_service_account
    ON users(is_service_account) WHERE is_service_account = true;

-- Per-repository token restrictions.
-- If a token has no rows here, it can access all repositories (within its
-- scope limits). If rows exist, the token is restricted to only those repos.
CREATE TABLE api_token_repositories (
    token_id UUID NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
    repo_id  UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, repo_id)
);

CREATE INDEX idx_api_token_repos_repo ON api_token_repositories(repo_id);

-- Track which admin created each token. For service account tokens this is
-- the admin who issued it, not the service account itself.
ALTER TABLE api_tokens
    ADD COLUMN created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Optional human-readable description for tokens.
ALTER TABLE api_tokens
    ADD COLUMN description TEXT;
