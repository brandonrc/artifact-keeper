-- Add JSONB repo_selector column to api_tokens.
-- When set, the selector is resolved at auth time to determine allowed repositories.
-- Takes precedence over explicit api_token_repositories rows.
-- Supports: match_labels (AND), match_formats (OR), match_pattern (glob), match_repos (explicit UUIDs).
ALTER TABLE api_tokens ADD COLUMN repo_selector JSONB;
