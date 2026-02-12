-- Sync policies: declarative rules that resolve repository+peer subscriptions
CREATE TABLE IF NOT EXISTS sync_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Repository selector (which repos match)
    repo_selector JSONB NOT NULL DEFAULT '{}',
    -- Supports: {"match_labels": {"env": "prod"}, "match_formats": ["docker", "maven"], "match_pattern": "libs-*", "match_repos": ["uuid1", "uuid2"]}

    -- Peer selector (which peers to replicate to)
    peer_selector JSONB NOT NULL DEFAULT '{}',
    -- Supports: {"all": true} or {"match_labels": {"region": "us-east"}, "match_region": "us-east", "match_peers": ["uuid1"]}

    replication_mode VARCHAR(20) NOT NULL DEFAULT 'push',
    priority INTEGER NOT NULL DEFAULT 0,

    -- Artifact filter (optional constraints on what gets synced)
    artifact_filter JSONB NOT NULL DEFAULT '{}',
    -- Supports: {"max_age_days": 90, "include_paths": ["release/*"], "exclude_paths": ["snapshot/*"], "max_size_bytes": 1073741824}

    precedence INTEGER NOT NULL DEFAULT 100, -- lower = higher priority
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sync_policies_enabled ON sync_policies(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_sync_policies_precedence ON sync_policies(precedence, created_at);

-- Add policy_id FK to peer_repo_subscriptions so we can track which subscriptions are policy-managed
ALTER TABLE peer_repo_subscriptions ADD COLUMN IF NOT EXISTS policy_id UUID REFERENCES sync_policies(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_peer_repo_subscriptions_policy ON peer_repo_subscriptions(policy_id) WHERE policy_id IS NOT NULL;

COMMENT ON TABLE sync_policies IS 'Declarative sync policies that automatically create peer_repo_subscriptions based on label/format/pattern selectors';
COMMENT ON COLUMN sync_policies.repo_selector IS 'JSONB selector for matching repositories by labels, formats, name patterns, or explicit IDs';
COMMENT ON COLUMN sync_policies.peer_selector IS 'JSONB selector for matching peer instances by labels, region, or explicit IDs';
COMMENT ON COLUMN sync_policies.artifact_filter IS 'Optional JSONB filter constraining which artifacts within matched repos get synced';
COMMENT ON COLUMN sync_policies.precedence IS 'Lower values = higher priority. Used to resolve conflicts when multiple policies match the same repo+peer pair';
COMMENT ON COLUMN peer_repo_subscriptions.policy_id IS 'References the sync policy that created this subscription, NULL for manually created subscriptions';
