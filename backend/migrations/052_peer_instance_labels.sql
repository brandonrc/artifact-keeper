-- Peer instance labels: key:value tags for sync policy matching
CREATE TABLE IF NOT EXISTS peer_instance_labels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    peer_instance_id UUID NOT NULL REFERENCES peer_instances(id) ON DELETE CASCADE,
    label_key VARCHAR(128) NOT NULL,
    label_value VARCHAR(256) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(peer_instance_id, label_key)
);

CREATE INDEX IF NOT EXISTS idx_peer_instance_labels_peer ON peer_instance_labels(peer_instance_id);
CREATE INDEX IF NOT EXISTS idx_peer_instance_labels_key_value ON peer_instance_labels(label_key, label_value);

COMMENT ON TABLE peer_instance_labels IS 'Key:value labels on peer instances for sync policy matching and organization';
COMMENT ON COLUMN peer_instance_labels.label_key IS 'Label key (e.g. region, tier, environment)';
COMMENT ON COLUMN peer_instance_labels.label_value IS 'Label value (e.g. us-east, critical, production). Empty string for bare tags.';
