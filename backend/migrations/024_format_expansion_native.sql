-- Format expansion: native format handlers
-- New formats requiring their own handler implementations

ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'terraform';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'opentofu';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'alpine';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'conda_native';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'composer';
