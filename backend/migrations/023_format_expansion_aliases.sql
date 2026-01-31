-- Format expansion: alias formats that map to existing handlers
-- OCI-based: podman, buildx, oras, wasm_oci, helm_oci
-- PyPI-based: poetry, conda
-- npm-based: yarn, bower, pnpm
-- NuGet-based: chocolatey, powershell

ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'podman';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'buildx';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'oras';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'wasm_oci';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'helm_oci';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'poetry';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'conda';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'yarn';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'bower';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'pnpm';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'chocolatey';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'powershell';
