-- Format expansion: remaining native format handlers

-- Language-specific
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'hex';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'cocoapods';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'swift';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'pub';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'sbt';

-- Config management
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'chef';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'puppet';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'ansible';

-- Git LFS
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'gitlfs';

-- Editor extensions
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'vscode';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'jetbrains';

-- ML/AI
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'huggingface';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'mlmodel';

-- Miscellaneous
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'cran';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'vagrant';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'opkg';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'p2';
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'bazel';
