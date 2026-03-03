//! Repository model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Repository format enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "repository_format", rename_all = "lowercase")]
pub enum RepositoryFormat {
    Maven,
    Gradle,
    Npm,
    Pypi,
    Nuget,
    Go,
    Rubygems,
    Docker,
    Helm,
    Rpm,
    Debian,
    Conan,
    Cargo,
    Generic,
    // OCI-based aliases
    Podman,
    Buildx,
    Oras,
    #[sqlx(rename = "wasm_oci")]
    WasmOci,
    #[sqlx(rename = "helm_oci")]
    HelmOci,
    // PyPI-based aliases
    Poetry,
    Conda,
    // npm-based aliases
    Yarn,
    Bower,
    Pnpm,
    // NuGet-based aliases
    Chocolatey,
    Powershell,
    // Native format handlers
    Terraform,
    Opentofu,
    Alpine,
    #[sqlx(rename = "conda_native")]
    CondaNative,
    Composer,
    // Language-specific
    Hex,
    Cocoapods,
    Swift,
    Pub,
    Sbt,
    // Config management
    Chef,
    Puppet,
    Ansible,
    // Git LFS
    Gitlfs,
    // Editor extensions
    Vscode,
    Jetbrains,
    // ML/AI
    Huggingface,
    Mlmodel,
    // Miscellaneous
    Cran,
    Vagrant,
    Opkg,
    P2,
    Bazel,
    // Schema registries
    Protobuf,
    // Container images
    Incus,
    Lxc,
}

/// Repository type enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "repository_type", rename_all = "lowercase")]
pub enum RepositoryType {
    Local,
    Remote,
    Virtual,
    Staging,
}

impl RepositoryType {
    /// Return the lowercase string representation matching the database enum.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Virtual => "virtual",
            Self::Staging => "staging",
        }
    }

    /// Check if this is a staging repository (requires promotion to release)
    pub fn is_staging(&self) -> bool {
        matches!(self, RepositoryType::Staging)
    }

    /// Check if this is a hosted repository (Local or Staging)
    pub fn is_hosted(&self) -> bool {
        matches!(self, RepositoryType::Local | RepositoryType::Staging)
    }
}

macro_rules! impl_repo_type_eq {
    ($($T:ty),+) => { $(
        impl PartialEq<RepositoryType> for $T {
            fn eq(&self, other: &RepositoryType) -> bool {
                AsRef::<str>::as_ref(self) == other.as_str()
            }
        }
        impl PartialEq<$T> for RepositoryType {
            fn eq(&self, other: &$T) -> bool {
                self.as_str() == AsRef::<str>::as_ref(other)
            }
        }
    )+ };
}

impl_repo_type_eq!(str, &str, String);

/// Replication priority for Borg replication policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "replication_priority", rename_all = "snake_case")]
pub enum ReplicationPriority {
    Immediate,
    Scheduled,
    OnDemand,
    LocalOnly,
}

/// Repository entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Repository {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    pub is_public: bool,
    pub quota_bytes: Option<i64>,
    pub replication_priority: ReplicationPriority,
    /// For staging repos: default release repo to promote artifacts to
    pub promotion_target_id: Option<Uuid>,
    /// For staging repos: security policy to evaluate before promotion
    pub promotion_policy_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Virtual repository member entity
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct VirtualRepoMember {
    pub id: Uuid,
    pub virtual_repo_id: Uuid,
    pub member_repo_id: Uuid,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repository_type_is_staging() {
        assert!(RepositoryType::Staging.is_staging());
        assert!(!RepositoryType::Local.is_staging());
        assert!(!RepositoryType::Remote.is_staging());
        assert!(!RepositoryType::Virtual.is_staging());
    }

    #[test]
    fn test_repository_type_is_hosted() {
        assert!(RepositoryType::Local.is_hosted());
        assert!(RepositoryType::Staging.is_hosted());
        assert!(!RepositoryType::Remote.is_hosted());
        assert!(!RepositoryType::Virtual.is_hosted());
    }

    #[test]
    fn test_repository_type_as_str() {
        assert_eq!(RepositoryType::Local.as_str(), "local");
        assert_eq!(RepositoryType::Remote.as_str(), "remote");
        assert_eq!(RepositoryType::Virtual.as_str(), "virtual");
        assert_eq!(RepositoryType::Staging.as_str(), "staging");
    }

    #[test]
    fn test_repository_type_string_eq() {
        let s = String::from("remote");
        assert!(s == RepositoryType::Remote);
        assert!(RepositoryType::Remote == s);
        assert!(s != RepositoryType::Local);
    }

    #[test]
    fn test_repository_type_str_eq() {
        assert!("remote" == RepositoryType::Remote);
        assert!("virtual" == RepositoryType::Virtual);
        assert!(RepositoryType::Local == "local");
        assert!(RepositoryType::Staging == "staging");
        assert!("remote" != RepositoryType::Local);
    }
}
