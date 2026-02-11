# =============================================================================
# EXAMPLE CONFIGURATION - Getting Started Template
# =============================================================================
# This file is provided as a starting point for deployments. It should be
# reviewed and modified to match your specific infrastructure requirements,
# security policies, and operational needs before use in production.
# =============================================================================

variable "bucket_name" {
  description = "Name of the S3 bucket for artifact storage"
  type        = string
}

variable "force_destroy" {
  description = "Allow bucket to be destroyed even if it contains objects (use with caution)"
  type        = bool
  default     = false
}

variable "enable_lifecycle_rules" {
  description = "Enable lifecycle rules for transitioning objects to cheaper storage classes"
  type        = bool
  default     = false
}

variable "irsa_role_arns" {
  description = "List of IAM role ARNs (from EKS IRSA) that should have access to the bucket"
  type        = list(string)
  default     = []
}

variable "enable_replication" {
  description = "Enable cross-region replication for the bucket"
  type        = bool
  default     = false
}

variable "replication_role_arn" {
  description = "ARN of the IAM role for S3 replication (required if enable_replication is true)"
  type        = string
  default     = ""
}

variable "replication_destination_bucket_arn" {
  description = "ARN of the destination bucket for replication (required if enable_replication is true)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
