# =============================================================================
# EXAMPLE CONFIGURATION - Getting Started Template
# =============================================================================
# This file is provided as a starting point for deployments. It should be
# reviewed and modified to match your specific infrastructure requirements,
# security policies, and operational needs before use in production.
# =============================================================================

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.29"
}

variable "vpc_id" {
  description = "ID of the VPC where the cluster will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the EKS cluster and node groups"
  type        = list(string)
}

variable "endpoint_public_access" {
  description = "Whether the EKS API server endpoint is publicly accessible"
  type        = bool
  default     = true
}

variable "node_groups" {
  description = "Map of managed node group configurations"
  type = map(object({
    instance_types = list(string)
    desired_size   = number
    min_size       = number
    max_size       = number
    capacity_type  = optional(string, "ON_DEMAND")
    disk_size      = optional(number, 50)
    labels         = optional(map(string), {})
  }))
  default = {
    default = {
      instance_types = ["t3.large"]
      desired_size   = 2
      min_size       = 1
      max_size       = 5
    }
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
