# =============================================================================
# EXAMPLE CONFIGURATION - Getting Started Template
# =============================================================================
# This file is provided as a starting point for deployments. It should be
# reviewed and modified to match your specific infrastructure requirements,
# security policies, and operational needs before use in production.
# =============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = "production"
      Project     = "artifact-keeper"
      ManagedBy   = "terraform"
    }
  }
}

locals {
  cluster_name = "artifact-keeper-production"
  environment  = "production"

  common_tags = {
    Environment = local.environment
    Project     = "artifact-keeper"
  }
}

################################################################################
# VPC
################################################################################

module "vpc" {
  source = "../../modules/vpc"

  vpc_cidr           = var.vpc_cidr
  cluster_name       = local.cluster_name
  single_nat_gateway = false

  tags = local.common_tags
}

################################################################################
# EKS
################################################################################

module "eks" {
  source = "../../modules/eks"

  cluster_name       = local.cluster_name
  kubernetes_version = "1.29"
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnet_ids

  endpoint_public_access = false

  node_groups = {
    general = {
      instance_types = ["t3.xlarge"]
      desired_size   = 3
      min_size       = 3
      max_size       = 10
      disk_size      = 100

      labels = {
        role = "general"
      }
    }
    compute = {
      instance_types = ["c6i.2xlarge"]
      desired_size   = 3
      min_size       = 3
      max_size       = 20
      disk_size      = 100

      labels = {
        role = "compute"
      }
    }
  }

  tags = local.common_tags
}

################################################################################
# RDS
################################################################################

module "rds" {
  source = "../../modules/rds"

  cluster_name          = local.cluster_name
  vpc_id                = module.vpc.vpc_id
  subnet_ids            = module.vpc.private_subnet_ids
  eks_security_group_id = module.eks.cluster_security_group_id

  instance_class        = "db.r6g.large"
  allocated_storage     = 100
  max_allocated_storage = 500
  multi_az              = true
  deletion_protection   = true

  backup_retention_period      = 14
  performance_insights_enabled = true

  tags = local.common_tags
}

################################################################################
# S3
################################################################################

module "s3" {
  source = "../../modules/s3"

  bucket_name            = "artifact-keeper-production-artifacts"
  force_destroy          = false
  enable_lifecycle_rules = true

  enable_replication                = var.enable_s3_replication
  replication_role_arn              = var.s3_replication_role_arn
  replication_destination_bucket_arn = var.s3_replication_destination_bucket_arn

  tags = local.common_tags
}

################################################################################
# Variables
################################################################################

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.2.0.0/16"
}

variable "enable_s3_replication" {
  description = "Enable cross-region replication for the artifacts S3 bucket"
  type        = bool
  default     = false
}

variable "s3_replication_role_arn" {
  description = "ARN of the IAM role for S3 replication"
  type        = string
  default     = ""
}

variable "s3_replication_destination_bucket_arn" {
  description = "ARN of the destination bucket for S3 replication"
  type        = string
  default     = ""
}

################################################################################
# Outputs
################################################################################

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "Endpoint for the EKS cluster"
  value       = module.eks.cluster_endpoint
}

output "eks_oidc_provider_arn" {
  description = "ARN of the OIDC provider for IRSA"
  value       = module.eks.oidc_provider_arn
}

output "rds_endpoint" {
  description = "Endpoint for the RDS instance"
  value       = module.rds.db_instance_endpoint
}

output "rds_password_secret_arn" {
  description = "ARN of the Secrets Manager secret for the DB password"
  value       = module.rds.db_password_secret_arn
}

output "s3_bucket_name" {
  description = "Name of the artifacts S3 bucket"
  value       = module.s3.bucket_name
}

output "s3_bucket_arn" {
  description = "ARN of the artifacts S3 bucket"
  value       = module.s3.bucket_arn
}
