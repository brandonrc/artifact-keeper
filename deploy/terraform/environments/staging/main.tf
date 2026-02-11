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
      Environment = "staging"
      Project     = "artifact-keeper"
      ManagedBy   = "terraform"
    }
  }
}

locals {
  cluster_name = "artifact-keeper-staging"
  environment  = "staging"

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
  single_nat_gateway = true

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

  endpoint_public_access = true

  node_groups = {
    general = {
      instance_types = ["t3.xlarge"]
      desired_size   = 2
      min_size       = 2
      max_size       = 5
      disk_size      = 80

      labels = {
        role = "general"
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

  instance_class        = "db.t3.large"
  allocated_storage     = 50
  max_allocated_storage = 200
  multi_az              = false
  deletion_protection   = true

  backup_retention_period      = 7
  performance_insights_enabled = true

  tags = local.common_tags
}

################################################################################
# S3
################################################################################

module "s3" {
  source = "../../modules/s3"

  bucket_name            = "artifact-keeper-staging-artifacts"
  force_destroy          = false
  enable_lifecycle_rules = true

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
  default     = "10.1.0.0/16"
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
