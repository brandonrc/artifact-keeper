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

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# S3 Bucket
################################################################################

resource "aws_s3_bucket" "artifacts" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.tags, {
    Name = var.bucket_name
  })
}

################################################################################
# Versioning
################################################################################

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

################################################################################
# Server-Side Encryption
################################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

################################################################################
# Block Public Access
################################################################################

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

################################################################################
# Lifecycle Rules
################################################################################

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  count = var.enable_lifecycle_rules ? 1 : 0

  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = 730
    }
  }
}

################################################################################
# Bucket Policy - Allow access from EKS IRSA role
################################################################################

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid    = "AllowEKSIRSAAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = var.irsa_role_arns
    }

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]

    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  count = length(var.irsa_role_arns) > 0 ? 1 : 0

  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

################################################################################
# Replication Configuration (optional, for production)
################################################################################

resource "aws_s3_bucket_replication_configuration" "artifacts" {
  count = var.enable_replication ? 1 : 0

  bucket = aws_s3_bucket.artifacts.id
  role   = var.replication_role_arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = var.replication_destination_bucket_arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}
