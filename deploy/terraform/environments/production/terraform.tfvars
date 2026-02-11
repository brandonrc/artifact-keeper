# =============================================================================
# EXAMPLE CONFIGURATION - Getting Started Template
# =============================================================================
# This file is provided as a starting point for deployments. It should be
# reviewed and modified to match your specific infrastructure requirements,
# security policies, and operational needs before use in production.
# =============================================================================

aws_region = "us-east-1"
vpc_cidr   = "10.2.0.0/16"

enable_s3_replication                = false
s3_replication_role_arn              = ""
s3_replication_destination_bucket_arn = ""
