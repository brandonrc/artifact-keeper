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
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

################################################################################
# Random Password
################################################################################

resource "random_password" "master" {
  length  = 32
  special = false
}

################################################################################
# DB Subnet Group
################################################################################

resource "aws_db_subnet_group" "this" {
  name       = "${var.cluster_name}-db-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-db-subnet-group"
  })
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds-"
  description = "Security group for RDS PostgreSQL - allows access from EKS nodes only"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-rds-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "rds_ingress_eks" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.eks_security_group_id
  security_group_id        = aws_security_group.rds.id
  description              = "Allow PostgreSQL access from EKS cluster nodes"
}

resource "aws_security_group_rule" "rds_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.rds.id
  description       = "Allow all egress"
}

################################################################################
# RDS PostgreSQL Instance
################################################################################

resource "aws_db_instance" "this" {
  identifier = "${var.cluster_name}-postgres"

  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.database_name
  username = var.database_username
  password = random_password.master.result
  port     = 5432

  multi_az            = var.multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = var.backup_retention_period
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.cluster_name}-postgres-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  deletion_protection       = var.deletion_protection
  copy_tags_to_snapshot     = true

  performance_insights_enabled = var.performance_insights_enabled

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-postgres"
  })

  lifecycle {
    ignore_changes = [final_snapshot_identifier]
  }
}

################################################################################
# Store password in AWS Secrets Manager
################################################################################

resource "aws_secretsmanager_secret" "db_password" {
  name        = "${var.cluster_name}/rds/master-password"
  description = "Master password for ${var.cluster_name} RDS PostgreSQL instance"

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = var.database_username
    password = random_password.master.result
    host     = aws_db_instance.this.address
    port     = aws_db_instance.this.port
    dbname   = var.database_name
    endpoint = aws_db_instance.this.endpoint
  })
}
