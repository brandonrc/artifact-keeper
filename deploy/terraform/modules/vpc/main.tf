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

data "aws_availability_zones" "available" {
  state = "available"
}

################################################################################
# VPC
################################################################################

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, {
    Name                                            = "${var.cluster_name}-vpc"
    "kubernetes.io/cluster/${var.cluster_name}"      = "shared"
  })
}

################################################################################
# Internet Gateway
################################################################################

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-igw"
  })
}

################################################################################
# Public Subnets
################################################################################

resource "aws_subnet" "public" {
  count = 3

  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name                                            = "${var.cluster_name}-public-${data.aws_availability_zones.available.names[count.index]}"
    "kubernetes.io/cluster/${var.cluster_name}"      = "shared"
    "kubernetes.io/role/elb"                         = "1"
  })
}

################################################################################
# Private Subnets
################################################################################

resource "aws_subnet" "private" {
  count = 3

  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 3)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(var.tags, {
    Name                                            = "${var.cluster_name}-private-${data.aws_availability_zones.available.names[count.index]}"
    "kubernetes.io/cluster/${var.cluster_name}"      = "shared"
    "kubernetes.io/role/internal-elb"                = "1"
  })
}

################################################################################
# NAT Gateway(s)
################################################################################

resource "aws_eip" "nat" {
  count  = var.single_nat_gateway ? 1 : 3
  domain = "vpc"

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-nat-eip-${count.index}"
  })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  count = var.single_nat_gateway ? 1 : 3

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-nat-${count.index}"
  })

  depends_on = [aws_internet_gateway.this]
}

################################################################################
# Route Tables - Public
################################################################################

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-public-rt"
  })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = 3

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

################################################################################
# Route Tables - Private
################################################################################

resource "aws_route_table" "private" {
  count = var.single_nat_gateway ? 1 : 3

  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-private-rt-${count.index}"
  })
}

resource "aws_route" "private_nat" {
  count = var.single_nat_gateway ? 1 : 3

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[count.index].id
}

resource "aws_route_table_association" "private" {
  count = 3

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[var.single_nat_gateway ? 0 : count.index].id
}
