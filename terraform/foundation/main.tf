terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1" # change to your preferred home region
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------------------
# One VPC, three subnet tiers standing in for the three former accounts.
# ---------------------------------------------------------------------------
resource "aws_vpc" "aegiscloud" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "aegiscloud-vpc", Project = "aegiscloud" }
}

resource "aws_subnet" "security_tools" {
  vpc_id            = aws_vpc.aegiscloud.id
  cidr_block        = "10.42.10.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = {
    Name    = "aegiscloud-security-tools"
    Tier    = "security-tools"
    Project = "aegiscloud"
  }
}

resource "aws_subnet" "workloads" {
  count             = 2
  vpc_id            = aws_vpc.aegiscloud.id
  cidr_block        = "10.42.2${count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Name    = "aegiscloud-workloads-${count.index}"
    Tier    = "workloads"
    Project = "aegiscloud"
  }
}

resource "aws_subnet" "shared_services" {
  vpc_id            = aws_vpc.aegiscloud.id
  cidr_block        = "10.42.30.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = {
    Name    = "aegiscloud-shared-services"
    Tier    = "shared-services"
    Project = "aegiscloud"
  }
}

# ---------------------------------------------------------------------------
# NACLs — this is where the "different accounts" isolation guarantee gets
# reconstructed at the network layer. shared-services (identity infra) is
# only reachable from workloads on 443 (Verified Access needs to reach out
# to IAM Identity Center's SAML endpoints); security-tools can reach into
# workloads (remediation Lambdas act on workloads resources) but not the
# reverse.
# ---------------------------------------------------------------------------
resource "aws_network_acl" "shared_services" {
  vpc_id     = aws_vpc.aegiscloud.id
  subnet_ids = [aws_subnet.shared_services.id]

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.42.20.0/24" # workloads tier only
    from_port  = 443
    to_port    = 443
  }
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.42.21.0/24"
    from_port  = 443
    to_port    = 443
  }
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535 # ephemeral return traffic
  }
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "aegiscloud-shared-services-nacl", Project = "aegiscloud" }
}

resource "aws_network_acl" "security_tools" {
  vpc_id     = aws_vpc.aegiscloud.id
  subnet_ids = [aws_subnet.security_tools.id]

  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = aws_vpc.aegiscloud.cidr_block # remediation Lambdas run VPC-less by
    from_port  = 0                              # default (they call the AWS API, not
    to_port    = 0                              # the VPC), this rule mainly covers
  }                                              # future in-VPC tooling in this tier
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "aegiscloud-security-tools-nacl", Project = "aegiscloud" }
}

# ---------------------------------------------------------------------------
# Outbound-only internet via NAT — no subnet in this design has an inbound
# route from the internet gateway. Access to the demo app is only ever via
# AWS Verified Access (Phase 4), never directly.
# ---------------------------------------------------------------------------
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.aegiscloud.id
  tags   = { Project = "aegiscloud" }
}

resource "aws_subnet" "public_nat" {
  vpc_id                  = aws_vpc.aegiscloud.id
  cidr_block              = "10.42.99.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = { Project = "aegiscloud" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.aegiscloud.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Project = "aegiscloud" }
}

resource "aws_route_table_association" "public_nat" {
  subnet_id      = aws_subnet.public_nat.id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Project = "aegiscloud" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_nat.id
  tags          = { Project = "aegiscloud" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.aegiscloud.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Project = "aegiscloud" }
}

resource "aws_route_table_association" "workloads" {
  count          = 2
  subnet_id      = aws_subnet.workloads[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "shared_services" {
  subnet_id      = aws_subnet.shared_services.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "security_tools" {
  subnet_id      = aws_subnet.security_tools.id
  route_table_id = aws_route_table.private.id
}

# ---------------------------------------------------------------------------
# Demo private app — lives in the workloads tier, no public IP. This is what
# AWS Verified Access fronts in Phase 4.
# ---------------------------------------------------------------------------
resource "aws_security_group" "app" {
  name        = "aegiscloud-app-sg"
  description = "Only allows inbound from within the VPC (Verified Access), nothing from the internet"
  vpc_id      = aws_vpc.aegiscloud.id

  ingress {
    description = "HTTP from within the VPC only"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.aegiscloud.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "aegiscloud" }
}

resource "aws_instance" "demo_app" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.workloads[0].id
  vpc_security_group_ids      = [aws_security_group.app.id]
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required" # IMDSv2 only — enforced again structurally by the
  }                            # permission boundary in Phase 2

  user_data = <<-EOF
    #!/bin/bash
    yum install -y httpd
    echo "<h1>Hello, Zero Trust</h1><p>AWS Verified Access just verified your identity and device posture. Zero VPN, zero public IP, single AWS account.</p>" > /var/www/html/index.html
    systemctl enable httpd
    systemctl start httpd
  EOF

  tags = { Name = "aegiscloud-demo-app", Project = "aegiscloud", Tier = "workloads" }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

output "vpc_id" {
  value = aws_vpc.aegiscloud.id
}
output "workloads_subnet_ids" {
  value = aws_subnet.workloads[*].id
}
output "security_tools_subnet_id" {
  value = aws_subnet.security_tools.id
}
output "shared_services_subnet_id" {
  value = aws_subnet.shared_services.id
}
output "demo_app_security_group_id" {
  value = aws_security_group.app.id
}
output "demo_app_network_interface_id" {
  value = aws_instance.demo_app.primary_network_interface_id
}
output "account_id" {
  value = data.aws_caller_identity.current.account_id
}
