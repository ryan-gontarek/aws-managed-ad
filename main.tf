terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.35.0"
    }
  }
  required_version = ">= v1.3.3"
}

provider "aws" {
  region  = "us-east-1"
}

locals {
  name = "<random string>"
}

module "vpc" {
  source          = "terraform-aws-modules/vpc/aws"
  name            = local.name
  cidr            = "10.0.0.0/16"
  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Terraform = "true"
  }
}

data "http" "my_ip" {
  url = "http://ipv4.icanhazip.com"
}

module "security_group_windows_machine" {
  source      = "terraform-aws-modules/security-group/aws"
  name        = "${local.name}-1"
  description = "for windows machine that will domain join with ad group"
  vpc_id      = module.vpc.vpc_id
  ingress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = "all"
      description = "managed-ad"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
    {
      from_port   = 3389
      to_port     = 3389
      protocol    = "tcp"
      description = "my computer connection to ec2"
      cidr_blocks = "${chomp(data.http.my_ip.body)}/32"
    },
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = "all"
      description = "managed-ad"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
}

# role for windows machine
module "iam_role_windows_machine" {
  source                  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  role_name               = "${local.name}-1"
  create_role             = true
  role_requires_mfa       = false
  create_instance_profile = true
  trusted_role_services = [
    "ec2.amazonaws.com"
  ]
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/AmazonSSMDirectoryServiceAccess"
  ]
}

# role for mssql database
module "iam_role_mssql" {
  source                  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  role_name               = "${local.name}-2"
  create_role             = true
  role_requires_mfa       = false
  create_instance_profile = true
  trusted_role_services = [
    "rds.amazonaws.com"
  ]
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonRDSDirectoryServiceAccess"
  ]
}


# costly resources
resource "aws_directory_service_directory" "main" {
  name                                 = "corp.${local.name}.com"
  password                             = "<managed ad password>"
  edition                              = "Standard"
  type                                 = "MicrosoftAD"
  desired_number_of_domain_controllers = 2
  vpc_settings {
    vpc_id     = module.vpc.vpc_id
    subnet_ids = [module.vpc.public_subnets[0], module.vpc.public_subnets[1]]
  }
}

module "windows_machine" {
  source                 = "terraform-aws-modules/ec2-instance/aws"
  version                = "~> 3.0"
  name                   = "aws-managed-ad"
  ami                    = "ami-050d0a1abe93f4773" # Microsoft Windows Server 2019 Base
  instance_type          = "t2.micro"
  key_name               = "<key name>"
  vpc_security_group_ids = [module.security_group_windows_machine.security_group_id]
  subnet_id              = module.vpc.public_subnets[0]
  iam_instance_profile   = module.iam_role_windows_machine.iam_instance_profile_id
  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

# domain join instance to active directory
resource "aws_ssm_document" "domain_join" {
  name          = "ssm_document_example.com"
  document_type = "Command"
  content       = <<DOC
{
    "schemaVersion": "1.0",
    "description": "Automatic Domain Join Configuration",
    "runtimeConfig": {
        "aws:domainJoin": {
            "properties": {
                "directoryId": "${aws_directory_service_directory.main.id}",
                "directoryName": "corp.${local.name}.com",
                "dnsIpAddresses": ${jsonencode(aws_directory_service_directory.main.dns_ip_addresses)}
            }
        }
    }
}
DOC
}

resource "aws_ssm_association" "associate_ssm" {
  name        = aws_ssm_document.domain_join.name
  targets {
    key    = "InstanceIds"
    values = [module.windows_machine.id]
  }
}

# 1) login as the ec2 windows admin user and run the following in powershell:
# >> Install-WindowsFeature -Name GPMC,RSAT-AD-PowerShell,RSAT-AD-AdminCenter,RSAT-ADDS-Tools,RSAT-DNS-Server
# 2) login as the directory service admin and access the "Windows Administrative Tools" then click the "Active Directory Users and Computers"
# username: "corp\admin"
# password: "<managed ad password>"

