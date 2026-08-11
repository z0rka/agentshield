terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Left unconfigured on purpose. A backend block committed with someone else's bucket in it is
  # the fastest way for a reader to write state into an account they do not own. Configure it
  # at init time:
  #
  #   terraform init -backend-config=backend.hcl
  #
  # See README.md for the three lines that file needs.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "agentshield"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
