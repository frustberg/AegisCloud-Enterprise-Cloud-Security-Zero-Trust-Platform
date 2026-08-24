terraform {
  backend "s3" {
    bucket         = "aegiscloud-terraform-state-600294641908"
    key            = "security/sns-alerts/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "terraform-lock"
    encrypt        = true
  }
}