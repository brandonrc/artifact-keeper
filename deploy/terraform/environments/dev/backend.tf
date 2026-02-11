terraform {
  backend "s3" {
    bucket         = "artifact-keeper-terraform-state"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "artifact-keeper-terraform-locks"
    encrypt        = true
  }
}
