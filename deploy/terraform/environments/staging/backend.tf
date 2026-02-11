terraform {
  backend "s3" {
    bucket         = "artifact-keeper-terraform-state"
    key            = "staging/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "artifact-keeper-terraform-locks"
    encrypt        = true
  }
}
