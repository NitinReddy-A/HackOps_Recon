# Intentionally-insecure Terraform fixture for Rampart's IaC scanner tests.
# DO NOT deploy. Every resource here is a deliberate misconfiguration.

resource "aws_s3_bucket" "public_data" {
  bucket = "rampart-demo-public-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket" "unencrypted" {
  bucket    = "rampart-demo-data-bucket"
  encrypted = false
}

resource "aws_security_group" "wide_open" {
  name        = "rampart-demo-open-sg"
  description = "allows the whole internet in"

  ingress {
    description = "ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin_wildcard" {
  name = "rampart-demo-admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
