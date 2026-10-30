data "aws_caller_identity" "me" {}

locals {
  role   = "${var.project_name}-lambda-role"
  prefix = "keepass/" # fixed layout: s3://<bucket>/keepass/<vault>.kdbx
  bucket = var.bucket != "" ? var.bucket : "${var.project_name}-${var.env}-${data.aws_caller_identity.me.account_id}"
}

# ---------------- S3: every vault is one .kdbx under keepass/ in this private bucket ----------------
resource "aws_s3_bucket" "vaults" {
  bucket        = local.bucket
  force_destroy = var.force_destroy # false: destroy stops at a non-empty bucket, so no vault is lost by accident
}

resource "aws_s3_bucket_public_access_block" "vaults" {
  bucket                  = aws_s3_bucket.vaults.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# every save is a new object version: an older vault is one click away in the UI (Versions)
resource "aws_s3_bucket_versioning" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  versioning_configuration {
    status = "Enabled"
  }
}

# at rest: SSE-KMS with the AWS-managed key aws/s3 (free; its key policy lets this account's S3 use it,
# so the Lambda role needs no kms: permission). The vaults are KDBX-encrypted before they get here.
resource "aws_s3_bucket_server_side_encryption_configuration" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "vaults" {
  bucket     = aws_s3_bucket.vaults.id
  depends_on = [aws_s3_bucket_public_access_block.vaults]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.vaults.arn, "${aws_s3_bucket.vaults.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# old versions: keep the newest var.keep_versions per vault (older ones go after a day); clean up the rest
resource "aws_s3_bucket_lifecycle_configuration" "vaults" {
  bucket     = aws_s3_bucket.vaults.id
  depends_on = [aws_s3_bucket_versioning.vaults]
  rule {
    id     = "keep-newest-versions"
    status = "Enabled"
    filter {
      prefix = local.prefix
    }
    noncurrent_version_expiration {
      noncurrent_days           = 1
      newer_noncurrent_versions = var.keep_versions
    }
    expiration {
      expired_object_delete_marker = true
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# ---------------- IAM: one role, least privilege — only keepass/*.kdbx ----------------
resource "aws_iam_role" "lambda" {
  name = local.role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "${local.role}-policy"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.vaults.arn}/${local.prefix}*.kdbx"
      },
      {
        Effect    = "Allow"
        Action    = ["s3:ListBucket", "s3:ListBucketVersions"]
        Resource  = aws_s3_bucket.vaults.arn
        Condition = { StringLike = { "s3:prefix" = ["${local.prefix}*"] } }
      }
    ]
  })
}

# ---------------- the service: one Lambda + Function URL (web UI + API) ----------------
data "archive_file" "server" {
  type        = "zip"
  source_dir  = "${path.module}/../src/server"
  excludes    = ["**/__pycache__/**", "**/.DS_Store"]
  output_path = "${path.module}/.build/server.zip"
}

resource "aws_lambda_function" "server" {
  function_name    = "${var.project_name}-lambda"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  architectures    = [var.architecture]
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.server.output_path
  source_code_hash = data.archive_file.server.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      USER_NAME = var.console_auth_username
      PASSWORD  = var.console_auth_password
      CONSOLE   = var.console ? "1" : "0"
      BUCKET    = aws_s3_bucket.vaults.bucket
    }
  }
}

# function_url_auth = NONE:    public URL, our user/password is the only gate (the vaults stay KDBX-encrypted).
#                              A public URL needs BOTH permission statements (AWS requirement since Oct 2025).
# function_url_auth = AWS_IAM: AWS verifies SigV4 + IAM first; no public permissions are created.
# No CORS: the UI is served by the same URL, and no other site needs to call it.
resource "aws_lambda_function_url" "server" {
  function_name      = aws_lambda_function.server.function_name
  authorization_type = var.function_url_auth
}

resource "aws_lambda_permission" "url" {
  count                  = var.function_url_auth == "NONE" ? 1 : 0
  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.server.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "url_invoke" {
  count                    = var.function_url_auth == "NONE" ? 1 : 0
  statement_id             = "AllowPublicFunctionUrlInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.server.function_name
  principal                = "*"
  invoked_via_function_url = true
}
