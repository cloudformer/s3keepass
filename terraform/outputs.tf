output "console_url" {
  description = "Open in a browser (the web UI); sign in with user / password from the variable file"
  value       = aws_lambda_function_url.server.function_url
}

output "bucket" {
  description = "Where the vaults live: s3://<bucket>/keepass/<vault>.kdbx"
  value       = aws_s3_bucket.vaults.bucket
}
