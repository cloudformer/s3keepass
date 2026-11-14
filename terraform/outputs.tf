output "console_url" {
  description = "Open in a browser (the web UI); sign in with user / password from the variable file"
  value       = module.s3keepass.console_url
}

output "bucket" {
  description = "Where the vaults live: s3://<bucket>/keepass/[<folder>/]<vault>.kdbx"
  value       = module.s3keepass.bucket
}
