# The deployment is the published module: cloudformer/infra/aws//modules/s3keepass on the Terraform Registry,
# which deploys a released s3keepass from PyPI (s3keepass_version, default: the version the module was tested with).
module "s3keepass" {
  source  = "cloudformer/infra/aws//modules/s3keepass"
  version = "0.2.0"
  # source = "../../terraform-aws-infra/modules/s3keepass" # local: the module's working tree, before a release
  # s3keepass_version = "X.Y.Z" # unset: the s3keepass release this module version ships with; set only to deploy another one

  project_name       = var.project_name
  console            = var.console
  function_url_auth  = var.function_url_auth
  http_auth          = var.http_auth
  cloudflare_auth    = var.cloudflare_auth
  bucket             = var.bucket != "" ? var.bucket : null
  keep_versions      = var.keep_versions
  log_retention_days = var.log_retention_days
  force_destroy      = var.force_destroy
  architecture       = var.architecture
  custom_template    = var.custom_template
}
