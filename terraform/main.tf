# The deployment is the published module: cloudformer/infra/aws//modules/s3keepass on the Terraform Registry,
# which deploys a released s3keepass from PyPI (s3keepass_version, default: the version the module was tested with).
module "s3keepass" {
  source  = "cloudformer/infra/aws//modules/s3keepass"
  version = "0.1.3"
  # source = "../../terraform-aws-infra/modules/s3keepass" # local: the module's working tree, before a release

  # module 0.1.3 deploys s3keepass 0.1.1 by default; uncomment and set a newer release to deploy it before the module moves
  # s3keepass_version = "0.1.1"

  project_name          = var.project_name
  console               = var.console
  function_url_auth     = var.function_url_auth
  console_auth_username = var.console_auth_username
  console_auth_password = var.console_auth_password
  bucket                = var.bucket != "" ? var.bucket : null
  keep_versions         = var.keep_versions
  log_retention_days    = var.log_retention_days
  force_destroy         = var.force_destroy
  architecture          = var.architecture
  custom_template       = var.custom_template
}
