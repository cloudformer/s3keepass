# ---- deploy credentials ----
variable "region" {
  type    = string
  default = "us-east-2"
}

variable "aws_profile" {
  description = "Local AWS CLI profile to use; \"\" = default credential chain"
  type        = string
  default     = ""
}

variable "assume_role_arn" {
  description = "Deploy role to assume; \"\" = none. Pick this OR aws_profile."
  type        = string
  default     = ""

  validation {
    condition     = !(var.assume_role_arn != "" && var.aws_profile != "")
    error_message = "Set either aws_profile or assume_role_arn, not both."
  }
}

# ---- app ----
variable "env" {
  description = "Environment label (tags, resource names)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name; resources are <project_name>-lambda, <project_name>-lambda-role"
  type        = string
  default     = "s3keepass"
}

# ---- the Function URL: web UI, gate, login (each vault also has its own master password) ----
variable "console" {
  description = "Serve the web UI at GET /. false = API only (the UI is how vaults are opened in 0.1.0)."
  type        = bool
  default     = true
}

variable "function_url_auth" {
  description = <<-EOT
    How the Function URL is protected:
      NONE    = public URL; only console_auth_username/password (HTTP Basic) is checked      <- default
      AWS_IAM = AWS checks a SigV4 signature + IAM permission first. The browser UI
                cannot sign requests, so it is unusable in this mode.
  EOT
  type        = string
  default     = "NONE"

  validation {
    condition     = contains(["NONE", "AWS_IAM"], var.function_url_auth)
    error_message = "function_url_auth must be NONE or AWS_IAM."
  }
}

variable "console_auth_username" {
  description = "HTTP Basic user: web UI login AND every API client; still required with console = false"
  type        = string
}

variable "console_auth_password" {
  description = "HTTP Basic password: web UI login AND every API client"
  type        = string
  sensitive   = true
}

# ---- the vaults' bucket ----
variable "bucket" {
  description = "S3 bucket for the vaults; \"\" = <project_name>-<env>-<account id>"
  type        = string
  default     = ""
}

variable "keep_versions" {
  description = "Older versions kept per vault (every save is one); older ones are deleted after a day"
  type        = number
  default     = 100

  validation {
    condition     = var.keep_versions >= 1 && var.keep_versions <= 100
    error_message = "keep_versions must be 1..100 (the S3 lifecycle limit for newer noncurrent versions)."
  }
}

variable "force_destroy" {
  description = "true lets `terraform destroy` delete the bucket with every vault and version in it"
  type        = bool
  default     = false
}

variable "architecture" {
  description = "The architecture this deployment runs: arm64 (Graviton, ~20% cheaper) or x86_64; both are built and tested"
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be arm64 or x86_64."
  }
}
