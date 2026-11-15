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
  description = "Environment label (tags)"
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
      NONE    = public URL; the Lambda checks http_auth / cloudflare_auth                    <- default
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

# sign-in: any method that is on lets a request in; at least one must be on (the module checks the fields)
variable "http_auth" {
  description = "User + password (HTTP Basic): { enabled, username, password (16+) }"
  type = object({
    enabled  = bool
    username = optional(string, "")
    password = optional(string, "")
  })
  default   = { enabled = false }
  sensitive = true
}

variable "cloudflare_auth" {
  description = "Cloudflare Access in front of the URL: { enabled, team (<team>.cloudflareaccess.com), aud (the Access application's AUD tag) }"
  type = object({
    enabled = bool
    team    = optional(string, "")
    aud     = optional(string, "")
  })
  default = { enabled = false }
}

# ---- the vaults' bucket ----
variable "bucket" {
  description = "S3 bucket for the vaults; \"\" = the module's <project_name>-vaults-<account id>"
  type        = string
  default     = ""
}

variable "keep_versions" {
  description = "Older versions kept per vault (every save is one); older ones are deleted after a day"
  type        = number
  default     = 5

  validation {
    condition     = var.keep_versions >= 1 && var.keep_versions <= 100
    error_message = "keep_versions must be 1..100 (the S3 lifecycle limit for newer noncurrent versions)."
  }
}

variable "log_retention_days" {
  description = "Days an access record (log/, one object per read / save / unlock) is kept"
  type        = number
  default     = 90
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

# ---- advanced: the new-vault template ----
variable "custom_template" {
  description = "Overrides of the package's base_template.json, field by field (kdf too), e.g. {\"kdf\": {\"unlock_ms\": 3000}, \"recycle_bin\": true}; null = the base as is. The module checks the fields."
  type        = any
  default     = null
}
