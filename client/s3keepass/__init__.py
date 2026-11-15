"""s3keepass — KeePass vaults on S3, opened in a web UI served by a Lambda Function URL.

s3keepass.server is the Lambda (the vault API and the web UI); the Terraform module cloudformer/infra/aws//modules/s3keepass
deploys it from this package. The command line (`s3keepass entry get github` …) comes in 0.2.0.
"""

__version__ = "0.1.3"
