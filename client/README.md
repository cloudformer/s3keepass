# s3keepass

**KeePass vaults (`.kdbx`) on your own S3, opened in a web UI served by a Lambda Function URL — decrypted only in
your browser, ≈ $0 when idle, and KeePassXC still opens the same file.** Part of
[Redefine AWS Serverless](https://github.com/topics/redefine-aws-serverless).

![s3keepass architecture](https://raw.githubusercontent.com/cloudformer/s3keepass/main/docs/architecture.svg)

0.1.0 is the service: deploy it once from the [main repository](https://github.com/cloudformer/s3keepass#quick-start)
(Terraform) and open the URL. This package holds the version only; the command line
(`pip install s3keepass`, then `s3keepass entry get github` …) comes in 0.2.0.

Compatibility with KeePassXC: [REPORT.md](https://github.com/cloudformer/s3keepass/blob/main/tests/compat/REPORT.md).
