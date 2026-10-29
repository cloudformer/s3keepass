# s3keepass — kickoff brief

Read this together with CLAUDE.md. CLAUDE.md is the series template, written for infra-serverless projects (an AWS
service rebuilt behind its standard client); s3keepass is Frank's own password manager, so the differences below
override it where they conflict. Delete this file once its content lives in CLAUDE.md / README.

## What it is (evaluated with Frank on 2026-10-28, in the s3rds session)

A KeePass password vault on S3 with a command line. The vault is one standard **KeePass file (`.kdbx`, KDBX4)**
in a versioned S3 bucket. It is only ever decrypted in memory on Frank's machine; S3 never holds plaintext.
Because it is a standard KeePass file, KeePassXC and mobile KeePass apps open the same file — that covers what a
command line cannot (browser autofill, phone).

```
laptop: s3keepass CLI (AWS profile)
  ├─ download s3://<bucket>/vault.kdbx (encrypted)
  ├─ unlock in memory: master password + key file
  └─ save: re-encrypt, conditional PUT (If-Match ETag, as s3rds does) — two devices never overwrite each other
S3: versioning on — every save is a version; history / restore come from it
```

## Decisions already made

- **Name s3keepass**; pip package = import name = command `s3keepass`. PyPI and github.com/cloudformer/s3keepass
  were free on 2026-10-29. Reserve on PyPI with
  `python3 ~/repo-private/redefine-aws-serverless-workflow/scripts/reserve_pypi.py s3keepass --upload` when Frank decides.
- **Command line in the cobra style** (`s3keepass <resource> <action>`), built with argparse sub-parsers, installed
  by `[project.scripts]` in client/pyproject.toml:
  ```
  s3keepass configure                       # aws_profile, region, bucket, key mode
  s3keepass vault init                      # new vault.kdbx, upload
  s3keepass entry add github                # interactive, never in shell history
  s3keepass entry get github                # to the clipboard, cleared after 30 s (pbcopy / clip / xclip, wl-copy)
  s3keepass entry get github --field username
  s3keepass entry ls [group]
  s3keepass entry edit github · entry rm github
  s3keepass gen 24                          # random password
  s3keepass vault history · vault restore <version>   # S3 versions
  s3keepass vault pull                      # download the encrypted file, open it in KeePassXC
  ```
- **Dependencies: pykeepass + boto3.** KDBX4 needs AES / ChaCha20 and Argon2; cryptography is never written by
  hand, so the "standard library only" rule does not apply here.
- **Key modes, both supported, default A:**

  | | A: key file local (default) | B: key file in AWS |
  |---|---|---|
  | unlock | master password + `~/.s3keepass/vault.keyx` | master password + key file kept in Parameter Store `SecureString` (KMS), read with IAM |
  | can AWS see passwords | no — S3 holds ciphertext only | an account admin could get the key file, still not the master password |
  | new machine | copy the key file | configure the AWS profile |
  | cost | S3 storage only | `aws/ssm` key free; a customer KMS key $1 / month |

## Infrastructure (Terraform, `terraform -chdir=terraform …`)

- S3 bucket: versioning on, block all public access, SSE (S3-managed or KMS), a lifecycle rule for old versions
  (keep N or N days — ask Frank), deny non-TLS.
- Mode B only: the SSM parameter and, optionally, a customer KMS key.
- IAM: a policy for the CLI's user / role, least privilege on this bucket (and the parameter in mode B).
- The template's `src/server/` Lambda console: **open question for Frank** — no Lambda is needed for the CLI.
  Ask whether he wants a web page at all (it would need to unlock the vault in the browser or on the server; the
  latter breaks "plaintext only on the laptop"). Default: no Lambda in 0.1.0.
- Frank's var file name: ask him (for s3rds it is `real-srds.json`; never assume `my.json`).

## Testing (the project's own method, CLAUDE.md principle 5)

The reference is **KeePassXC's own `keepassxc-cli`, in Docker**: every file s3keepass writes must open in
keepassxc-cli with the same entries, and every file keepassxc-cli creates must open in s3keepass. "KeePass
compatible" is then a tested result. Plus moto (or the fake S3 pattern from s3rds tests/conftest.py) for the S3
side: conditional PUT conflicts, versions, restore. REPORT.md / TASKS.md as in the template.

## Open questions to settle with Frank before building

1. Series or personal tool? (2026-10-28: proposed as a personal tool, outside SERIES.md — not confirmed.)
2. Default mode A — confirm. Mode B in 0.1.0 or later?
3. Lambda / web page: none in 0.1.0? (see above)
4. Several vaults (personal / team) = several S3 keys in one bucket, like s3rds' one key = one database?

## Working rules (from CLAUDE.md, repeated because they matter most)

- Discuss first; build only after "开始 / 建吧 / 可以了". Frank runs every command; give commands with absolute
  paths (`git -C /Users/frankzhang/repo-private/s3keepass …`, `terraform -chdir=/Users/frankzhang/repo-private/s3keepass/terraform …`).
- English everywhere except README.zh.md. Answer Frank in Chinese, short, conclusions first.
