# s3keepass — kickoff brief

Read this together with CLAUDE.md. CLAUDE.md is the series template, written for infra-serverless projects (an AWS
service rebuilt behind its standard client); s3keepass is **app-serverless** (KeePass — a desktop app and its
file — as a serverless web vault), so the differences below override CLAUDE.md where they conflict. Delete this
file once its content lives in CLAUDE.md / README.

## What it is

KeePass vaults on S3, opened in a **web UI** served by a Lambda Function URL, ≈ $0 when idle. Each vault is one
standard **KeePass file (`.kdbx`, KDBX4)**, so KeePassXC and mobile KeePass apps can still open the same file
(download it from the UI). Part of the series (Frank, 2026-10-29), and Frank's own daily password manager.

```
browser: s3keepass web UI (HTTP Basic, like s3rds' console)
  └─ Function URL → Lambda
        ├─ list  s3://<bucket>/keepass/*.kdbx          (the "folder")
        ├─ get   s3://<bucket>/keepass/<vault>.kdbx    (encrypted bytes)
        └─ put   … with If-Match ETag                  (two tabs / devices never overwrite each other)
S3: one bucket, prefix keepass/, any number of vaults; versioning on; SSE-KMS at rest
```

## Decisions (Frank, 2026-10-29)

- **In the series**, app-serverless (next to lambdavault and lambdachecks). Name s3keepass = pip package = import
  name; PyPI and github.com/cloudformer/s3keepass were free on 2026-10-29 (reserve with
  `python3 ~/repo-private/redefine-aws-serverless-workflow/scripts/reserve_pypi.py s3keepass --upload` when Frank says).
- **Many vaults, no limit**: one bucket, `keepass/<name>.kdbx` (库1, 库2, 库3 …). The UI lists them like a folder
  and opens one — the same idea as s3rds' console choosing a database (one S3 key = one database there, one S3
  key = one vault here).
- **The web UI is required in 0.1.0** and must feel like opening a folder on the desktop — convenient and
  professional (model: KeePassXC's window): vault list → unlock with the master password → group tree on the
  left, entries on the right → entry details; copy username / password (clipboard cleared after 30 s), reveal,
  add / edit / delete entries and groups, password generator, create a new vault, download the `.kdbx`,
  upload an existing `.kdbx`, lock (also on idle). One `index.html`, no build step, as CLAUDE.md principle 6.
- **No key file in 0.1.0**: a vault is unlocked by its master password only. Encryption at rest beyond KDBX's
  own is S3 server-side encryption with KMS (SSE-KMS on the bucket, AWS-managed key `aws/s3`).

## Settled with Frank (2026-10-29)

**Goal of 0.1.0: it replaces Frank's local KeePass client and where the file is kept.** He opens the URL instead
of KeePassXC, and the vaults live in S3 instead of on his disk.

1. **A vault is decrypted in the browser.** The Lambda only lists / reads / writes encrypted bytes; the master
   password and plaintext never leave the browser (as KeeWeb does). KDBX4 in JavaScript (Argon2 + ChaCha20 /
   AES): vendor a vetted library (kdbxweb, MIT, used by KeeWeb, plus an Argon2 WASM build) next to / inline in
   index.html — never hand-written crypto. Pin and record the vendored versions.
2. **UI login: HTTP Basic**, user name and password from the Terraform variable file, as s3rds' console. The var
   file is named after the project: **`terraform/s3keepass.json`** (gitignored; `example.json` committed) —
   `terraform -chdir=/Users/frankzhang/repo-private/s3keepass/terraform apply -var-file=s3keepass.json`.
3. **SSE-KMS with the AWS-managed key `aws/s3`** (free). A customer key may come later.
4. **Command line in 0.2.0** (`s3keepass entry get github` …, designed 2026-10-28). 0.1.0 is the web UI only.

## 0.1.0 deliverables

1. Terraform (`terraform -chdir=terraform …`): S3 bucket (versioning, block public access, SSE-KMS, deny
   non-TLS, lifecycle for old versions — ask how many to keep), Lambda + Function URL, IAM least privilege
   (s3:ListBucket on `keepass/`, Get / Put on `keepass/*`). Variables: UI user / password (sensitive), bucket
   name, region, architecture; the var file is `terraform/s3keepass.json`.
2. `src/server/`: the Lambda (list / get / conditional put / delete / versions of `keepass/*.kdbx`, HTTP Basic)
   and `index.html` (the UI above).
3. README / README.zh.md: architecture image on top, then the "switch" table (left: KeePassXC + a synced file /
   a hosted password manager; right: s3keepass — open the URL), then "the server: deploy once, ≈ $0 when idle".
4. SERIES.md row (app-serverless) is already added in the template repo.

## Testing (the project's own method, CLAUDE.md principle 5)

The reference is **KeePassXC's `keepassxc-cli`, in Docker**: every file s3keepass writes must open in
keepassxc-cli with the same groups and entries, and every file keepassxc-cli creates must open in s3keepass
(drive the UI's crypto path headlessly, or the same library from Node in the test). Plus the fake S3 pattern from
s3rds tests/conftest.py for the server: listing, conditional PUT conflicts, versions. REPORT.md / TASKS.md as in
the template.

## Acceptance of 0.1.0 (Frank runs every command)

1. `terraform apply` → the UI opens at the Function URL (Basic auth).
2. Create vault 库1, add entries in groups, lock, reopen → same content. Create 库2: both listed.
3. Download 库1.kdbx → KeePassXC opens it with the master password. Upload a KeePassXC-made `.kdbx` → it opens
   in the UI.
4. Two tabs edit the same vault → the second save is refused (ETag), never silently overwritten.
5. S3 console: `keepass/` holds only `.kdbx` ciphertext, SSE-KMS shown on each object.

## Working rules (from CLAUDE.md, repeated because they matter most)

- Discuss first; build only after "开始 / 建吧 / 可以了". Frank runs every command; give commands with absolute
  paths (`git -C /Users/frankzhang/repo-private/s3keepass …`, `terraform -chdir=/Users/frankzhang/repo-private/s3keepass/terraform …`).
- English everywhere except README.zh.md. Answer Frank in Chinese, short, conclusions first.
