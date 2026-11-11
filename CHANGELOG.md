# Changelog

## Unreleased

- Sign-in method is a setting, `AUTH_METHOD`: `web` (HTTP Basic, as before) or `cloudflare` (reserved: refused
  with 503 until it is built, never left open). `GET /api/me` returns who is signed in; the identity (the Basic
  user for now) is what owner and access records will use.
- Folders under the same `keepass/` prefix, nothing moves: `keepass/<name>.kdbx` (the top level, every vault so
  far) or `keepass/<folder>/<name>.kdbx`. Folders are names for people to sort by — no rules, no permissions.
  `GET /api/tree` lists them and their files; `/api/files/<folder>/<name>` opens / saves / deletes a vault in a sub-folder, `/api/vaults/<name>` in the
  main folder as before. Paths are built in one place and refuse `..`, hidden names, deeper nesting and anything
  outside `keepass/`.
- Owner: who created a vault (the web user; with Cloudflare, the email) is kept in the file's S3 metadata
  (`x-amz-meta-owner`); later saves by anyone keep it. `/api/tree` shows it.
- Access records in the same bucket: every read, save, create, delete and unlock is one small JSON object under
  `log/<vault key>/` (write-only, so writers never collide) plus one JSON line in CloudWatch; a failed record never
  blocks the vault. The unlock result is reported by the browser (`POST /api/audit/unlock`, path and true / false
  only) — a file fetched around the page does not show up. `GET /api/audit?path=&limit=` lists a vault's records,
  newest first; `/api/tree` shows each vault's last unlock. `log_retention_days` (default 90) expires them.
- A save that lost the race is now 409 (was 412); nothing is overwritten. Upload into a folder
  (`?action=upload`, `If-None-Match: *`) never replaces an existing file (412). A vault is at most 4.5 MB (was 5):
  a Function URL request is 6 MB with base64; the error says how much was sent and what to clean up.
- One layout for both screens: vault files (S3) are folders | files | file, an open vault (KeePass) is
  groups | entries | entry. The file page shows each file's owner, size, modified time and last unlock, and its
  access records; New vault / Upload / Open / Versions / Delete live once, in the toolbar. An open vault shows its
  S3 file (folder / name.kdbx) above its groups; 📁 is an S3 folder, 🗂 a KeePass group. Sign out only on the
  file page. No download buttons (the conflict "download my copy" stays: it never leaves the browser).

## 0.1.0 — 2026-10-29

First release: the web UI replaces a local KeePass client.

- Vaults are standard KDBX 4 files in `s3://<bucket>/keepass/<name>.kdbx`, any number of them.
- Web UI (one `index.html`, served by the Lambda): vault list, unlock with the master password, group tree,
  entries, details; copy (clipboard cleared after 30 s), reveal, add / edit / delete entries and groups (recycle
  bin), additional attributes, password generator, change the master key, new vault, upload / download
  `.kdbx`, versions (download / restore), lock on demand and after 5 minutes idle.
- Master key = password + optional key file, as in KeePass: KeePassXC `.keyx` / `.key`, a generated `.keyx`, or any
  file (by its SHA-256). Read in the browser for each unlock, never uploaded.
- Decryption only in the browser: vendored kdbxweb 2.1.1 + argon2-browser 1.18.0, pinned by SHA-256. New vaults:
  AES-256, Argon2id 64 MiB x 8.
- Saves are conditional (`If-Match` ETag): a second tab or device is refused, never overwritten.
- Terraform: private, TLS-only, versioned bucket with SSE-KMS (`aws/s3`) and a lifecycle for old versions; one
  Lambda + Function URL behind HTTP Basic; least-privilege IAM on `keepass/*.kdbx`.
- Tests: the API against a fake S3; the vault files against KeePassXC's keepassxc-cli in Docker.
