# Changelog

## Unreleased

- Sign-in method is a setting, `AUTH_METHOD`: `web` (HTTP Basic, as before) or `cloudflare` (reserved: refused
  with 503 until it is built, never left open). `GET /api/me` returns who is signed in; the identity (the Basic
  user for now) is what owner and access records will use.
- Folders: vaults are `vaults/<folder>/<name>.kdbx`, `<folder>` = `shared` or a person's identity (their personal
  folder). `GET /api/tree` lists the folders (mine, shared, everyone else's) and their files;
  `/api/files/<folder>/<name>` opens / saves / deletes any of them; `/api/vaults/<name>` is the same in my own
  folder. Paths are built in one place and refuse `..`, hidden names, nesting and anything outside `vaults/`.
  Existing vaults move once from `keepass/` to `vaults/<user>/`.

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
