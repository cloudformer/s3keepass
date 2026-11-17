# Changelog

## 0.1.10

UI and docs only: **which local KeePass apps open these vaults**. The release at the right end of the status bar
(`s3keepass 0.1.10`) is now a link to [cloudformer.github.io/s3keepass/compat.html](https://cloudformer.github.io/s3keepass/compat.html):
Windows, Mac, iPhone and Android apps, from which version a downloaded `.kdbx` opens and shows the TOTP code
(EN / CN). The table itself is written once, in the "Local KeePass apps" section of this package's README on PyPI;
the page reads it from there, so a change to it is one release of this package.

## 0.1.9

UI only: **TOTP (two-factor codes)**, in place of an authenticator app. Edit an entry, paste the secret key a site
shows when two-factor is set up (or its `otpauth://totp/…` link) into TOTP; the entry then shows the current code
and its seconds left, with a copy button (the clipboard clears after 30 s). Kept as KeePassXC keeps it — the
protected attribute `otp`, an `otpauth://totp/…` URI — so KeePassXC shows the same code (tests/compat). Worked out
in the browser (WebCrypto), never on the server: SHA-1 / SHA-256 / SHA-512, 6–8 digits, any period.

## 0.1.8

UI only:
- **A new icon**: a safe (top bar, browser tab). Unlocking shows it large in the dialog — its wheel turns while
  Argon2 runs, a green ✓ appears when the vault opens, then it shrinks into the top-bar logo, which keeps the ✓
  while the vault is open (the tab's icon too). A wrong master password shakes it once. The moving parts are their
  own layers, so the wheel keeps turning while Argon2 holds the page. Skipped under "reduce motion".
- **Library**: the S3 side's tree is called Library (inside a vault: Groups).
- **Lock** (by hand or after 5 idle minutes) always goes back to the vault's folder, the file still selected.

## 0.1.7

UI only, phones (a computer is unchanged): an unlocked vault opens on its groups (its top level often has no entries
of its own), and one bar stays on screen inside it — ‹ Back (one level up: entry › entries › groups) and 🔒 Lock —
instead of each pane's own Back and a Lock at the far end of the scrolling button row.

## 0.1.6

UI only:
- **Vault files**: at the top level the folders are listed first in the file list (a click opens one), so the list
  is never empty when the vaults live in folders. A selected file's panel puts 🔓 Open first; Versions and Move
  to… sit below its details.
- **Rename folder** (a folder selected, no file): each vault file in it moves to the new name — S3 has no folder
  rename, so one by one through the same move as Move to… (copy, then delete; never over an existing file). If it
  stops half way nothing is lost: rename again to move the rest.
- **Groups**: no 🗑 shortcut next to the group tree (a destructive action is no shortcut). With no entry selected,
  Edit / Move / Delete act on the group shown (Rename group, Move group, Delete group); the details pane shows the
  group (entries, subgroups, Rename, Move, Delete). **Move group** takes it with all its entries and subgroups under
  another group, saved in one write (never into itself or below itself, not into the recycle bin). The vault's top
  level is neither renamed, moved nor deleted. Checked against KeePassXC (tests/compat).
- **Phones**: each pane's head (‹ Back and what it shows) and the list's head stay at the top while it scrolls.

## 0.1.5

UI only: inside an open vault the next step is highlighted too — nothing selected: New entry, New group; an
entry selected: Edit. Entries keep every action (add, edit, move, delete) on a computer and a phone.

## 0.1.4

UI only:
- **Phones** (≤ 640px): one pane at a time, like an app — vault files › file › open vault › entries › entry — with
  ‹ Back and ☰ Folders / ☰ Groups; lists become cards; larger copy / reveal buttons; dialogs open as a bottom sheet;
  16px inputs (no iOS zoom on focus). A computer's three-pane layout is unchanged.
- **Vault-file buttons**: the next step is highlighted — nothing selected: New vault, New folder, Upload .kdbx; a
  file selected: Open. Delete stays visible but disabled: a vault file is deleted in S3, not from the page.

## 0.1.3

UI only: the release running is shown at the right end of the status bar (`s3keepass 0.1.3`), read from the
package itself, so a page tells which version a deployment serves.

## 0.1.2

**Sign-in: HTTP Basic, Cloudflare Access, or both.** Two settings, each on or off; a request passes when any method
that is on accepts it. Deploy with the module `cloudformer/infra/aws//modules/s3keepass` 0.2.0 (`http_auth` /
`cloudflare_auth`).

- `HTTP_AUTH` (default on): HTTP Basic with `USER_NAME` / `PASSWORD`, as before.
- `CLOUDFLARE_AUTH` (default off) with `CLOUDFLARE_TEAM` / `CLOUDFLARE_AUD`: the `Cf-Access-Jwt-Assertion` header
  Cloudflare Access adds, an RS256 JWT checked against the team's public keys (fetched from
  `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`, kept while the Lambda is warm, fetched again for an
  unknown key at most once a minute), its `aud`, issuer and expiry. The identity — owner and access records — is
  the email in it. Pure Python, no new dependency.
- With Cloudflare alone the page and `/vendor` need the JWT too, so the Function URL opened directly shows nothing.
- Fails closed: both off, HTTP Basic on without a user and password (it used to mean no sign-in at all), or
  Cloudflare on without a team and aud — every request is 503 with what to fix.
- `AUTH_METHOD` is gone; `GET /api/me` returns `auth_method` `http` or `cloudflare` (how this request signed in).
- UI: requests go out without a password first, so through Cloudflare the page opens signed in; the password
  dialog comes only on a 401 while HTTP Basic is on. Sign out through Cloudflare goes to its own logout.

## 0.1.1

**The Lambda ships in the pip package.** `src/server/` moved to `client/s3keepass/server/` (handler
`s3keepass.server.lambda_function.lambda_handler`), so the Terraform module `cloudformer/infra/aws//modules/s3keepass`
deploys a release from PyPI.

- **New-vault template in two layers.** `base_template.json` (in the package: Argon2id 128 MiB × 2 lanes tuned to
  ≥ 2 s, AES-256, no entry history, no recycle bin) is what every deployment starts from; a deployment's
  `custom_template` (the module variable, stored as `config/custom_template.json`) overrides it field by field,
  `kdf` one level down. `GET /api/template` serves the merged result and says which (`base` or
  `base+s3:config/custom_template.json`). `config/template.json` is no longer read.
- UI: the folder tree lists the vault files in each folder (folders fold); inside an unlocked vault the bar turns
  amber with "🔓 Inside <file>", and the folders on the left only show where the file is (Lock to leave) — the
  open file is marked "Opened" instead of a second Close button.
- UI default KDF (no template) = the base template: 128 MiB, ≥ 2 s.


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

- New vaults resist brute force by time, not by a fixed setting: Argon2id 128 MiB (was 64), and the number of
  passes is tuned on the device that creates the vault so that opening it takes at least 1.5 s (was a fixed 8).
  KeePassXC tunes the same way and opens these files unchanged.

- Changing the master key asks for the current one first (password, and key file if the vault uses one): an
  unlocked tab left alone cannot have its master key replaced. Checked by comparing key hashes, no extra Argon2 run.
- Bigger copy / reveal buttons next to user name, password and the other fields. The password generator opens at
  20 characters every time.

- Move entries between groups: tick them (or select one), Move to…, pick the group. KeePassXC reads the moved
  entries in their new group, unchanged (compatibility test).

- `GET /api/template`: what a new vault starts with (Argon2id memory, parallelism, minimum unlock time; groups;
  extra fields; entry history kept; recycle bin). It is `terraform/template.json` in the repository; terraform
  apply uploads it to `config/template.json` in the bucket. Applied when a vault is created (task 8).
- Both screens keep their actions on the list head (files: New vault, Upload, New folder, Open, Versions, Delete;
  entries: New entry, New group, Edit, Move to…, Delete); the top bar has only what concerns the whole page.

- Move vault files between folders, like entries between groups: tick them (or select one), Move to…, pick
  the folder. `POST /api/move`: S3 has no rename, so the copy is written first (never over an existing file),
  then the original deleted; the owner moves along, older versions stay under the old name.

- New vaults follow the template (task 8): its Argon2id memory, parallelism and minimum unlock time; its groups;
  its extra fields (every new entry starts with them, empty); its entry history (0 = none kept); recycle bin off =
  a delete is final, and the UI says so. KeePassXC reads such a vault the same way (compatibility test).

- Every unlock is recorded (task 9): the page reports success / failure (path and true / false only) right after
  it tries; the file list's "Last unlock" and the access records show it.
- 🧹 Clean up (task 10): empties every entry's history and the recycle bin, then saves — the file shrinks. Opening a
  vault whose own settings differ from the template (history kept, recycle bin) shows a notice with "Apply the
  template"; a vault over 3 MB shows how close it is to the 4.5 MB limit.
- At rest the bucket uses SSE-S3 (task 11, was SSE-KMS with aws/s3): no KMS in the path; files written before stay
  readable and change on their next save. The vaults are KDBX-encrypted either way.

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
