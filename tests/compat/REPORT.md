# s3keepass compatibility report · [tasks](TASKS.md)

Generated 2026-10-29 by `pytest tests` · s3keepass 0.1.0 · Python 3.9.6

Each row is one feature exercised the same way on the reference and on the project; results, types and errors must match. The feature list only grows (a removed case would show in git), so the support percentage can only move up.

Whole test run: **47 passed**, 0 failed, 0 expected failures (known gaps), 0 skipped — regression suite (`tests/`) and compatibility suite (`tests/compat/`) together.

Open tasks: none — see [TASKS.md](TASKS.md).

## Test scope

What each business step is checked by. ✅ every listed test passed · 🔴 one failed · ⏭ some not run (filtered, or an Airflow outcome not recorded yet) · ⏳ still to do.

| Business step | How it is tested | Tests | Status |
|---|---|---|---|
| 1. terraform apply → the UI opens at the Function URL (Basic auth) | in-process Lambda | `test_ui_and_vendor_are_public_and_the_api_needs_auth`<br>`test_csp_runs_only_this_pages_scripts` | ✅ 2/2 · ⏳ Frank: terraform apply, open the URL |
| 2. Create 库1, groups and entries, lock, reopen; 库2 listed too | in-process Lambda + the UI's vault code vs keepassxc-cli | `test_create_list_and_open_vaults`<br>`test_vault_created_in_s3keepass_opens_in_keepassxc` | ✅ 2/2 · ⏳ Frank: in the browser |
| 3. Download 库1 → KeePassXC opens it; a KeePassXC .kdbx opens in the UI | keepassxc-cli in Docker | `test_vault_created_in_s3keepass_opens_in_keepassxc`<br>`test_vault_created_in_keepassxc_opens_in_s3keepass`<br>`test_edits_in_s3keepass_are_seen_by_keepassxc`<br>`test_edits_in_keepassxc_are_seen_by_s3keepass` | ✅ 4/4 · ⏳ Frank: with the desktop KeePassXC |
| 4. Two tabs edit the same vault → the second save is refused | in-process Lambda, fake S3 (If-Match) | `test_stale_save_is_refused_never_overwritten`<br>`test_unconditional_save_is_refused` | ✅ 2/2 · ⏳ Frank: two tabs on the deployed URL |
| 5. keepass/ holds only .kdbx ciphertext, SSE-KMS on each object | in-process Lambda, fake S3 | `test_saves_are_sse_kms_ciphertext` | ✅ 1/1 · ⏳ Frank: S3 console |

## s3keepass vault files vs KeePassXC (lambda_handler in-process) — reference: KeePassXC 2.7.9 (keepassxc-cli, Docker)

**Support 100%** (14 / 14 features) · 14 verified

✅ verified · ❌ gap — known difference, the note names the task that closes it · ⚪ quirk — documented, deliberately not aligned · ⛔ unsupported by design, refused with NotSupportedError · 🟡 fixed — xfail marker to remove · 🔴 regression · ⏭ not run

| Feature | Status | Note |
|---|---|---|
| **Data** | | |
| a vault KeePassXC creates opens in s3keepass | ✅ | KeePassXC's defaults (Argon2d, 1 s key derivation) |
| a vault s3keepass creates opens in KeePassXC with the same groups and entries | ✅ | nested groups, Unicode, multi-line notes, tags, protected attributes |
| add / edit / delete / rename in s3keepass, read by KeePassXC | ✅ | on a KeePassXC-made file; an edit keeps the previous version in the entry's history; delete = recycle bin |
| add / edit / delete in KeePassXC, read by s3keepass | ✅ | on an s3keepass-made file |
| any file as the key file (a photo, an .svg …) | ✅ | counted by its SHA-256 on both sides, as KeePassXC does |
| any file as the key file (a photo, an .svg …) | ✅ | counted by its SHA-256 on both sides, as KeePassXC does |
| attachments added in KeePassXC survive an edit in s3keepass | ✅ | the UI shows them, KeePassXC opens them |
| change the master key: add a key file in s3keepass, remove it again; add one in KeePassXC | ✅ | each change seen by the other side |
| change the master password in s3keepass | ✅ | KeePassXC opens the file with the new one only |
| delete a group in s3keepass | ✅ | KeePassXC finds it, with its entries, in the recycle bin |
| password + key file: a KeePassXC vault opens in s3keepass | ✅ | the .keyx KeePassXC generates; without it, refused |
| password + key file: an s3keepass vault opens in KeePassXC | ✅ | the .keyx the UI's "New" button makes; without it, refused |
| **Errors** | | |
| a wrong master password opens nothing | ✅ | on both sides, for files from either side |
| **Metadata** | | |
| new vaults: KDBX 4, AES-256, Argon2id 64 MiB x 8 | ✅ | KeePassXC's defaults with Argon2id instead of Argon2d |
