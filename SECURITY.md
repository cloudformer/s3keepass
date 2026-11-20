# Security

s3keepass keeps your KeePass vaults in your own S3 bucket and decrypts them only in your browser. This page says
what that protects, what it does not, and how to report a problem.

## What each part sees

| | Sees | Never sees |
|---|---|---|
| **Your browser** | the master password (and key file), the decrypted entries, while the tab is unlocked | — |
| **The Lambda** | vault files as KDBX ciphertext; vault names and folders; who signed in (HTTP Basic user or Cloudflare Access email); when each vault was read, saved, created, deleted or reported unlocked | the master password, a key file, any entry |
| **S3** | the same ciphertext, encrypted again at rest (SSE-KMS); the access records under `log/` | the same as the Lambda |
| **AWS / Cloudflare as operators** | what S3, the Lambda and (with Cloudflare Access) the proxy see | the same as the Lambda |

The crypto is not hand-written: the page uses kdbxweb (KeeWeb's KDBX library) and argon2-browser (the Argon2
reference code as WASM), vendored and pinned by hash ([vendor/](client/s3keepass/server/vendor/README.md)). New
vaults are KDBX 4, AES-256, Argon2id.

## What protects what

- **Confidentiality of the entries**: only the master key decrypts a vault; it is typed (or picked, for a key file)
  in the browser and never sent. A stolen bucket, a leaked backup or a read of the Lambda's logs is ciphertext.
- **The page itself**: a strict Content-Security-Policy runs only this page's scripts (inline ones by hash) and
  the pinned `/vendor` files; no third-party script, font or request. Text in a vault is never run as code.
- **No lost update**: a save must name the version it opened (`If-Match`); a save over a newer version is
  refused, never written.
- **Sign-in in front of the API**: HTTP Basic, Cloudflare Access (a signed JWT, checked against the team's keys),
  or both. Neither on, or one on without its settings, refuses every request.
- **History**: the bucket is versioned; a bad save or a delete is undone from the Versions dialog.

## What it does not protect against

- **A compromised device or browser**: malware, a malicious browser extension or a keylogger sees what you type
  and what the unlocked tab shows. The same is true of any password manager.
- **A changed server**: the page comes from your Lambda. Whoever can change that Lambda's code (your AWS
  account, or a package you deploy) can serve a page that sends the master password away. Deploy released versions
  from PyPI, pin the version, and keep the AWS account itself protected (MFA, few administrators).
- **A weak master password**: Argon2id makes each guess slow, not impossible. Use a long passphrase, or a key file.
- **Metadata**: vault names, folder names, sizes and the access records are not encrypted.
- **Availability during an AWS or network outage**: download the `.kdbx` and open it in a local KeePass app
  ([which apps and versions](https://cloudformer.github.io/s3keepass/compat.html)).

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
[cloudformer/s3keepass](https://github.com/cloudformer/s3keepass/security/advisories/new). Do not open a public
issue for a security problem. You will get an answer, and a fix is released on PyPI as a new patch version, noted
in the [changelog](CHANGELOG.md).

Supported: the latest release on PyPI.
