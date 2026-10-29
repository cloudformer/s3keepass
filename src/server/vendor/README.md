# Vendored libraries

The browser decrypts and encrypts the vaults with these two files, served by the Lambda next to
`index.html` (`GET /vendor/<file>`). Never hand-written crypto; never edited by hand. To upgrade: download
the new npm tarball, check its `dist.integrity` against `npm view <package>@<version> dist.integrity`,
copy the file from `dist/`, update this table. `tests/test_server.py` checks the SHA-256 column, and the
compatibility suite (keepassxc-cli) must pass again.

| file | package | from | SHA-256 of the file | npm tarball integrity |
|---|---|---|---|---|
| kdbxweb.min.js | kdbxweb 2.1.1 (MIT, KeeWeb's KDBX library) | `dist/kdbxweb.min.js` | `d11e4d4f5316adcaadb349dad6df568e7a861faf0582bcc948a40efb21a41f98` | `sha512-z+a2+BEzyK2kUh0xDekY7gwc9CkbzSetUyvc78NKVawxV06UG1KYbg9W9hZCJdQPYizIVePTvQsYUXIO1qtAhQ==` |
| argon2-bundled.min.js | argon2-browser 1.18.0 (MIT, Argon2 reference code as WASM, inlined) | `dist/argon2-bundled.min.js` | `77c64b946baf1a5116dc591f4b9965d636b1b455f75edd2d4a587cb75e01687b` | `sha512-ImVAGIItnFnvET1exhsQB7apRztcoC5TnlSqernMJDUjbc/DLq3UEYeXFrLPrlaIl8cVfwnXb6wX2KpFf2zxHw==` |

kdbxweb's optional dependency `@xmldom/xmldom` is not needed in a browser (it uses the native `DOMParser`);
the Node test harness (`tests/compat/kdbx_node.js`) gets it from the test container. Licenses:
`kdbxweb.LICENSE`, `argon2-browser.LICENSE`.
