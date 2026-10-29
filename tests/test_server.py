"""The server Lambda, called in-process against the fake S3: auth, the web UI, the vault API, its guarantees."""
import base64
import hashlib
import json
import os
import re
import urllib.parse

import pytest

import lambda_function as lf

AUTH = "Basic " + base64.b64encode(b"admin:pw").decode()
KDBX = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + b"ciphertext"   # the KDBX signature, then anything: the server never decrypts


def call(method, path, body=None, auth=AUTH, headers=None, query=None):
    """body: bytes = a vault file (sent base64, as a Function URL sends application/octet-stream)."""
    h = dict({"authorization": auth} if auth else {}, **(headers or {}))
    event = {"requestContext": {"http": {"method": method}}, "rawPath": path, "headers": h,
             "queryStringParameters": query}
    if isinstance(body, bytes):
        event.update(body=base64.b64encode(body).decode(), isBase64Encoded=True)
    resp = lf.lambda_handler(event, None)
    ctype = resp["headers"]["content-type"]
    if ctype.startswith("application/json"):
        return resp["statusCode"], json.loads(resp["body"]), resp["headers"]
    if resp.get("isBase64Encoded"):
        return resp["statusCode"], base64.b64decode(resp["body"]), resp["headers"]
    return resp["statusCode"], resp["body"], resp["headers"]


def vault(name):
    return "/api/vaults/" + urllib.parse.quote(name)   # a browser percent-encodes 库1


def create(name, data=KDBX):
    status, out, _ = call("PUT", vault(name), data, headers={"if-none-match": "*"})
    assert status == 201, out
    return out["etag"]


# ---- the page ----

def test_ui_and_vendor_are_public_and_the_api_needs_auth(fake_s3):
    status, body, headers = call("GET", "/", auth=None)
    assert status == 200 and "<html" in body and "vault-core" in body
    for f in ("kdbxweb.min.js", "argon2-bundled.min.js"):
        status, js, headers = call("GET", "/vendor/" + f, auth=None)
        assert status == 200 and headers["content-type"].startswith("text/javascript") and len(js) > 10000
    assert call("GET", "/vendor/README.md", auth=None)[0] == 401          # only the .js files are served
    assert call("GET", "/api/vaults", auth=None)[0] == 401
    assert call("GET", "/api/vaults", auth="Basic " + base64.b64encode(b"admin:wrong").decode())[0] == 401
    assert call("GET", "/api/ping")[1]["ok"] is True


def test_csp_runs_only_this_pages_scripts():
    """A title from an uploaded vault cannot become script: inline scripts run only by hash, no unsafe-inline."""
    status, body, headers = call("GET", "/", auth=None)
    csp = headers["content-security-policy"]
    script_src = re.search(r"script-src ([^;]+)", csp).group(1)
    assert "'unsafe-inline'" not in script_src and "'unsafe-eval'" not in script_src
    inline = re.findall(r"<script>(.*?)</script>", body, re.S)
    assert len(inline) == 2
    for s in inline:
        assert "'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() in script_src
    assert "connect-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert not re.search(r"<[^>]+\son[a-z]+=", body), "inline event handlers would be blocked by the CSP"


def test_vendored_libraries_match_their_pins():
    """src/server/vendor/README.md pins every vendored file by SHA-256."""
    vendor = os.path.join(os.path.dirname(lf.__file__), "vendor")
    with open(os.path.join(vendor, "README.md"), encoding="utf-8") as f:
        pins = dict(re.findall(r"^\| (\S+\.js) \|.*?\| `([0-9a-f]{64})` \|", f.read(), re.M))
    assert set(pins) == set(lf.VENDOR) == {"kdbxweb.min.js", "argon2-bundled.min.js"}
    for name, sha in pins.items():
        with open(os.path.join(vendor, name), "rb") as f:
            assert hashlib.sha256(f.read()).hexdigest() == sha, name


# ---- the vault API ----

def test_create_list_and_open_vaults(fake_s3):
    """Acceptance 2: 库1 and 库2 are listed; opening returns the same bytes and the ETag to save against."""
    etag = create("库1")
    create("库2", KDBX + b"2")
    status, out, _ = call("GET", "/api/vaults")
    assert status == 200 and [v["name"] for v in out["vaults"]] == ["库1", "库2"]
    assert out["vaults"][0]["etag"] == etag and out["vaults"][0]["size"] == len(KDBX)
    assert "S3 list" in out["backend"] and isinstance(out["ms"], float)
    status, data, headers = call("GET", vault("库1"))
    assert status == 200 and data == KDBX and headers["etag"] == etag
    assert headers["content-type"] == "application/octet-stream" and "S3 get" in headers["x-backend"]
    assert float(headers["x-server-ms"]) >= 0
    assert set(fake_s3.versions) == {"keepass/库1.kdbx", "keepass/库2.kdbx"}


def test_create_refuses_an_existing_name(fake_s3):
    create("库1")
    status, out, _ = call("PUT", vault("库1"), KDBX + b"other", headers={"if-none-match": "*"})
    assert status == 412 and "already exists" in out["error"]
    assert call("GET", vault("库1"))[1] == KDBX


def test_save_with_the_etag_it_read(fake_s3):
    etag = create("库1")
    status, out, _ = call("PUT", vault("库1"), KDBX + b"v2", headers={"if-match": etag})
    assert status == 200 and out["etag"] != etag and "If-Match" in out["backend"]
    assert call("GET", vault("库1"))[1] == KDBX + b"v2"


def test_stale_save_is_refused_never_overwritten(fake_s3):
    """Acceptance 4: two tabs open the same version; the first save wins, the second is refused with 412."""
    etag = create("库1")
    tab1 = call("PUT", vault("库1"), KDBX + b"tab 1", headers={"if-match": etag})
    tab2 = call("PUT", vault("库1"), KDBX + b"tab 2", headers={"if-match": etag})
    assert tab1[0] == 200
    assert tab2[0] == 412 and "changed elsewhere" in tab2[1]["error"] and "nothing was overwritten" in tab2[1]["error"]
    assert call("GET", vault("库1"))[1] == KDBX + b"tab 1"


def test_unconditional_save_is_refused(fake_s3):
    create("库1")
    status, out, _ = call("PUT", vault("库1"), KDBX + b"blind")
    assert status == 428 and "If-Match" in out["error"]
    assert call("GET", vault("库1"))[1] == KDBX
    assert call("PUT", vault("nope"), KDBX, headers={"if-match": '"x"'})[0] == 404


def test_saves_are_sse_kms_ciphertext(fake_s3):
    """Acceptance 5: only KeePass files are accepted, and every put asks for SSE-KMS."""
    create("库1")
    assert fake_s3.calls[-1]["ServerSideEncryption"] == "aws:kms"
    status, out, _ = call("PUT", vault("plain"), b'{"password": "hunter2"}', headers={"if-none-match": "*"})
    assert status == 400 and "not a KeePass file" in out["error"]
    assert call("PUT", vault("empty"), b"", headers={"if-none-match": "*"})[0] == 400
    assert call("PUT", vault("big"), KDBX + b"x" * lf.MAX_BYTES, headers={"if-none-match": "*"})[0] == 413
    assert set(fake_s3.versions) == {"keepass/库1.kdbx"}


@pytest.mark.parametrize("name,status", [
    ("库1", 201), ("Personal (old) v2.1", 201), ("a", 201),
    (".hidden", 400), (" lead", 400), ("trail ", 400), ("a%2Fb", 404), ("..", 400), ("x" * 65, 400), ("semi;colon", 400),
])
def test_vault_names(fake_s3, name, status):
    path = "/api/vaults/" + (name if "%" in name else urllib.parse.quote(name))
    assert call("PUT", path, KDBX, headers={"if-none-match": "*"})[0] == status


def test_versions_and_reading_an_old_one(fake_s3):
    etag = create("库1")
    for i in (2, 3):
        etag = call("PUT", vault("库1"), KDBX + b"v%d" % i, headers={"if-match": etag})[1]["etag"]
    status, out, _ = call("GET", vault("库1") + "/versions")
    assert status == 200 and len(out["versions"]) == 3
    assert [v["latest"] for v in out["versions"]] == [True, False, False]
    oldest = out["versions"][-1]["version_id"]
    status, data, headers = call("GET", vault("库1"), query={"version": oldest})
    assert status == 200 and data == KDBX and headers["x-version-id"] == oldest
    assert call("GET", vault("库1"), query={"version": "nope"})[0] == 404
    assert call("GET", vault("missing") + "/versions")[0] == 404


def test_delete_needs_the_current_etag_and_keeps_versions(fake_s3):
    etag = create("库1")
    assert call("DELETE", vault("库1"))[0] == 428
    assert call("DELETE", vault("库1"), headers={"if-match": '"stale"'})[0] == 412
    status, out, _ = call("DELETE", vault("库1"), headers={"if-match": etag})
    assert status == 200 and out["deleted"] == "库1"
    assert call("GET", "/api/vaults")[1]["vaults"] == []
    assert call("GET", vault("库1"))[0] == 404
    versions = call("GET", vault("库1") + "/versions")[1]["versions"]
    assert [v["deleted"] for v in versions] == [True, False]          # recoverable: the file is still a version
    assert call("DELETE", vault("库1"), headers={"if-match": etag})[0] == 404
    assert create("库1")                                              # the name is free again


def test_listing_ignores_other_keys(fake_s3):
    create("库1")
    fake_s3._add("keepass/sub/x.kdbx", body=KDBX, etag='"a"', deleted=False)
    fake_s3._add("keepass/notes.txt", body=b"x", etag='"b"', deleted=False)
    fake_s3._add("other/y.kdbx", body=KDBX, etag='"c"', deleted=False)
    assert [v["name"] for v in call("GET", "/api/vaults")[1]["vaults"]] == ["库1"]


def test_unknown_routes(fake_s3):
    assert call("GET", "/api/nope")[0] == 404
    assert call("POST", vault("库1"), KDBX)[0] == 404
