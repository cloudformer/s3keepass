"""s3keepass server: one Lambda behind a Function URL — stores KeePass files (.kdbx) in S3, serves the web UI.

The Lambda only lists, reads and writes encrypted bytes. Vaults are decrypted and encrypted in the browser
(index.html, with the vendored kdbxweb + argon2); the master password and the plaintext never reach it.

The first half (JSON, request body, sign-in, routing, error mapping, timing) is the series' shared shell; the
routes are in the second half.

Sign-in, AUTH_METHOD:
    web         HTTP Basic (USER_NAME / PASSWORD); the page and /vendor are public. Identity = the user name.
    cloudflare  reserved for Cloudflare Access, not built yet: every request is refused (503), never left open.

    GET    /                                  web UI (index.html), public
    GET    /vendor/<file>.js                  the vendored crypto libraries, public
    GET    /api/ping                          {"ok": true}
    GET    /api/me                            {"identity", "auth_method"}: who is signed in
    GET    /api/tree                          the folders under keepass/ (main, shared, others) and their vault files
    GET    /api/vaults                        the main folder's vaults (keepass/<name>.kdbx)
    GET    /api/vaults/<name>[?version=<id>]  the encrypted file (ETag header); an older version with ?version
    PUT    /api/vaults/<name>                 save: If-Match <etag> (update) or If-None-Match * (create) required
    DELETE /api/vaults/<name>                 If-Match <etag> required; the bucket keeps old versions
    GET    /api/vaults/<name>/versions        the file's S3 versions, newest first
    /api/files/<folder>/<name>[/versions]     the same, in a sub-folder (keepass/<folder>/<name>.kdbx)

Storage: keepass/<name>.kdbx is the main folder (every vault so far); keepass/shared/ is the shared folder and
keepass/<identity>/ a person's own. Every signed-in person can open every folder for now (no per-person isolation).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse

import boto3
from botocore.exceptions import ClientError

AUTH_METHOD = os.environ.get("AUTH_METHOD", "web")   # web | cloudflare (reserved)
USER = os.environ.get("USER_NAME", "")
PASSWORD = os.environ.get("PASSWORD", "")
CONSOLE = os.environ.get("CONSOLE", "1") == "1"
BUCKET = os.environ.get("BUCKET", "")
PREFIX = "keepass/"                 # fixed layout: s3://<bucket>/keepass/[<folder>/]<name>.kdbx
MAIN, SHARED = "", "shared"         # the main folder is keepass/ itself; shared and a person's are one level down
MAX_BYTES = 5 * 1024 * 1024         # a Function URL takes at most 6 MB per request, base64 included

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
    INDEX_HTML = f.read()
VENDOR = {}
for _name in sorted(os.listdir(os.path.join(HERE, "vendor"))):
    if _name.endswith(".js"):
        with open(os.path.join(HERE, "vendor", _name), encoding="utf-8") as f:
            VENDOR[_name] = f.read()

# Content-Security-Policy: only this page's own inline scripts (by hash) and /vendor/*.js run; WASM for argon2;
# no request leaves for another origin. A title in an uploaded vault cannot become script.
_HASHES = " ".join("'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
                   for s in re.findall(r"<script>(.*?)</script>", INDEX_HTML, re.S))
CSP = (f"default-src 'none'; script-src 'self' {_HASHES} 'wasm-unsafe-eval'; style-src 'unsafe-inline'; "
       "connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
PAGE_HEADERS = {"content-security-policy": CSP, "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer", "x-frame-options": "DENY"}

# a vault name: letters of any script (库1), digits, space, _ - . ( ); no "/" or "%"; not starting with "."
NAME = re.compile(r"\w(?:[\w .()-]{0,62}[\w.()-])?")
# a folder: "shared" or an identity (a user name, an email); no "/", no space, not starting with "."
FOLDER = re.compile(r"\w[\w@.+-]{0,127}")

s3 = boto3.client("s3")


class BadRequest(Exception):
    pass


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


class Conflict(Exception):
    """The vault changed since the caller read it (another tab or device saved first)."""


class PreconditionRequired(Exception):
    pass


class TooLarge(Exception):
    pass


# ---------------- shared: the same in every project ----------------

def _json(status, data):
    return {"statusCode": status, "headers": {"content-type": "application/json"},
            "body": json.dumps(data, ensure_ascii=False, default=str)}


def _body(event):
    """The JSON request body; 400 when it is not a JSON object."""
    raw = event.get("body") or "{}"
    try:
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw)
        data = json.loads(raw)
    except ValueError:
        raise BadRequest("request body is not valid JSON") from None
    if not isinstance(data, dict):
        raise BadRequest("request body must be a JSON object")
    return data


def _authed(event):
    """HTTP Basic, constant-time compare. No USER_NAME configured = no auth (do not do that)."""
    if not USER:
        return True
    auth = (event.get("headers") or {}).get("authorization", "")
    if not auth.lower().startswith("basic "):
        return False
    try:
        user, _, password = base64.b64decode(auth.split(None, 1)[1]).decode().partition(":")
    except Exception:
        return False
    return hmac.compare_digest(user.encode(), USER.encode()) & hmac.compare_digest(password.encode(), PASSWORD.encode())


def _identity(event):
    """Who is calling (web: the Basic user), or None when not signed in. Handlers read it as event["identity"]."""
    return (USER or "anonymous") if _authed(event) else None


ERRORS = [(BadRequest, 400), (Forbidden, 403), (NotFound, 404), (Conflict, 412), (TooLarge, 413),
          (PreconditionRequired, 428)]   # exception class -> HTTP status


def lambda_handler(event, context):
    http = (event.get("requestContext") or {}).get("http") or {}
    method, path = http.get("method", "GET"), urllib.parse.unquote(event.get("rawPath", "/"))
    if AUTH_METHOD != "web":   # fail closed: an unbuilt sign-in must not leave the page or the API open
        return _json(503, {"error": f"auth_method {AUTH_METHOD!r} is not available yet; deploy with auth_method = web"})
    if CONSOLE and method == "GET" and path in ("/", "/index.html"):
        return {"statusCode": 200, "body": INDEX_HTML,
                "headers": dict(PAGE_HEADERS, **{"content-type": "text/html; charset=utf-8", "cache-control": "no-cache"})}
    if CONSOLE and method == "GET" and path.startswith("/vendor/") and path[8:] in VENDOR:
        return {"statusCode": 200, "body": VENDOR[path[8:]],
                "headers": {"content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=86400",
                            "x-content-type-options": "nosniff"}}
    event["identity"] = _identity(event)
    if event["identity"] is None:
        return _json(401, {"error": "bad credentials"})
    t0 = time.perf_counter()
    status, data = 404, {"error": f"no route: {method} {path}"}
    try:
        for route_method, pattern, handler in ROUTES:
            match = pattern.fullmatch(path)
            if match and route_method == method:
                out = handler(event, **match.groupdict())
                if isinstance(out, dict) and "statusCode" in out:     # a raw response (the vault's bytes)
                    out["headers"]["x-server-ms"] = str(round((time.perf_counter() - t0) * 1000, 1))
                    return out
                status, data = out if isinstance(out, tuple) else (200, out)
                break
    except Exception as e:  # noqa: BLE001 - every error becomes a JSON response
        status = next((s for cls, s in ERRORS if isinstance(e, cls)), 500)
        data = {"error": str(e) if status < 500 else f"{type(e).__name__}: {e}"}
    data.setdefault("ms", round((time.perf_counter() - t0) * 1000, 1))
    return _json(status, data)


# ---------------- the project's API: keepass/[<folder>/]<name>.kdbx in one bucket ----------------

def _key(folder, name):
    """The S3 key of a vault; the only place a path is built, so nothing outside keepass/[<folder>/]<name>.kdbx."""
    if folder != MAIN and (not FOLDER.fullmatch(folder) or ".." in folder):
        raise BadRequest("folder: 'shared' or an identity (letters, digits, @ . + - _), at most 128, not starting "
                         "with '.' — got " + repr(folder))
    if not NAME.fullmatch(name):
        raise BadRequest("vault name: letters, digits, space, _ - . ( ), at most 64, not starting with '.' or "
                         "a space — got " + repr(name))
    return f"{PREFIX}{folder}/{name}.kdbx" if folder else f"{PREFIX}{name}.kdbx"


def _split(key):
    """keepass/[<folder>/]<name>.kdbx -> (folder, name), or None for anything else (deeper, not a vault)."""
    parts = key[len(PREFIX):].split("/")
    folder, file = ("", parts[0]) if len(parts) == 1 else tuple(parts) if len(parts) == 2 else ("", "")
    if file.endswith(".kdbx") and NAME.fullmatch(file[:-5]) and (folder == MAIN or FOLDER.fullmatch(folder)):
        return folder, file[:-5]
    return None


def _header(event, name):
    return (event.get("headers") or {}).get(name)


def _code(e):
    return e.response.get("Error", {}).get("Code", "")


def _bytes(event):
    raw = event.get("body") or ""
    data = base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode("latin-1")
    if not data:
        raise BadRequest("empty body: send the .kdbx file")
    if len(data) > MAX_BYTES:
        raise TooLarge(f"a vault is at most {MAX_BYTES // 1024 // 1024} MB (a Lambda Function URL request limit)")
    if data[:4] != b"\x03\xd9\xa2\x9a":
        raise BadRequest("not a KeePass file (.kdbx signature missing)")
    return data


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def ping(event):
    return {"ok": True}


def me(event):
    return {"identity": event["identity"], "auth_method": AUTH_METHOD}


def _files(prefix):
    """Every vault file under prefix, as the UI shows it."""
    files = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=prefix):
        for o in page.get("Contents", []):
            where = _split(o["Key"])
            if where:
                files.append({"folder": where[0], "name": where[1], "path": o["Key"], "size": o["Size"],
                              "modified": _iso(o["LastModified"]), "etag": o["ETag"]})
    return sorted(files, key=lambda f: (f["folder"], f["name"]))


def tree(event):
    """Folders: main (keepass/ itself) first, then shared, then each person's; main and shared even when empty."""
    by_folder = {MAIN: [], SHARED: []}
    for f in _files(PREFIX):
        by_folder.setdefault(f["folder"], []).append(f)
    for files in by_folder.values():
        for f in files:
            f["owner"] = _owner(f["path"])
    order = [MAIN, SHARED] + sorted(k for k in by_folder if k not in (MAIN, SHARED))
    kind = {MAIN: "main", SHARED: "shared"}
    folders = [{"name": k, "path": PREFIX + (k + "/" if k else ""), "kind": kind.get(k, "personal"),
                "files": by_folder[k]} for k in order]
    return {"me": event["identity"], "folders": folders,
            "backend": f"S3 list {PREFIX} · {sum(len(f['files']) for f in folders)} files"}


def list_vaults(event):
    vaults = [{k: f[k] for k in ("name", "size", "modified", "etag")} for f in _files(PREFIX) if f["folder"] == MAIN]
    return {"vaults": vaults, "backend": f"S3 list {PREFIX} · {len(vaults)} vaults"}


def get_vault(event, folder, name):
    key = _key(folder, name)
    version = ((event.get("queryStringParameters") or {}).get("version") or "").strip()
    try:
        o = s3.get_object(Bucket=BUCKET, Key=key, **({"VersionId": version} if version else {}))
    except ClientError as e:
        if _code(e) in ("NoSuchKey", "NoSuchVersion", "404", "InvalidArgument"):
            raise NotFound(f"no vault {name!r}" + (f" version {version}" if version else "")) from None
        raise
    body = o["Body"].read()
    return {"statusCode": 200, "isBase64Encoded": True, "body": base64.b64encode(body).decode(),
            "headers": {"content-type": "application/octet-stream", "etag": o["ETag"],
                        "x-version-id": o.get("VersionId") or "", "x-backend": f"S3 get {key} · {len(body)} bytes",
                        "cache-control": "no-store"}}


def _owner(key):
    """Who created the vault (x-amz-meta-owner), "" when unknown or the file is gone."""
    try:
        return urllib.parse.unquote(s3.head_object(Bucket=BUCKET, Key=key).get("Metadata", {}).get("owner", ""))
    except ClientError:
        return ""


def put_vault(event, folder, name):
    """Never an unconditional overwrite: If-Match = the ETag the caller read, If-None-Match: * = create."""
    key = _key(folder, name)
    if_match, if_none = _header(event, "if-match"), _header(event, "if-none-match")
    if not if_match and if_none != "*":
        raise PreconditionRequired("send If-Match: <etag> (update) or If-None-Match: * (create); "
                                   "an unconditional save could overwrite another tab's or device's change")
    data = _bytes(event)
    cond = {"IfMatch": if_match} if if_match else {"IfNoneMatch": "*"}
    # owner: whoever created it; a save keeps it (S3 metadata is ASCII, so it is stored percent-encoded)
    owner = (_owner(key) if if_match else "") or event["identity"]
    try:
        r = s3.put_object(Bucket=BUCKET, Key=key, Body=data, ContentType="application/octet-stream",
                          ServerSideEncryption="aws:kms", Metadata={"owner": urllib.parse.quote(owner)}, **cond)
    except ClientError as e:
        if _code(e) in ("PreconditionFailed", "ConditionalRequestConflict", "412", "409"):
            raise Conflict(f"vault {name!r} already exists" if not if_match else
                           f"vault {name!r} was changed elsewhere (another tab or device) since you opened it; "
                           "nothing was overwritten — reopen it to see the other change") from None
        if _code(e) in ("NoSuchKey", "404"):
            raise NotFound(f"no vault {name!r}") from None
        raise
    return (200 if if_match else 201), {
        "name": name, "etag": r["ETag"], "version_id": r.get("VersionId") or "", "size": len(data),
        "backend": f"S3 put {key} · {len(data)} bytes · {'If-Match' if if_match else 'If-None-Match *'}"}


def delete_vault(event, folder, name):
    key = _key(folder, name)
    if_match = _header(event, "if-match")
    if not if_match:
        raise PreconditionRequired("send If-Match: <etag> of the version you mean to delete")
    try:
        etag = s3.head_object(Bucket=BUCKET, Key=key)["ETag"]
    except ClientError as e:
        if _code(e) in ("NoSuchKey", "404"):
            raise NotFound(f"no vault {name!r}") from None
        raise
    if etag != if_match:
        raise Conflict(f"vault {name!r} was changed elsewhere since you listed it; nothing was deleted")
    s3.delete_object(Bucket=BUCKET, Key=key)
    return {"deleted": name, "backend": f"S3 delete {key} · older versions kept"}


def list_versions(event, folder, name):
    key = _key(folder, name)
    versions = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=BUCKET, Prefix=key):
        for v in page.get("Versions", []):
            if v["Key"] == key:
                versions.append({"version_id": v["VersionId"], "modified": _iso(v["LastModified"]),
                                 "size": v["Size"], "etag": v["ETag"], "latest": v["IsLatest"], "deleted": False})
        for v in page.get("DeleteMarkers", []):
            if v["Key"] == key:
                versions.append({"version_id": v["VersionId"], "modified": _iso(v["LastModified"]),
                                 "size": 0, "etag": "", "latest": v["IsLatest"], "deleted": True})
    if not versions:
        raise NotFound(f"no vault {name!r}")
    versions.sort(key=lambda v: (v["modified"], v["latest"]), reverse=True)   # same second: the latest first
    return {"name": name, "versions": versions, "backend": f"S3 list versions {key} · {len(versions)}"}


def _main(handler):
    """/api/vaults/<name>: the same handler, in the main folder (keepass/<name>.kdbx)."""
    return lambda event, name: handler(event, MAIN, name)


FILE, MAIN_FILE = r"/api/files/(?P<folder>[^/]+)/(?P<name>[^/]+)", r"/api/vaults/(?P<name>[^/]+)"
ROUTES = [
    ("GET",    re.compile(r"/api/ping"), ping),
    ("GET",    re.compile(r"/api/me"), me),
    ("GET",    re.compile(r"/api/tree"), tree),
    ("GET",    re.compile(FILE + "/versions"), list_versions),
    ("GET",    re.compile(FILE), get_vault),
    ("PUT",    re.compile(FILE), put_vault),
    ("DELETE", re.compile(FILE), delete_vault),
    ("GET",    re.compile(r"/api/vaults"), list_vaults),
    ("GET",    re.compile(MAIN_FILE + "/versions"), _main(list_versions)),
    ("GET",    re.compile(MAIN_FILE), _main(get_vault)),
    ("PUT",    re.compile(MAIN_FILE), _main(put_vault)),
    ("DELETE", re.compile(MAIN_FILE), _main(delete_vault)),
]
