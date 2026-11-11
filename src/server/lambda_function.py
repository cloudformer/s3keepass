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
    GET    /api/tree                          the folders under keepass/ (the top level first) and their vault files
    GET    /api/vaults                        the main folder's vaults (keepass/<name>.kdbx)
    GET    /api/vaults/<name>[?version=<id>]  the encrypted file (ETag header); an older version with ?version
    PUT    /api/vaults/<name>[?action=upload] save: If-Match <etag> (update; changed meanwhile = 409) or
                                              If-None-Match * (create / upload; the name exists = 412)
    DELETE /api/vaults/<name>                 If-Match <etag> required; the bucket keeps old versions
    GET    /api/vaults/<name>/versions        the file's S3 versions, newest first
    /api/files/<folder>/<name>[/versions]     the same, in a sub-folder (keepass/<folder>/<name>.kdbx)
    POST   /api/audit/unlock                  {"path", "ok"}: the browser reports an unlock result (self-reported:
                                              a file downloaded around the page never shows up here)
    GET    /api/audit?path=<key>&limit=<n>    a vault's access records, newest first

Access records: every read, save, create, delete and reported unlock is one small JSON object,
log/<vault key>/<time>-<random>.json (write-only, so concurrent writers never collide; the bucket's lifecycle
rule expires them), and one JSON line in CloudWatch. Recording never blocks the vault: a failed write is logged.

Storage: keepass/<name>.kdbx (the top level, every vault so far) or keepass/<folder>/<name>.kdbx. Folders are only
names for people to sort by: no rules, no permissions — every signed-in person opens every folder.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse
import uuid

import boto3
from botocore.exceptions import ClientError

AUTH_METHOD = os.environ.get("AUTH_METHOD", "web")   # web | cloudflare (reserved)
USER = os.environ.get("USER_NAME", "")
PASSWORD = os.environ.get("PASSWORD", "")
CONSOLE = os.environ.get("CONSOLE", "1") == "1"
BUCKET = os.environ.get("BUCKET", "")
PREFIX = "keepass/"                 # fixed layout: s3://<bucket>/keepass/[<folder>/]<name>.kdbx
MAIN = ""                           # the top level, keepass/ itself; a folder is one level down
LOG = "log/"                        # access records: s3://<bucket>/log/<vault key>/<time>-<random>.json
MAX_BYTES = 4_718_592               # 4.5 MB: a Function URL takes at most 6 MB per request, base64 included

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
# a folder name (shared, frank, frank@example.com …): no "/", no space, not starting with "."
FOLDER = re.compile(r"\w[\w@.+-]{0,127}")

s3 = boto3.client("s3")


class BadRequest(Exception):
    pass


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


class Conflict(Exception):
    """A precondition failed: the name exists (create), or the version to delete is not the current one."""


class Stale(Exception):
    """A save lost the race: the vault changed since the caller read it (another tab or device saved first)."""


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


ERRORS = [(BadRequest, 400), (Forbidden, 403), (NotFound, 404), (Stale, 409), (Conflict, 412), (TooLarge, 413),
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
        raise BadRequest("folder: letters, digits, @ . + - _, at most 128, not starting with '.' — got "
                         + repr(folder))
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
        raise TooLarge(f"a vault is at most 4.5 MB ({len(data) / 1048576:.1f} MB sent): a Lambda Function URL request "
                       "is 6 MB, base64 included — remove attachments and history (Clean up) and save again")
    if data[:4] != b"\x03\xd9\xa2\x9a":
        raise BadRequest("not a KeePass file (.kdbx signature missing)")
    return data


def datetime_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


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
    """The top level (keepass/ itself, always listed) first, then every folder that holds a vault, by name."""
    by_folder = {MAIN: []}
    for f in _files(PREFIX):
        f["owner"] = _owner(f["path"])
        f["last_unlock"] = (_records(f["path"], 1, action="unlock") or [None])[0]
        by_folder.setdefault(f["folder"], []).append(f)
    folders = [{"name": k, "path": PREFIX + (k + "/" if k else ""), "files": by_folder[k]}
               for k in sorted(by_folder)]   # "" sorts first
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
    _record(event, key, "read", etag=o["ETag"])
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


# ---- access records ----

def _record(event, key, action, **extra):
    """One access record: a JSON line for CloudWatch and an object under log/. Never raises."""
    rec = dict({"at": _iso(datetime_now()), "who": event["identity"], "path": key, "action": action}, **extra)
    print(json.dumps({"audit": rec}, ensure_ascii=False))
    try:
        s3.put_object(Bucket=BUCKET, Key=f"{LOG}{key}/{time.time_ns():020d}-{uuid.uuid4().hex[:8]}.json",
                      Body=json.dumps(rec, ensure_ascii=False).encode(), ContentType="application/json")
    except Exception as e:  # noqa: BLE001 - a lost record must not lose the vault operation
        print(json.dumps({"audit_write_failed": f"{type(e).__name__}: {e}", "path": key}))


def _records(key, limit, action=None):
    """The vault's records, newest first (keys sort by time)."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=f"{LOG}{key}/"):
        keys += [o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".json")]
    out = []
    for k in sorted(keys, reverse=True):
        rec = json.loads(s3.get_object(Bucket=BUCKET, Key=k)["Body"].read())
        if action is None or rec.get("action") == action:
            out.append(rec)
            if len(out) >= limit:
                break
    return out


def _vault_key(path):
    if not isinstance(path, str) or not path.startswith(PREFIX) or not _split(path):
        raise BadRequest("path: a vault's key, keepass/[<folder>/]<name>.kdbx — got " + repr(path))
    return path


def report_unlock(event):
    """The browser reports an unlock result: only the path and true / false, never anything secret."""
    data = _body(event)
    if set(data) != {"path", "ok"} or not isinstance(data["ok"], bool):
        raise BadRequest('send exactly {"path": "<vault key>", "ok": true | false}')
    key = _vault_key(data["path"])
    _record(event, key, "unlock", ok=data["ok"], self_reported=True)
    return {"recorded": True}


def audit(event):
    q = event.get("queryStringParameters") or {}
    key = _vault_key(q.get("path"))
    limit = min(max(int(q.get("limit") or 20), 1), 200) if str(q.get("limit") or "20").isdigit() else 20
    return {"path": key, "records": _records(key, limit), "backend": f"S3 list + get {LOG}{key}/"}


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
            if not if_match:
                raise Conflict(f"vault {name!r} already exists; nothing was overwritten") from None
            raise Stale(f"vault {name!r} was changed elsewhere (another tab or device) since you opened it; "
                        "nothing was overwritten — reopen it to see the other change") from None
        if _code(e) in ("NoSuchKey", "404"):
            raise NotFound(f"no vault {name!r}") from None
        raise
    upload = ((event.get("queryStringParameters") or {}).get("action") == "upload")
    _record(event, key, "save" if if_match else "upload" if upload else "create", etag=r["ETag"])
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
    _record(event, key, "delete", etag=etag)
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
    ("POST",   re.compile(r"/api/audit/unlock"), report_unlock),
    ("GET",    re.compile(r"/api/audit"), audit),
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
