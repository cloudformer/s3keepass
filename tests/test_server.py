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


def vault_keys(fake):
    """The vault files in the bucket (log/ holds the access records, task 4)."""
    return {k for k in fake.versions if k.startswith("keepass/")}


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


def test_me_is_the_signed_in_user(fake_s3):
    """Task 1: auth_method = web — the identity is the HTTP Basic user (owner and access records use it)."""
    status, out, _ = call("GET", "/api/me")
    assert status == 200 and out["identity"] == "admin" and out["auth_method"] == "web"
    assert call("GET", "/api/me", auth=None)[0] == 401


def test_cloudflare_mode_is_closed_until_it_exists(fake_s3, monkeypatch):
    """Task 1: auth_method = cloudflare is reserved, not built yet — it fails closed, never falls back to open."""
    monkeypatch.setattr(lf, "AUTH_METHOD", "cloudflare")
    for path in ("/", "/api/ping", "/api/me", "/api/vaults"):
        status, out, _ = call("GET", path)
        assert status == 503 and "cloudflare" in out["error"], path


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
    assert vault_keys(fake_s3) == {"keepass/库1.kdbx", "keepass/库2.kdbx"}   # task 4: log/ holds access records


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
    assert tab2[0] == 409 and "changed elsewhere" in tab2[1]["error"] and "nothing was overwritten" in tab2[1]["error"]   # task 5: 409
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
    assert [c for c in fake_s3.calls if c["Key"].startswith("keepass/")][-1]["ServerSideEncryption"] == "aws:kms"   # task 4: skip log/ writes
    status, out, _ = call("PUT", vault("plain"), b'{"password": "hunter2"}', headers={"if-none-match": "*"})
    assert status == 400 and "not a KeePass file" in out["error"]
    assert call("PUT", vault("empty"), b"", headers={"if-none-match": "*"})[0] == 400
    assert call("PUT", vault("big"), KDBX + b"x" * lf.MAX_BYTES, headers={"if-none-match": "*"})[0] == 413
    assert vault_keys(fake_s3) == {"keepass/库1.kdbx"}   # task 4: log/ holds access records


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


# ---- task 2: folders — keepass/ (top level) and keepass/<folder>/, names only, no rules ----

def file(folder, name):
    return "/api/files/" + urllib.parse.quote(folder, safe="") + "/" + urllib.parse.quote(name, safe="")


def test_files_in_any_folder(fake_s3):
    """A vault lives at the top level or in any folder. /api/vaults/<name> = the top level, as before."""
    assert call("PUT", file("shared", "team"), KDBX, headers={"if-none-match": "*"})[0] == 201
    assert call("PUT", file("bob@example.com", "bob1"), KDBX + b"b", headers={"if-none-match": "*"})[0] == 201
    mine = create("mine")
    assert vault_keys(fake_s3) == {"keepass/shared/team.kdbx", "keepass/bob@example.com/bob1.kdbx", "keepass/mine.kdbx"}
    status, data, headers = call("GET", vault("mine"))
    assert status == 200 and data == KDBX and headers["etag"] == mine
    assert call("GET", file("bob@example.com", "bob1"))[1] == KDBX + b"b"    # no per-person isolation yet
    etag = call("GET", file("shared", "team"))[2]["etag"]
    assert call("PUT", file("shared", "team"), KDBX + b"2", headers={"if-match": etag})[0] == 200
    assert call("DELETE", file("shared", "team"), headers={"if-match": call("GET", file("shared", "team"))[2]["etag"]})[0] == 200


@pytest.mark.parametrize("folder,name,status", [
    ("shared", "ok", 201), ("frank@example.com", "ok", 201), ("frank", "库1", 201),
    ("..", "x", 400), (".hidden", "x", 400), ("a b", "x", 400), ("shared", "..", 400), ("shared", ".x", 400),
    ("x" * 129, "x", 400),
])
def test_folder_and_name_rules(fake_s3, folder, name, status):
    """Only keepass/[<folder>/]<name>.kdbx: no '..', no hidden names, nothing outside keepass/."""
    assert call("PUT", file(folder, name), KDBX, headers={"if-none-match": "*"})[0] == status


def test_paths_cannot_escape_or_nest(fake_s3):
    for raw in ("/api/files/shared/a%2Fb", "/api/files/a%2F..%2Fb/x", "/api/files/shared", "/api/files//x",
                "/api/files/shared/x/versions/y"):
        assert call("PUT", raw, KDBX, headers={"if-none-match": "*"})[0] in (400, 404), raw
    assert not fake_s3.versions


def test_tree_lists_folders_and_files(fake_s3):
    """GET /api/tree: the top level first (even empty), then every folder that holds a vault, by name."""
    create("mine")
    call("PUT", file("bob@example.com", "b"), KDBX, headers={"if-none-match": "*"})
    fake_s3._add("keepass/shared/readme.txt", body=b"x", etag='"t"', deleted=False)      # not a vault: ignored
    fake_s3._add("keepass/x/deep/y.kdbx", body=KDBX, etag='"d"', deleted=False)          # deeper: ignored
    fake_s3._add("other/old.kdbx", body=KDBX, etag='"o"', deleted=False)                 # outside keepass/: ignored
    status, out, _ = call("GET", "/api/tree")
    assert status == 200 and out["me"] == "admin"
    assert [f["name"] for f in out["folders"]] == ["", "bob@example.com"]          # shared holds no vault: not listed
    assert [f["path"] for f in out["folders"]] == ["keepass/", "keepass/bob@example.com/"]
    mine = out["folders"][0]["files"][0]
    assert mine["name"] == "mine" and mine["path"] == "keepass/mine.kdbx" and mine["size"] == len(KDBX)
    assert mine["modified"] and mine["etag"]
    assert [f["name"] for f in out["folders"][1]["files"]] == ["b"]


# ---- task 3: owner = who created the vault (web: the user; cloudflare: the email) ----

def as_user(monkeypatch, user):
    monkeypatch.setattr(lf, "USER", user)
    monkeypatch.setattr(lf, "PASSWORD", "pw-" + user)
    return "Basic " + base64.b64encode(f"{user}:pw-{user}".encode()).decode()


def test_owner_is_who_created_it_and_a_save_keeps_it(fake_s3, monkeypatch):
    a = as_user(monkeypatch, "alice")
    status, out, _ = call("PUT", vault("库1"), KDBX, auth=a, headers={"if-none-match": "*"})
    assert status == 201
    assert fake_s3._current("keepass/库1.kdbx")["meta"]["owner"] == "alice"
    b = as_user(monkeypatch, "bob")
    status, out, _ = call("PUT", vault("库1"), KDBX + b"by bob", auth=b, headers={"if-match": out["etag"]})
    assert status == 200
    assert fake_s3._current("keepass/库1.kdbx")["meta"]["owner"] == "alice"      # bob saved, alice still owns it
    tree = call("GET", "/api/tree", auth=b)[1]
    assert tree["folders"][0]["files"][0]["owner"] == "alice"


def test_owner_survives_a_non_ascii_user(fake_s3, monkeypatch):
    """S3 metadata is ASCII only: a user name like 张三 is stored percent-encoded and shown as typed."""
    u = as_user(monkeypatch, "张三")
    call("PUT", file("shared", "team"), KDBX, auth=u, headers={"if-none-match": "*"})
    assert fake_s3._current("keepass/shared/team.kdbx")["meta"]["owner"].isascii()
    assert call("GET", "/api/tree", auth=u)[1]["folders"][1]["files"][0]["owner"] == "张三"   # folders: "", shared


# ---- task 4: access records — one small JSON per event under log/, newest first; also one CloudWatch line ----

def records(path, limit=None):
    status, out, _ = call("GET", "/api/audit", query=dict({"path": path}, **({"limit": str(limit)} if limit else {})))
    assert status == 200, out
    return out["records"]


def test_every_read_save_create_delete_is_recorded(fake_s3, capsys):
    etag = create("库1")
    call("GET", vault("库1"))
    etag2 = call("PUT", vault("库1"), KDBX + b"2", headers={"if-match": etag})[1]["etag"]
    call("DELETE", vault("库1"), headers={"if-match": etag2})
    recs = records("keepass/库1.kdbx")
    assert [r["action"] for r in recs] == ["delete", "save", "read", "create"]          # newest first
    assert all(r["who"] == "admin" and r["path"] == "keepass/库1.kdbx" and r["at"] for r in recs)
    assert recs[1]["etag"] == etag2 and recs[3]["etag"] == etag                          # the ETag after the save
    assert all(k.startswith("log/keepass/库1.kdbx/") and k.endswith(".json") for k in fake_s3.versions if k.startswith("log/"))
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert [l["audit"]["action"] for l in lines] == ["create", "read", "save", "delete"]   # CloudWatch: one JSON line each


def test_unlock_result_is_self_reported_and_carries_no_secret(fake_s3):
    create("库1")
    assert call("POST", "/api/audit/unlock", json.dumps({"path": "keepass/库1.kdbx", "ok": False}).encode(),
                headers={"content-type": "application/json"})[0] == 200
    assert call("POST", "/api/audit/unlock", json.dumps({"path": "keepass/库1.kdbx", "ok": True}).encode())[0] == 200
    for bad in ({"path": "keepass/库1.kdbx", "ok": True, "password": "x"},         # anything but path and ok: refused
                {"path": "keepass/库1.kdbx", "ok": "yes"}, {"path": "../etc/passwd", "ok": True}, {"ok": True}):
        assert call("POST", "/api/audit/unlock", json.dumps(bad).encode())[0] == 400, bad
    recs = records("keepass/库1.kdbx")
    assert [(r["action"], r.get("ok")) for r in recs[:2]] == [("unlock", True), ("unlock", False)]
    assert recs[0]["self_reported"] is True


def test_records_newest_first_with_a_limit_and_the_tree_shows_the_last_unlock(fake_s3):
    create("库1")
    for ok in (True, False, True):
        call("POST", "/api/audit/unlock", json.dumps({"path": "keepass/库1.kdbx", "ok": ok}).encode())
    assert len(records("keepass/库1.kdbx", limit=2)) == 2
    assert call("GET", "/api/audit", query={"path": "../x", "limit": "2"})[0] == 400
    last = call("GET", "/api/tree")[1]["folders"][0]["files"][0]["last_unlock"]
    assert last["ok"] is True and last["who"] == "admin" and last["at"]


def test_a_failing_log_never_blocks_the_vault(fake_s3, monkeypatch):
    real_put = fake_s3.put_object
    def put(**kw):
        if kw["Key"].startswith("log/"):
            raise RuntimeError("log bucket down")
        return real_put(**kw)
    monkeypatch.setattr(fake_s3, "put_object", put)
    assert create("库1")                                          # the save itself succeeds
    assert call("GET", vault("库1"))[0] == 200


# ---- task 5: stale save = 409, upload into a folder never overwrites, at most 4.5 MB ----

def test_upload_into_a_folder_never_overwrites(fake_s3):
    up = lambda body: call("PUT", file("team", "imported"), body, headers={"if-none-match": "*"}, query={"action": "upload"})
    assert up(KDBX)[0] == 201
    status, out, _ = up(KDBX + b"other")
    assert status == 412 and "already exists" in out["error"]
    assert call("GET", file("team", "imported"))[1] == KDBX
    assert records("keepass/team/imported.kdbx")[-1]["action"] == "upload"


def test_size_limit_is_4_5_mb(fake_s3):
    assert lf.MAX_BYTES == 4_718_592                                # 4.5 MiB: a Function URL request is 6 MB, base64 included
    assert call("PUT", vault("at-limit"), KDBX + b"x" * (lf.MAX_BYTES - len(KDBX)), headers={"if-none-match": "*"})[0] == 201
    status, out, _ = call("PUT", vault("over"), KDBX + b"x" * (lf.MAX_BYTES - len(KDBX) + 1), headers={"if-none-match": "*"})
    assert status == 413 and "4.5 MB" in out["error"]


# ---- task 6: the new-vault template — terraform/template.json, uploaded to s3://<bucket>/config/template.json ----

def test_template_is_the_one_in_the_repository(fake_s3):
    """The repository's template (what terraform apply uploads) is what the API serves."""
    with open(os.path.join(os.path.dirname(__file__), "..", "terraform", "template.json"), encoding="utf-8") as f:
        repo = json.load(f)
    assert repo["kdf"] == {"memory_mib": 128, "parallelism": 2, "unlock_ms": 1500} and repo["history_max_items"] == 0
    fake_s3.put_object(Bucket="b", Key="config/template.json", Body=json.dumps(repo).encode())
    status, out, _ = call("GET", "/api/template")
    assert status == 200 and out["template"] == repo and out["source"] == "s3:config/template.json"


def test_a_missing_or_broken_template_says_what_to_do(fake_s3):
    status, out, _ = call("GET", "/api/template")
    assert status == 500 and "terraform apply" in out["error"]
    fake_s3.put_object(Bucket="b", Key="config/template.json", Body=b"{not json")
    status, out, _ = call("GET", "/api/template")
    assert status == 500 and "terraform/template.json" in out["error"]


# ---- move a vault file to another folder (S3 has no rename: write the copy, then delete the original) ----

def move(path, etag, folder, auth=AUTH):
    return call("POST", "/api/move", json.dumps({"path": path, "etag": etag, "folder": folder}).encode(), auth=auth)


def test_move_a_vault_to_another_folder(fake_s3, monkeypatch):
    a = as_user(monkeypatch, "alice")
    etag = call("PUT", vault("库1"), KDBX, auth=a, headers={"if-none-match": "*"})[1]["etag"]
    status, out, _ = move("keepass/库1.kdbx", etag, "team", auth=a)
    assert status == 200 and out["path"] == "keepass/team/库1.kdbx"
    assert call("GET", vault("库1"), auth=a)[0] == 404                                   # gone from the top level
    assert call("GET", file("team", "库1"), auth=a)[1] == KDBX                           # same bytes in team/
    assert fake_s3._current("keepass/team/库1.kdbx")["meta"]["owner"] == "alice"         # the owner moves along
    recs = call("GET", "/api/audit", auth=a, query={"path": "keepass/team/库1.kdbx"})[1]["records"]
    assert [r["from"] for r in recs if r["action"] == "move"] == ["keepass/库1.kdbx"]   # newest is the read just above
    status, out, _ = move("keepass/team/库1.kdbx", out["etag"], "", auth=a)              # and back to the top level
    assert status == 200 and out["path"] == "keepass/库1.kdbx"


def test_move_never_overwrites_and_never_loses(fake_s3):
    e1 = create("库1")
    call("PUT", file("team", "库1"), KDBX + b"other", headers={"if-none-match": "*"})
    status, out, _ = move("keepass/库1.kdbx", e1, "team")
    assert status == 412 and "already" in out["error"]
    assert call("GET", vault("库1"))[1] == KDBX and call("GET", file("team", "库1"))[1] == KDBX + b"other"
    assert move("keepass/库1.kdbx", '"stale"', "x")[0] == 412                             # changed since it was listed
    assert move("keepass/库1.kdbx", e1, "")[0] == 400                                    # already there
    assert move("keepass/库1.kdbx", e1, "../x")[0] == 400
    assert move("keepass/nope.kdbx", e1, "x")[0] == 404
