"""s3keepass vaults vs KeePassXC: the compatibility matrix (the reference is keepassxc-cli in Docker).

One test = one feature; docstring "Category | Feature | note". The list only grows. Every file one side writes
is read by both sides (keepassxc-cli export / the web UI's vault code in Node) and the readings must be equal.

    python3 -m pytest tests -q                 # Docker left alone: live if the keepassxc container runs, else skipped
    python3 -m pytest tests -q --docker up     # build/start it, wait until healthy, test, keep running
    python3 -m pytest tests -q --docker run    # ... stop if all passed
    python3 -m pytest tests -q --docker down   # ... always stop
"""
import pytest

from kdbx_sides import Refused, expected

PW = "correct horse 电池 staple"
NEW_BIN = {"name": "Recycle Bin"}   # a vault s3keepass creates has an empty recycle bin from the start, as in KeePass

TREE = {
    "groups": [
        {"name": "工作", "groups": [
            {"name": "Cloud", "entries": [
                {"title": "aws", "username": "frank", "password": "p@ss 中文 ✓ \"quoted\" <xml>&", "url": "https://aws.amazon.com",
                 "notes": "line 1\nline 2\n\nline 4", "tags": ["cloud", "prod"],
                 "custom": [{"name": "MFA secret", "value": "JBSWY3DPEHPK3PXP", "protected": True},
                            {"name": "account", "value": "123456789012", "protected": False}]}]}],
         "entries": [{"title": "github", "username": "fz", "password": "gh-xyz", "url": "https://github.com"}]},
        {"name": "库2 (家)", "entries": [{"title": "wifi", "password": "  spaces kept  "}]},
    ],
    "entries": [{"title": "root entry", "username": "me@example.com", "password": ""}],
}


def test_vault_created_in_s3keepass_opens_in_keepassxc(kx, ours, box):
    """Data | a vault s3keepass creates opens in KeePassXC with the same groups and entries | nested groups, Unicode, multi-line notes, tags, protected attributes"""
    f = box.box("库1.kdbx")
    ours.create(f, PW, TREE)
    assert kx.tree(f, PW) == ours.tree(f, PW) == expected(TREE, "库1", NEW_BIN)


def test_vault_created_in_keepassxc_opens_in_s3keepass(kx, ours, box):
    """Data | a vault KeePassXC creates opens in s3keepass | KeePassXC's defaults (Argon2d, 1 s key derivation)"""
    f = box.box("kx.kdbx")
    kx.create(f, PW)
    kx.mkdir(f, PW, "工作")
    kx.mkdir(f, PW, "工作/Cloud")
    kx.add(f, PW, "工作/Cloud/aws", username="frank", url="https://aws.amazon.com", notes="line 1\nline 2", entry_password="p@ss 中文 ✓")
    kx.add(f, PW, "root entry", username="me@example.com")
    theirs = kx.tree(f, PW)
    assert ours.tree(f, PW) == theirs
    aws = theirs["groups"][0]["groups"][0]["entries"][0]
    assert (aws["username"], aws["password"], aws["notes"]) == ("frank", "p@ss 中文 ✓", "line 1\nline 2")


def test_edits_in_s3keepass_are_seen_by_keepassxc(kx, ours, box):
    """Data | add / edit / delete / rename in s3keepass, read by KeePassXC | on a KeePassXC-made file; an edit keeps the previous version in the entry's history; delete = recycle bin"""
    f, out = box.box("kx.kdbx"), box.box("edited.kdbx")
    kx.create(f, PW, decryption_time=200)
    kx.mkdir(f, PW, "Old")
    kx.add(f, PW, "Old/mail", username="a", entry_password="1")
    kx.add(f, PW, "gone", username="b")
    ours.edit(f, PW, [
        ["addGroup", "新组"],
        ["addEntry", "新组", {"title": "n1", "username": "u", "password": "pw", "url": "https://n1.example", "notes": "", "tags": ["x"], "custom": []}],
        ["editEntry", "Old/mail", {"username": "a2", "password": "2"}],
        ["renameGroup", "Old", "Mail"],
        ["removeEntry", "gone"],
    ], out)
    theirs = kx.tree(out, PW)
    assert ours.tree(out, PW) == theirs
    mail = next(g for g in theirs["groups"] if g["name"] == "Mail")["entries"][0]
    assert (mail["username"], mail["password"], mail["history"]) == ("a2", "2", 1)
    assert [g["name"] for g in theirs["groups"]] == ["Mail", "新组"]
    assert [e["title"] for e in theirs["entries"]] == []
    assert [e["title"] for e in theirs["recycleBin"]["entries"]] == ["gone"]


def test_edits_in_keepassxc_are_seen_by_s3keepass(kx, ours, box):
    """Data | add / edit / delete in KeePassXC, read by s3keepass | on an s3keepass-made file"""
    f = box.box("库1.kdbx")
    ours.create(f, PW, TREE)
    kx.mkdir(f, PW, "From KeePassXC")
    kx.add(f, PW, "From KeePassXC/new", username="kx", entry_password="kx-pw")
    kx.edit(f, PW, "工作/github", "-u", "fz-renamed")
    kx.rm(f, PW, "root entry")
    mine = ours.tree(f, PW)
    assert mine == kx.tree(f, PW)
    assert mine["recycleBin"]["entries"][0]["title"] == "root entry"
    github = next(g for g in mine["groups"] if g["name"] == "工作")["entries"][0]
    assert github["username"] == "fz-renamed" and github["history"] == 1


def test_groups_deleted_in_s3keepass_go_to_the_recycle_bin(kx, ours, box):
    """Data | delete a group in s3keepass | KeePassXC finds it, with its entries, in the recycle bin"""
    f, out = box.box("库1.kdbx"), box.box("out.kdbx")
    ours.create(f, PW, TREE)
    ours.edit(f, PW, [["removeGroup", "库2 (家)"]], out)
    theirs = kx.tree(out, PW)
    assert ours.tree(out, PW) == theirs
    assert [g["name"] for g in theirs["recycleBin"]["groups"]] == ["库2 (家)"]
    assert theirs["recycleBin"]["groups"][0]["entries"][0]["password"] == "  spaces kept  "


def test_attachments_survive_an_edit_in_s3keepass(kx, ours, box):
    """Data | attachments added in KeePassXC survive an edit in s3keepass | the UI shows them, KeePassXC opens them"""
    f, out = box.box("kx.kdbx"), box.box("out.kdbx")
    kx.create(f, PW, decryption_time=200)
    kx.add(f, PW, "server", username="root")
    with open(box.host("key.pem"), "w", encoding="utf-8") as fh:
        fh.write("-----BEGIN KEY-----\nabc 中文\n-----END KEY-----\n")
    kx.attachment_import(f, PW, "server", "key.pem", box.box("key.pem"))
    ours.edit(f, PW, [["editEntry", "server", {"username": "admin"}]], out)
    assert kx.attachment_export(out, PW, "server", "key.pem") == "-----BEGIN KEY-----\nabc 中文\n-----END KEY-----\n"
    assert kx.tree(out, PW)["entries"][0]["username"] == "admin"


def test_master_password_change(kx, ours, box):
    """Data | change the master password in s3keepass | KeePassXC opens the file with the new one only"""
    f, out = box.box("库1.kdbx"), box.box("out.kdbx")
    ours.create(f, PW, TREE)
    ours.edit(f, PW, [["setMasterKey", "new 新 password", None]], out)
    assert kx.tree(out, "new 新 password") == expected(TREE, "库1", NEW_BIN)
    with pytest.raises(Refused):
        kx.tree(out, PW)


def test_wrong_master_password_is_refused(kx, ours, box):
    """Errors | a wrong master password opens nothing | on both sides, for files from either side"""
    mine, theirs = box.box("mine.kdbx"), box.box("theirs.kdbx")
    ours.create(mine, PW, TREE)
    kx.create(theirs, PW, decryption_time=200)
    for f in (mine, theirs):
        for side in (kx, ours):
            with pytest.raises(Refused):
                side.tree(f, PW + "x")


def test_new_vault_format(kx, ours, box):
    """Metadata | new vaults: KDBX 4, AES-256, Argon2id 64 MiB x 8 | KeePassXC's defaults with Argon2id instead of Argon2d"""
    f = box.box("库1.kdbx")
    ours.create(f, PW, {})
    assert ours.info(f, PW) == {"version": 4, "cipher": "Aes", "kdf": "Argon2id", "memory": 64 * 1024 * 1024, "iterations": 8}
    info = kx.info(f, PW)
    assert "Argon2id" in info and "AES" in info, info


def test_key_file_vault_from_keepassxc_opens_in_s3keepass(kx, ours, box):
    """Data | password + key file: a KeePassXC vault opens in s3keepass | the .keyx KeePassXC generates; without it, refused"""
    f, key = box.box("kx.kdbx"), box.box("kx.keyx")
    kx.create(f, PW, key_file=key, decryption_time=200)
    kx.mkdir(f, PW, "工作", key)
    assert ours.tree(f, PW, key) == kx.tree(f, PW, key)
    with pytest.raises(Refused):
        ours.tree(f, PW)


def test_key_file_vault_from_s3keepass_opens_in_keepassxc(kx, ours, box):
    """Data | password + key file: an s3keepass vault opens in KeePassXC | the .keyx the UI's "New" button makes; without it, refused"""
    f, key = box.box("库1.kdbx"), box.box("库1.keyx")
    ours.new_key_file(key)
    ours.create(f, PW, TREE, key)
    assert kx.tree(f, PW, key) == ours.tree(f, PW, key) == expected(TREE, "库1", NEW_BIN)
    with pytest.raises(Refused):
        kx.tree(f, PW)


@pytest.mark.parametrize("name,content", [
    ("photo.jpg", bytes(range(256)) * 40),
    ("drawing.svg", '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>'.encode()),
], ids=["photo", "svg"])
def test_any_file_as_key_file(kx, ours, box, name, content):
    """Data | any file as the key file (a photo, an .svg …) | counted by its SHA-256 on both sides, as KeePassXC does"""
    f, key = box.box("库1.kdbx"), box.box(name)
    with open(box.host(name), "wb") as fh:
        fh.write(content)
    ours.create(f, PW, TREE, key)
    assert kx.tree(f, PW, key) == expected(TREE, "库1", NEW_BIN)


def test_add_and_remove_key_file(kx, ours, box):
    """Data | change the master key: add a key file in s3keepass, remove it again; add one in KeePassXC | each change seen by the other side"""
    f, with_key, without = box.box("库1.kdbx"), box.box("with.kdbx"), box.box("without.kdbx")
    key = box.box("new.keyx")
    ours.new_key_file(key)
    ours.create(f, PW, TREE)
    ours.edit(f, PW, [["setMasterKey", PW, key]], with_key)
    assert kx.tree(with_key, PW, key) == expected(TREE, "库1", NEW_BIN)
    with pytest.raises(Refused):
        kx.tree(with_key, PW)
    ours.edit(with_key, PW, [["setMasterKey", PW, None]], without, key=key)
    assert kx.tree(without, PW) == expected(TREE, "库1", NEW_BIN)
    kx_key = box.box("kx.keyx")
    kx.add_key_file(without, PW, kx_key)
    assert ours.tree(without, PW, kx_key) == expected(TREE, "库1", NEW_BIN)
    with pytest.raises(Refused):
        ours.tree(without, PW)
