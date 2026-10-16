import json

import pytest

import vault as vault_module
from vault import Vault, VaultError

MASTER = "correct horse battery"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    # Cheaper scrypt so the tests run quickly. Real settings are unchanged.
    monkeypatch.setattr(vault_module, "KDF_N", 2**12)


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "vault.enc"))
    v.create(MASTER)
    return v


def test_add_search_delete(vault):
    a = vault.add({"name": "GitHub", "username": "me@x.com", "password": "pw-one"})
    vault.add({"name": "Gmail", "username": "me@gmail.com", "password": "pw-two"})

    assert [e["name"] for e in vault.list()] == ["GitHub", "Gmail"]
    assert [e["name"] for e in vault.list("gmail")] == ["Gmail"]
    assert vault.list("pw-one") == []  # passwords are never searched
    assert "password" not in vault.list()[0]

    vault.delete(a["id"])
    assert [e["name"] for e in vault.list()] == ["Gmail"]


def test_password_is_not_stored_in_plain_text(vault):
    vault.add({"name": "Bank", "password": "SuperSecret!123"})
    raw = open(vault.path, encoding="utf-8").read()
    assert "SuperSecret" not in raw and "Bank" not in raw


def test_unlock_roundtrip_and_wrong_password(vault):
    entry = vault.add({"name": "Site", "password": "abc123XYZ!"})
    vault.lock()
    with pytest.raises(VaultError):
        vault.list()

    with pytest.raises(VaultError, match="Wrong master password"):
        vault.unlock("not the master")
    vault.unlock(MASTER)
    assert vault.get(entry["id"])["password"] == "abc123XYZ!"


def test_update_entry(vault):
    entry = vault.add({"name": "Site", "password": "old"})
    vault.update(entry["id"], {"password": "new"})
    assert vault.get(entry["id"])["password"] == "new"
    assert vault.get(entry["id"])["name"] == "Site"


def test_validation(vault):
    with pytest.raises(VaultError):
        vault.add({"name": "", "password": "x"})
    with pytest.raises(VaultError):
        vault.add({"name": "Site"})
    with pytest.raises(VaultError):
        vault.add({"name": "x" * 500, "password": "x"})


def test_short_master_password_rejected(tmp_path):
    with pytest.raises(VaultError):
        Vault(str(tmp_path / "v.enc")).create("short")


def test_lockout_after_repeated_failures(vault):
    vault.lock()
    for _ in range(5):
        with pytest.raises(VaultError):
            vault.unlock("wrong")
    with pytest.raises(VaultError, match="Too many"):
        vault.unlock(MASTER)


def test_vault_file_is_valid_json_with_kdf_header(vault):
    blob = json.load(open(vault.path, encoding="utf-8"))
    assert blob["version"] == 2 and {"n", "r", "p"} <= set(blob["kdf"])


# ----- change master password ---------------------------------------------

NEW_MASTER = "a completely different phrase"


def test_change_master_password(vault):
    entry = vault.add({"name": "Site", "password": "keep-me-12345"})
    vault.change_master(MASTER, NEW_MASTER)
    vault.lock()

    with pytest.raises(VaultError, match="Wrong master password"):
        vault.unlock(MASTER)  # old password no longer works
    vault.unlock(NEW_MASTER)
    assert vault.get(entry["id"])["password"] == "keep-me-12345"


def test_change_master_rejects_wrong_old_short_new_and_same(vault):
    with pytest.raises(VaultError, match="Wrong master password"):
        vault.change_master("not the master", NEW_MASTER)
    with pytest.raises(VaultError, match="at least"):
        vault.change_master(MASTER, "short")
    with pytest.raises(VaultError, match="different"):
        vault.change_master(MASTER, MASTER)
    # vault still opens with the original password after all those failures
    vault.lock()
    vault.unlock(MASTER)


def test_change_master_uses_a_fresh_salt(vault):
    before = json.load(open(vault.path, encoding="utf-8"))["salt"]
    vault.change_master(MASTER, NEW_MASTER)
    assert json.load(open(vault.path, encoding="utf-8"))["salt"] != before


# ----- encrypted backups --------------------------------------------------

BACKUP_PW = "backup password phrase"


def fresh_vault(tmp_path, name):
    v = Vault(str(tmp_path / name))
    v.create(MASTER)
    return v


def test_backup_roundtrip_into_another_vault(vault, tmp_path):
    vault.add({"name": "GitHub", "username": "me", "password": "pw-github-1",
               "url": "https://github.com", "notes": "2FA on"})
    vault.add({"name": "Gmail", "password": "pw-gmail-22"})
    text = vault.export_backup(MASTER, BACKUP_PW)

    other = fresh_vault(tmp_path, "other.enc")
    assert other.import_backup(text, BACKUP_PW) == {"added": 2, "skipped": 0}
    names = [e["name"] for e in other.list()]
    assert names == ["GitHub", "Gmail"]
    github = next(e for e in other.list() if e["name"] == "GitHub")
    assert other.get(github["id"])["password"] == "pw-github-1"
    assert github["notes"] == "2FA on"


def test_backup_file_does_not_leak_anything(vault):
    vault.add({"name": "SecretBank", "username": "alice", "password": "Sup3rSecret!"})
    text = vault.export_backup(MASTER, BACKUP_PW)
    for leaked in ("SecretBank", "alice", "Sup3rSecret"):
        assert leaked not in text
    assert json.loads(text)["format"] == "vault-backup"


def test_import_skips_duplicates_and_never_overwrites(vault):
    vault.add({"name": "GitHub", "username": "me", "password": "original-pw"})
    text = vault.export_backup(MASTER, BACKUP_PW)
    entry = vault.list()[0]
    vault.update(entry["id"], {"password": "changed-later"})

    assert vault.import_backup(text, BACKUP_PW) == {"added": 0, "skipped": 1}
    assert vault.get(entry["id"])["password"] == "changed-later"
    assert len(vault.list()) == 1


def test_import_wrong_password_and_bad_files(vault):
    text = vault.export_backup(MASTER, BACKUP_PW)
    with pytest.raises(VaultError, match="Wrong backup password"):
        vault.import_backup(text, "not the backup password")
    with pytest.raises(VaultError, match="not a valid"):
        vault.import_backup("this is not json", BACKUP_PW)
    with pytest.raises(VaultError, match="not a Vault backup"):
        vault.import_backup(json.dumps({"hello": "world"}), BACKUP_PW)


def test_import_rejects_dangerous_kdf_settings(vault):
    blob = json.loads(vault.export_backup(MASTER, BACKUP_PW))
    blob["kdf"] = {"n": 2**30, "r": 8, "p": 1}  # would need gigabytes of memory
    with pytest.raises(VaultError, match="encryption settings"):
        vault.import_backup(json.dumps(blob), BACKUP_PW)


def test_export_needs_the_master_password_and_a_long_backup_password(vault):
    with pytest.raises(VaultError, match="Wrong master password"):
        vault.export_backup("not the master", BACKUP_PW)
    with pytest.raises(VaultError, match="Backup password must be at least"):
        vault.export_backup(MASTER, "short")


def test_backup_functions_need_an_unlocked_vault(vault):
    text = vault.export_backup(MASTER, BACKUP_PW)
    vault.lock()
    with pytest.raises(VaultError, match="locked"):
        vault.export_backup(MASTER, BACKUP_PW)
    with pytest.raises(VaultError, match="locked"):
        vault.import_backup(text, BACKUP_PW)
