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
