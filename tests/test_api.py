import pytest

import app as app_module
import vault as vault_module
from vault import Vault

MASTER = "correct horse battery"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(vault_module, "KDF_N", 2**12)
    app_module.vault = Vault(str(tmp_path / "vault.enc"))
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def call(client, method, path, body=None):
    return getattr(client, method)(path, json=body, base_url="http://127.0.0.1:5000")


def test_full_flow(client):
    assert call(client, "get", "/api/status").json == {"exists": False, "unlocked": False}
    assert call(client, "post", "/api/setup", {"master": MASTER}).status_code == 200

    created = call(client, "post", "/api/entries",
                   {"name": "GitHub", "username": "me", "password": "pw!1"})
    entry_id = created.json["entry"]["id"]
    assert "password" not in created.json["entry"]

    assert call(client, "get", "/api/entries?q=git").json["entries"][0]["name"] == "GitHub"
    assert call(client, "get", f"/api/entries/{entry_id}/password").json["password"] == "pw!1"

    assert call(client, "delete", f"/api/entries/{entry_id}").status_code == 200
    assert call(client, "get", "/api/entries").json["entries"] == []


def test_locked_vault_blocks_entries(client):
    call(client, "post", "/api/setup", {"master": MASTER})
    call(client, "post", "/api/lock", {})
    res = call(client, "get", "/api/entries")
    assert res.status_code == 401 and res.json["locked"]


def test_wrong_master_password(client):
    call(client, "post", "/api/setup", {"master": MASTER})
    call(client, "post", "/api/lock", {})
    res = call(client, "post", "/api/unlock", {"master": "nope nope nope"})
    assert res.status_code == 400 and "Wrong" in res.json["error"]


def test_foreign_host_is_rejected(client):
    res = client.get("/api/status", base_url="http://evil.example:5000")
    assert res.status_code == 403


def test_non_json_body_is_rejected(client):
    res = client.post("/api/check", data="password=abc",
                      content_type="text/plain", base_url="http://127.0.0.1:5000")
    assert res.status_code == 400


def test_check_endpoint_suggests_for_weak(client):
    res = call(client, "post", "/api/check", {"password": "sunshine1"}).json
    assert res["weak"] and res["suggestion"]["password"]
    assert call(client, "post", "/api/check", {"password": ""}).status_code == 400


def test_security_headers(client):
    res = call(client, "get", "/")
    assert res.status_code == 200
    assert "script-src 'self'" in res.headers["Content-Security-Policy"]


# ----- v2.1: change master password, backups, strength context --------------

def test_change_master_endpoint(client):
    call(client, "post", "/api/setup", {"master": MASTER})
    new = "another long passphrase here"
    res = call(client, "post", "/api/change-master", {"old": MASTER, "new": new})
    assert res.status_code == 200
    call(client, "post", "/api/lock", {})
    assert call(client, "post", "/api/unlock", {"master": MASTER}).status_code == 400
    assert call(client, "post", "/api/unlock", {"master": new}).status_code == 200


def test_weak_master_passwords_are_refused(client):
    res = call(client, "post", "/api/setup", {"master": "passwordpassword"})
    assert res.status_code == 400 and "too easy to guess" in res.json["error"]
    assert call(client, "get", "/api/status").json["exists"] is False

    call(client, "post", "/api/setup", {"master": MASTER})
    res = call(client, "post", "/api/change-master", {"old": MASTER, "new": "123456789012"})
    assert res.status_code == 400 and "too easy to guess" in res.json["error"]


def test_export_and_import_endpoints(client):
    call(client, "post", "/api/setup", {"master": MASTER})
    call(client, "post", "/api/entries", {"name": "GitHub", "username": "me", "password": "pw!1"})

    res = call(client, "post", "/api/export",
               {"master": MASTER, "backup_password": "backup password phrase"})
    assert res.status_code == 200
    assert "attachment" in res.headers["Content-Disposition"]
    backup = res.get_data(as_text=True)
    assert "GitHub" not in backup

    entry_id = call(client, "get", "/api/entries").json["entries"][0]["id"]
    call(client, "delete", f"/api/entries/{entry_id}")
    res = call(client, "post", "/api/import",
               {"backup": backup, "password": "backup password phrase"})
    assert res.json == {"added": 1, "skipped": 0}
    assert call(client, "get", "/api/entries").json["entries"][0]["name"] == "GitHub"


def test_backup_endpoints_require_unlocked_vault(client):
    call(client, "post", "/api/setup", {"master": MASTER})
    call(client, "post", "/api/lock", {})
    for path, body in (("/api/export", {"master": MASTER, "backup_password": "x" * 12}),
                       ("/api/import", {"backup": "{}", "password": "x"}),
                       ("/api/change-master", {"old": MASTER, "new": "y" * 14})):
        assert call(client, "post", path, body).status_code == 401


def test_check_endpoint_accepts_context_words(client):
    body = {"password": "zxqvkjwplm", "context": ["zxqvkjwplm"]}
    res = call(client, "post", "/api/check", body).json
    assert res["weak"] and res["suggestion"]
    # junk context must not crash it
    assert call(client, "post", "/api/check", {"password": "abc", "context": "nope"}).status_code == 200
