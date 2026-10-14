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
