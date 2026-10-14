"""Encrypted password vault.

The whole vault (every entry) is stored in ONE encrypted file. The encryption
key is derived from the master password with scrypt, so the master password is
never saved anywhere. Fernet (AES-128-CBC + HMAC) encrypts and authenticates
the data: a wrong master password simply fails to decrypt.
"""

import base64
import json
import os
import secrets
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT_FILE = os.environ.get("VAULT_FILE", "vault.enc")
AUTO_LOCK_SECONDS = 5 * 60
MIN_MASTER_LENGTH = 12

# scrypt cost settings (stored in the vault file so they can be raised later)
KDF_N, KDF_R, KDF_P = 2**15, 8, 1

FIELD_LIMITS = {
    "name": 100,
    "username": 200,
    "password": 500,
    "url": 300,
    "notes": 2000,
}

MAX_FAILED_ATTEMPTS = 5
COOLDOWN_SECONDS = 30


class VaultError(Exception):
    """An error whose message is safe to show to the user."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _derive_key(master, salt, n, r, p):
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(master.encode("utf-8")))


class Vault:
    def __init__(self, path=None):
        self.path = path or VAULT_FILE
        self._lock = threading.RLock()
        self._key = None
        self._salt = None
        self._kdf = (KDF_N, KDF_R, KDF_P)
        self._entries = {}
        self._last_activity = 0.0
        self._failed = 0
        self._blocked_until = 0.0

    # ----- state -------------------------------------------------------

    def exists(self):
        return os.path.exists(self.path)

    def is_unlocked(self):
        with self._lock:
            if self._key is None:
                return False
            if time.monotonic() - self._last_activity > AUTO_LOCK_SECONDS:
                self.lock()
                return False
            return True

    def touch(self):
        self._last_activity = time.monotonic()

    def lock(self):
        with self._lock:
            self._key = None
            self._salt = None
            self._entries = {}

    # ----- create / unlock ---------------------------------------------

    def create(self, master):
        with self._lock:
            if self.exists():
                raise VaultError("A vault already exists.")
            if len(master) < MIN_MASTER_LENGTH:
                raise VaultError(
                    f"Master password must be at least {MIN_MASTER_LENGTH} characters."
                )
            self._salt = secrets.token_bytes(16)
            self._kdf = (KDF_N, KDF_R, KDF_P)
            self._key = _derive_key(master, self._salt, *self._kdf)
            self._entries = {}
            self._save()
            self.touch()

    def unlock(self, master):
        with self._lock:
            wait = self._blocked_until - time.monotonic()
            if wait > 0:
                raise VaultError(
                    f"Too many wrong attempts. Try again in {int(wait) + 1} seconds."
                )
            if not self.exists():
                raise VaultError("No vault found. Create one first.")

            with open(self.path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            salt = base64.b64decode(blob["salt"])
            n, r, p = blob["kdf"]["n"], blob["kdf"]["r"], blob["kdf"]["p"]
            key = _derive_key(master, salt, n, r, p)

            try:
                plain = Fernet(key).decrypt(blob["data"].encode("ascii"))
            except InvalidToken:
                self._failed += 1
                if self._failed >= MAX_FAILED_ATTEMPTS:
                    self._failed = 0
                    self._blocked_until = time.monotonic() + COOLDOWN_SECONDS
                raise VaultError("Wrong master password.")

            self._failed = 0
            self._salt, self._kdf, self._key = salt, (n, r, p), key
            self._entries = {e["id"]: e for e in json.loads(plain)["entries"]}
            self.touch()

    # ----- entries -----------------------------------------------------

    def _require_unlocked(self):
        if not self.is_unlocked():
            raise VaultError("Vault is locked.")
        self.touch()

    @staticmethod
    def _clean(fields, partial=False):
        clean = {}
        for key, limit in FIELD_LIMITS.items():
            if key not in fields:
                if not partial and key in ("name", "password"):
                    raise VaultError(f"{key.capitalize()} is required.")
                continue
            value = fields[key]
            if not isinstance(value, str):
                raise VaultError(f"{key.capitalize()} must be text.")
            value = value.strip() if key != "password" else value
            if len(value) > limit:
                raise VaultError(f"{key.capitalize()} is too long (max {limit}).")
            if key in ("name", "password") and not value:
                raise VaultError(f"{key.capitalize()} is required.")
            clean[key] = value
        return clean

    @staticmethod
    def _public(entry):
        """Entry without its password (passwords are fetched on demand)."""
        return {k: v for k, v in entry.items() if k != "password"}

    def list(self, query=""):
        with self._lock:
            self._require_unlocked()
            q = query.strip().lower()
            items = []
            for e in self._entries.values():
                haystack = " ".join(
                    e.get(k, "") for k in ("name", "username", "url", "notes")
                ).lower()
                if q in haystack:
                    items.append(self._public(e))
            return sorted(items, key=lambda e: e["name"].lower())

    def get(self, entry_id):
        with self._lock:
            self._require_unlocked()
            entry = self._entries.get(entry_id)
            if entry is None:
                raise VaultError("Entry not found.")
            return dict(entry)

    def add(self, fields):
        with self._lock:
            self._require_unlocked()
            entry = {
                "id": uuid.uuid4().hex,
                "username": "",
                "url": "",
                "notes": "",
                **self._clean(fields),
                "created": _now(),
                "updated": _now(),
            }
            self._entries[entry["id"]] = entry
            self._save()
            return self._public(entry)

    def update(self, entry_id, fields):
        with self._lock:
            self._require_unlocked()
            entry = self._entries.get(entry_id)
            if entry is None:
                raise VaultError("Entry not found.")
            entry.update(self._clean(fields, partial=True))
            entry["updated"] = _now()
            self._save()
            return self._public(entry)

    def delete(self, entry_id):
        with self._lock:
            self._require_unlocked()
            if entry_id not in self._entries:
                raise VaultError("Entry not found.")
            del self._entries[entry_id]
            self._save()

    # ----- persistence -------------------------------------------------

    def _save(self):
        payload = json.dumps({"entries": list(self._entries.values())}).encode("utf-8")
        blob = {
            "version": 2,
            "kdf": {"n": self._kdf[0], "r": self._kdf[1], "p": self._kdf[2]},
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "data": Fernet(self._key).encrypt(payload).decode("ascii"),
        }
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(blob, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)  # atomic: never leaves a half-written vault
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
