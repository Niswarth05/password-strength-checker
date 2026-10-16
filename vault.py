"""Encrypted password vault.

The whole vault (every entry) is stored in ONE encrypted file. The encryption
key is derived from the master password with scrypt, so the master password is
never saved anywhere. Fernet (AES-128-CBC + HMAC) encrypts and authenticates
the data: a wrong master password simply fails to decrypt.

Backups use the same recipe, but with their own password and their own salt.
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
BACKUP_FORMAT = "vault-backup"

# scrypt cost settings (stored in every vault/backup file so they can be raised later)
KDF_N, KDF_R, KDF_P = 2**15, 8, 1

# A file we did not write ourselves must not be able to ask for absurd amounts
# of memory, so stored scrypt settings are only accepted inside these bounds.
KDF_N_RANGE = (2**10, 2**17)
KDF_R_MAX = 8
KDF_P_MAX = 4

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


class WrongPassword(VaultError):
    """The password did not decrypt the file (or the file is damaged)."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _derive_key(password, salt, n, r, p):
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


# ----- reading and writing encrypted blobs ------------------------------------

def _check_kdf(kdf):
    """Return (n, r, p) if the stored scrypt settings are sane, else raise."""
    try:
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    except (KeyError, TypeError, ValueError):
        raise VaultError("This file is not a valid Vault file.")
    power_of_two = n > 0 and n & (n - 1) == 0
    if not (power_of_two and KDF_N_RANGE[0] <= n <= KDF_N_RANGE[1]
            and 1 <= r <= KDF_R_MAX and 1 <= p <= KDF_P_MAX):
        raise VaultError("This file uses encryption settings Vault does not accept.")
    return n, r, p


def _parse_blob(text):
    try:
        blob = json.loads(text)
    except ValueError:
        raise VaultError("This is not a valid Vault file.")
    if not isinstance(blob, dict):
        raise VaultError("This is not a valid Vault file.")
    return blob


def _open_blob(blob, password):
    """Decrypt a vault/backup blob. Returns (entries, key, salt, kdf)."""
    try:
        salt = base64.b64decode(blob["salt"], validate=True)
        token = blob["data"].encode("ascii")
        kdf = _check_kdf(blob["kdf"])
    except (KeyError, TypeError, ValueError, AttributeError):
        raise VaultError("This is not a valid Vault file.")

    key = _derive_key(password, salt, *kdf)
    try:
        plain = Fernet(key).decrypt(token)
    except InvalidToken:
        raise WrongPassword("Wrong password.")

    try:
        entries = json.loads(plain)["entries"]
        if not isinstance(entries, list):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        raise VaultError("This file's contents are damaged.")
    return entries, key, salt, kdf


def _seal(entries, key, salt, kdf):
    """Encrypt entries into a JSON-ready blob."""
    payload = json.dumps({"entries": entries}).encode("utf-8")
    return {
        "version": 2,
        "kdf": {"n": kdf[0], "r": kdf[1], "p": kdf[2]},
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": Fernet(key).encrypt(payload).decode("ascii"),
    }


def _valid_timestamp(value):
    if isinstance(value, str) and len(value) <= 40:
        try:
            datetime.fromisoformat(value)
            return value
        except ValueError:
            pass
    return _now()


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

    # ----- guessing protection -----------------------------------------

    def _check_cooldown(self):
        wait = self._blocked_until - time.monotonic()
        if wait > 0:
            raise VaultError(
                f"Too many wrong attempts. Try again in {int(wait) + 1} seconds."
            )

    def _register_failure(self):
        self._failed += 1
        if self._failed >= MAX_FAILED_ATTEMPTS:
            self._failed = 0
            self._blocked_until = time.monotonic() + COOLDOWN_SECONDS

    def _verify_master(self, master):
        """Re-check the master password of an already unlocked vault."""
        self._check_cooldown()
        key = _derive_key(master, self._salt, *self._kdf)
        if not secrets.compare_digest(key, self._key):
            self._register_failure()
            raise VaultError("Wrong master password.")
        self._failed = 0

    @staticmethod
    def _check_new_password(password, label):
        if len(password) < MIN_MASTER_LENGTH:
            raise VaultError(
                f"{label} must be at least {MIN_MASTER_LENGTH} characters."
            )

    # ----- create / unlock ---------------------------------------------

    def create(self, master):
        with self._lock:
            if self.exists():
                raise VaultError("A vault already exists.")
            self._check_new_password(master, "Master password")
            self._salt = secrets.token_bytes(16)
            self._kdf = (KDF_N, KDF_R, KDF_P)
            self._key = _derive_key(master, self._salt, *self._kdf)
            self._entries = {}
            self._save()
            self.touch()

    def unlock(self, master):
        with self._lock:
            self._check_cooldown()
            if not self.exists():
                raise VaultError("No vault found. Create one first.")

            with open(self.path, "r", encoding="utf-8") as f:
                blob = _parse_blob(f.read())
            try:
                entries, key, salt, kdf = _open_blob(blob, master)
            except WrongPassword:
                self._register_failure()
                raise VaultError("Wrong master password.")

            self._failed = 0
            self._salt, self._kdf, self._key = salt, kdf, key
            self._entries = {e["id"]: e for e in entries}
            self.touch()

    # ----- change master password --------------------------------------

    def change_master(self, old, new):
        with self._lock:
            self._require_unlocked()
            self._verify_master(old)
            self._check_new_password(new, "Master password")
            if new == old:
                raise VaultError("The new master password must be different.")

            previous = (self._salt, self._kdf, self._key)
            salt = secrets.token_bytes(16)
            kdf = (KDF_N, KDF_R, KDF_P)
            self._salt, self._kdf = salt, kdf
            self._key = _derive_key(new, salt, *kdf)
            try:
                self._save()
            except BaseException:
                self._salt, self._kdf, self._key = previous  # file is unchanged
                raise
            self.touch()

    # ----- backups -----------------------------------------------------

    def export_backup(self, master, backup_password):
        """Return the text of an encrypted backup of every entry."""
        with self._lock:
            self._require_unlocked()
            self._verify_master(master)
            self._check_new_password(backup_password, "Backup password")

            salt = secrets.token_bytes(16)
            kdf = (KDF_N, KDF_R, KDF_P)
            key = _derive_key(backup_password, salt, *kdf)
            blob = _seal(list(self._entries.values()), key, salt, kdf)
            blob = {"format": BACKUP_FORMAT, "created": _now(), **blob}
            return json.dumps(blob)

    def import_backup(self, text, password):
        """Add the entries of a backup. Never overwrites or removes anything."""
        with self._lock:
            self._require_unlocked()
            blob = _parse_blob(text)
            if blob.get("format") != BACKUP_FORMAT:
                raise VaultError("This is not a Vault backup file.")
            try:
                entries, _, _, _ = _open_blob(blob, password)
            except WrongPassword:
                raise VaultError("Wrong backup password, or the file is damaged.")

            def identity(name, username):
                return (name.strip().lower(), username.strip().lower())

            known = {identity(e["name"], e.get("username", ""))
                     for e in self._entries.values()}
            added, skipped = [], 0
            for raw in entries:
                if not isinstance(raw, dict):
                    raise VaultError("The backup contains an invalid entry.")
                try:
                    clean = self._clean(raw)
                except VaultError as err:
                    raise VaultError(f"The backup contains an invalid entry. {err}")
                key = identity(clean["name"], clean.get("username", ""))
                if key in known:
                    skipped += 1
                    continue
                known.add(key)
                added.append({
                    "id": uuid.uuid4().hex,
                    "username": "",
                    "url": "",
                    "notes": "",
                    **clean,
                    "created": _valid_timestamp(raw.get("created")),
                    "updated": _valid_timestamp(raw.get("updated")),
                })

            for entry in added:
                self._entries[entry["id"]] = entry
            if added:
                try:
                    self._save()
                except BaseException:
                    for entry in added:
                        del self._entries[entry["id"]]
                    raise
            return {"added": len(added), "skipped": skipped}

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
        blob = _seal(list(self._entries.values()), self._key, self._salt, self._kdf)
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
