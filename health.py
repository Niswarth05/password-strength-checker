"""Password health scan.

Looks at every saved password and reports which ones need attention:

- weak: rated Very weak or Weak by the strength checker (zxcvbn)
- reused: the exact same password is saved on more than one entry

The scan runs entirely on this computer. The report it returns holds entry
names and ratings only, never a password. Breach status is not part of the
scan: it needs the internet, so it stays a separate, opt-in action (breach.py).
"""

import hashlib
import hmac
import os

import strength

MAX_ISSUES_SHOWN = 2


def _username_word(entry):
    return entry.get("username", "").split("@")[0]


def scan(entries):
    """Scan full entries (with passwords) and return a report without passwords."""
    # Passwords are grouped by a keyed fingerprint instead of by their text, using a
    # random key that exists only for this call. Fingerprints never leave this function.
    key = os.urandom(32)
    groups = {}
    report = []

    for entry in sorted(entries, key=lambda e: e["name"].lower()):
        password = entry["password"]
        analysis = strength.analyze(password, [entry["name"], _username_word(entry)])
        weak = analysis["strength"] in strength.WEAK_LEVELS
        fingerprint = hmac.new(key, password.encode("utf-8"), hashlib.sha256).digest()
        groups.setdefault(fingerprint, []).append(entry["id"])
        report.append({
            "id": entry["id"],
            "name": entry["name"],
            "username": entry.get("username", ""),
            "strength": analysis["strength"],
            "weak": weak,
            "issues": analysis["issues"][:MAX_ISSUES_SHOWN] if weak else [],
            "fingerprint": fingerprint,
        })

    names = {item["id"]: item["name"] for item in report}
    reused_groups = [ids for ids in groups.values() if len(ids) > 1]
    group_of = {entry_id: ids for ids in reused_groups for entry_id in ids}

    for item in report:
        ids = group_of.get(item["id"])
        item["reused"] = ids is not None
        item["reused_with"] = [names[i] for i in ids if i != item["id"]] if ids else []
        del item["fingerprint"]

    return {
        "total": len(report),
        "weak": sum(item["weak"] for item in report),
        "reused": sum(item["reused"] for item in report),
        "reused_groups": len(reused_groups),
        "entries": report,
    }
