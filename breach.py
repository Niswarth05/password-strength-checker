"""Optional breach check using the Have I Been Pwned "range" API.

How it keeps your password private (k-anonymity):

1. The password is hashed with SHA-1 on this computer.
2. Only the FIRST 5 characters of that hash are sent to the service.
3. The service replies with every leaked hash that starts with those 5
   characters (hundreds of them, so yours is hidden among them).
4. This program looks for the rest of your hash in that list, locally.

Neither the password nor its full hash ever leaves this computer.
SHA-1 is used here only because the service requires it. It is not used to
protect anything stored in the vault.
"""

import hashlib
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"
TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 1_000_000


class BreachCheckError(Exception):
    """The lookup could not be completed. The message is safe to show."""


def hash_parts(password):
    """Split the SHA-1 hash into (prefix sent to the service, suffix kept here)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def fetch_range(prefix):
    """Ask the service for every hash suffix that starts with `prefix`."""
    request = urllib.request.Request(
        API_URL + prefix,
        headers={
            "Add-Padding": "true",  # pads replies so their size reveals nothing
            "User-Agent": "Vault-local-password-manager",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.read(MAX_RESPONSE_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        if err.code == 429:
            raise BreachCheckError("The breach service is busy. Wait a minute and try again.")
        raise BreachCheckError("The breach service returned an error. Try again later.")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise BreachCheckError(
            "Couldn't reach the breach database. Check your internet connection and try again."
        )


def count_in_response(text, suffix):
    """How many times `suffix` appears in a range reply ('SUFFIX:COUNT' lines)."""
    for line in text.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            try:
                return max(int(count), 0)  # padding lines report a count of 0
            except ValueError:
                return 0
    return 0


def check_password(password, fetch=None):
    """Return {"found": bool, "count": int} for a password."""
    fetch = fetch or fetch_range
    prefix, suffix = hash_parts(password)
    count = count_in_response(fetch(prefix), suffix)
    return {"found": count > 0, "count": count}
