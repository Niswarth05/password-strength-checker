"""Password strength checker (a side tool of the password manager).

Rates a password with zxcvbn, explains what is wrong, and - if it is weak -
builds a stronger password *based on* the one that was entered.

zxcvbn does not just count character types. It looks for the things attackers
really try first: common passwords, dictionary words, names, dates, keyboard
patterns (qwerty), sequences (abcd, 1234), repeats and "l33t" swaps (p@ssw0rd),
then estimates how many guesses it would take.
"""

import secrets
import string
from bisect import bisect_right

from zxcvbn import zxcvbn

LEVELS = ["VERY WEAK", "WEAK", "MEDIUM", "STRONG", "VERY STRONG"]

# log10(guesses) needed to reach each level. At 10,000 guesses per second
# (an attacker against a slow hash such as bcrypt or scrypt):
#   10^8  guesses = about 3 hours      10^12 guesses = about 3 years
#   10^10 guesses = about 12 days      10^14 guesses = about 300 years
LEVEL_THRESHOLDS = (8, 10, 12, 14)

# Levels that trigger a generated suggestion. Add "MEDIUM" for a wider net.
WEAK_LEVELS = {"VERY WEAK", "WEAK"}

# Generated suggestions must reach at least this level (3 = STRONG).
MIN_SUGGESTION_LEVEL = 3

# zxcvbn gets slow on very long input, so only the first characters are rated.
MAX_CHECK_LENGTH = 72

SYMBOLS = string.punctuation
LEET = {"a": "@4", "e": "3", "i": "!1", "o": "0", "s": "$5", "t": "7", "l": "1"}

_rng = secrets.SystemRandom()


def analyze(pw, user_inputs=None):
    """Rate a password.

    user_inputs: extra words (an entry's name, username...) that attackers who
    know you would try. A password that contains them is rated lower.
    """
    context = [s.lower() for s in (user_inputs or []) if isinstance(s, str) and s.strip()]
    z = zxcvbn(pw[:MAX_CHECK_LENGTH], user_inputs=context[:10])
    level = bisect_right(LEVEL_THRESHOLDS, z["guesses_log10"])

    checks = {
        "At least 12 characters": len(pw) >= 12,
        "Uppercase letter": any(c.isupper() for c in pw),
        "Lowercase letter": any(c.islower() for c in pw),
        "Number": any(c.isdigit() for c in pw),
        "Special character": any(not c.isalnum() for c in pw),
    }

    issues = []
    if z["feedback"]["warning"]:
        issues.append(z["feedback"]["warning"])
    issues.extend(z["feedback"]["suggestions"])

    # Composition tips only matter while the password is not yet strong:
    # a long passphrase with no digits can be perfectly safe.
    if level < 3:
        if not checks["At least 12 characters"]:
            issues.append("Use at least 12 characters. Length matters most.")
        if not checks["Uppercase letter"]:
            issues.append("Add an uppercase letter.")
        if not checks["Lowercase letter"]:
            issues.append("Add a lowercase letter.")
        if not checks["Number"]:
            issues.append("Add a number.")
        if not checks["Special character"]:
            issues.append("Add a special character.")
        if not issues:
            issues.append(
                "It can be guessed too quickly. "
                "Try a longer passphrase of unrelated words."
            )

    return {
        "level": level,
        "strength": LEVELS[level],
        "checks": checks,
        "issues": issues,
        "crack_time": z["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
    }


# ----- generating passwords ------------------------------------------------

def generate_password(length=16):
    """Fully random password (no relation to anything the user typed)."""
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS]
    chars = [secrets.choice(g) for g in groups]
    pool = "".join(groups)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    _rng.shuffle(chars)
    return "".join(chars)


def _derive_once(pw, min_length):
    base = "".join(pw.split())[:24] or generate_password(min_length)
    chars = []
    first_letter_done = False
    for ch in base:
        if ch.isalpha():
            if not first_letter_done:
                ch = ch.upper()
                first_letter_done = True
            elif _rng.random() < 0.3:
                ch = ch.swapcase()
            if ch.lower() in LEET and _rng.random() < 0.4:
                ch = secrets.choice(LEET[ch.lower()])
        chars.append(ch)

    # Pad with random characters until the password is long enough.
    pool = string.ascii_letters + string.digits + SYMBOLS
    while len(chars) < min_length:
        chars.append(secrets.choice(pool))

    # Make sure every character class is present.
    needs = {
        string.ascii_lowercase: not any(c.islower() for c in chars),
        string.ascii_uppercase: not any(c.isupper() for c in chars),
        string.digits: not any(c.isdigit() for c in chars),
        SYMBOLS: not any(not c.isalnum() for c in chars),
    }
    for group, missing in needs.items():
        if missing:
            chars.insert(_rng.randrange(len(chars) + 1), secrets.choice(group))
    return "".join(chars)


def suggest_from(pw, min_length=18, user_inputs=None):
    """A stronger password that still resembles `pw` (easier to remember).

    Because it is based on the original, it is less safe than a fully random
    password - the UI offers a random one as well.
    """
    for _ in range(50):
        candidate = _derive_once(pw, min_length)
        if (
            analyze(candidate, user_inputs)["level"] >= MIN_SUGGESTION_LEVEL
            and candidate.lower() != pw.lower()
        ):
            return candidate
    return generate_password(min_length)


def review(pw, user_inputs=None):
    """Everything the strength-check dialog needs."""
    result = analyze(pw, user_inputs)
    weak = result["strength"] in WEAK_LEVELS
    result["weak"] = weak
    result["suggestion"] = None
    if weak:
        suggestion = suggest_from(pw, user_inputs=user_inputs)
        result["suggestion"] = {
            "password": suggestion,
            "strength": analyze(suggestion, user_inputs)["strength"],
        }
    return result
