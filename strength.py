"""Password strength checker (a side tool of the password manager).

Checks a password, explains what is wrong, and - if it is weak - builds a
stronger password *based on* the one that was entered.
"""

import math
import re
import secrets
import string

COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "1234567", "12345678",
    "123456789", "1234567890", "qwerty", "qwerty123", "qwertyuiop", "abc123",
    "admin", "admin123", "letmein", "welcome", "welcome1", "iloveyou",
    "monkey", "dragon", "football", "baseball", "master", "login", "princess",
    "sunshine", "shadow", "superman", "trustno1", "passw0rd", "p@ssw0rd",
    "p@ssword", "changeme", "111111", "000000", "123123", "1q2w3e4r",
    "zaq12wsx", "root", "toor", "kali", "ubuntu",
}

# Words that make a password weak even when something is added around them.
COMMON_FRAGMENTS = ("password", "qwerty", "admin", "letmein", "welcome", "iloveyou")

KEYBOARD_RUNS = ("qwerty", "asdfgh", "zxcvbn", "1qaz2wsx")

SYMBOLS = string.punctuation
LEET = {"a": "@4", "e": "3", "i": "!1", "o": "0", "s": "$5", "t": "7", "l": "1"}

# Strength levels that trigger a generated suggestion.
# Add "MEDIUM" here if you also want suggestions for medium passwords.
WEAK_LEVELS = {"VERY WEAK", "WEAK"}

LEVELS = ["VERY WEAK", "WEAK", "MEDIUM", "STRONG", "VERY STRONG"]
_rng = secrets.SystemRandom()


# ----- individual checks ---------------------------------------------------

def _has_sequence(pw, length=4):
    """True for runs like abcd, 4321 or a keyboard row such as qwerty."""
    low = pw.lower()
    if any(run in low for run in KEYBOARD_RUNS):
        return True
    for i in range(len(low) - length + 1):
        chunk = low[i:i + length]
        steps = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(length - 1)}
        if steps in ({1}, {-1}) and chunk.isalnum():
            return True
    return False


def _has_repeats(pw, count=3):
    return re.search(r"(.)\1{%d,}" % (count - 1), pw) is not None


def _looks_predictable(pw):
    """A word (maybe capitalised) + digits + a few symbols, e.g. Summer2024!!"""
    return re.fullmatch(r"[A-Za-z]{3,}\d{1,4}[^A-Za-z0-9]{0,3}", pw) is not None


def calculate_entropy(pw):
    """Theoretical maximum entropy in bits, assuming random characters."""
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 32
    return len(pw) * math.log2(pool) if pool else 0.0


def analyze(pw):
    checks = {
        "At least 12 characters": len(pw) >= 12,
        "Uppercase letter": any(c.isupper() for c in pw),
        "Lowercase letter": any(c.islower() for c in pw),
        "Number": any(c.isdigit() for c in pw),
        "Special character": any(not c.isalnum() for c in pw),
    }
    score = sum(checks.values())
    low = pw.lower()

    is_common = low in COMMON_PASSWORDS
    has_fragment = not is_common and any(f in low for f in COMMON_FRAGMENTS)
    has_sequence = _has_sequence(pw)
    has_repeats = _has_repeats(pw)
    predictable = _looks_predictable(pw)
    entropy = calculate_entropy(pw)

    # Start from the checklist score, then cap it for known-bad patterns.
    level = min(max(score - 1, 0), 4)
    if entropy < 40:
        level = min(level, 1)
    elif entropy < 60:
        level = min(level, 2)
    if has_fragment or has_sequence or has_repeats:
        level = min(level, 1)
    if predictable:
        level = min(level, 2)
    if is_common:
        level = 0

    issues = []
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
    if is_common:
        issues.append("This is one of the most commonly used passwords.")
    if has_fragment:
        issues.append("It contains a very common word that attackers try first.")
    if has_sequence:
        issues.append("It contains a sequence like abcd, 1234 or qwerty.")
    if has_repeats:
        issues.append("It repeats the same character three or more times in a row.")
    if predictable:
        issues.append("A word followed by numbers is one of the first patterns attackers try.")

    return {
        "strength": LEVELS[level],
        "score": score,
        "entropy": round(entropy, 1),
        "checks": checks,
        "issues": issues,
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


def suggest_from(pw, min_length=16):
    """A stronger password that still resembles `pw` (easier to remember).

    Because it is based on the original, it is less safe than a fully random
    password - the UI offers a random one as well.
    """
    for _ in range(50):
        candidate = _derive_once(pw, min_length)
        if (
            analyze(candidate)["strength"] not in WEAK_LEVELS
            and candidate.lower() != pw.lower()
        ):
            return candidate
    return generate_password(min_length)


def review(pw):
    """Everything the strength-check dialog needs."""
    result = analyze(pw)
    weak = result["strength"] in WEAK_LEVELS
    result["weak"] = weak
    result["suggestion"] = None
    if weak:
        suggestion = suggest_from(pw)
        result["suggestion"] = {
            "password": suggestion,
            "strength": analyze(suggestion)["strength"],
        }
    return result
