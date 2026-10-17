import urllib.error

import pytest

import breach

# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (a published test vector)
PREFIX = "5BAA6"
SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_hash_parts_split_the_sha1_hash():
    assert breach.hash_parts("password") == (PREFIX, SUFFIX)


def test_only_the_five_character_prefix_is_sent():
    sent = []

    def fake_fetch(prefix):
        sent.append(prefix)
        return ""

    breach.check_password("password", fetch=fake_fetch)
    assert sent == [PREFIX]
    assert "password" not in sent[0].lower() and SUFFIX not in sent[0]


def test_found_password_reports_its_count():
    reply = f"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{SUFFIX}:9545824\r\nFFFF0000FFFF0000FFFF0000FFFF0000FFF:2"
    result = breach.check_password("password", fetch=lambda prefix: reply)
    assert result == {"found": True, "count": 9545824}


def test_matching_ignores_letter_case():
    result = breach.check_password("password", fetch=lambda prefix: f"{SUFFIX.lower()}:7")
    assert result == {"found": True, "count": 7}


def test_padding_lines_with_zero_count_do_not_count_as_found():
    result = breach.check_password("password", fetch=lambda prefix: f"{SUFFIX}:0")
    assert result == {"found": False, "count": 0}


def test_password_not_in_reply_is_not_found():
    reply = "0018A45C4D1DEF81644B54AB7F969B88D65:3\nnot a valid line\n:5\nABC:notanumber"
    assert breach.check_password("password", fetch=lambda prefix: reply) == {"found": False, "count": 0}


def test_network_failure_becomes_a_friendly_error(monkeypatch):
    def boom(*args, **kwargs):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr(breach.urllib.request, "urlopen", boom)
    with pytest.raises(breach.BreachCheckError, match="Couldn't reach"):
        breach.fetch_range(PREFIX)


def test_rate_limit_gets_its_own_message(monkeypatch):
    def busy(*args, **kwargs):
        raise urllib.error.HTTPError("https://x", 429, "Too Many Requests", {}, None)

    monkeypatch.setattr(breach.urllib.request, "urlopen", busy)
    with pytest.raises(breach.BreachCheckError, match="busy"):
        breach.fetch_range(PREFIX)
