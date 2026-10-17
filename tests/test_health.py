import json

import health
import strength


def entry(entry_id, name, password, username=""):
    return {"id": entry_id, "name": name, "username": username, "password": password}


STRONG_A = "zq7-Vh2!kMw-unique-phrase-4417"
STRONG_B = "violet-Anchor-9033-lantern-quartz"


def by_id(report):
    return {item["id"]: item for item in report["entries"]}


def test_weak_password_is_flagged_and_strong_is_not():
    report = health.scan([entry("1", "Old forum", "password"), entry("2", "Bank", STRONG_A)])
    items = by_id(report)
    assert items["1"]["weak"] and items["1"]["strength"] in strength.WEAK_LEVELS
    assert items["1"]["issues"]
    assert not items["2"]["weak"] and items["2"]["issues"] == []
    assert report["total"] == 2 and report["weak"] == 1


def test_reused_passwords_are_grouped_and_name_each_other():
    report = health.scan([
        entry("1", "GitHub", STRONG_A),
        entry("2", "College email", STRONG_A),
        entry("3", "Gmail", STRONG_A),
        entry("4", "Bank", STRONG_B),
    ])
    items = by_id(report)
    assert report["reused"] == 3 and report["reused_groups"] == 1
    assert items["1"]["reused_with"] == ["College email", "Gmail"]
    assert not items["4"]["reused"] and items["4"]["reused_with"] == []


def test_two_separate_reuse_groups():
    report = health.scan([
        entry("1", "A", STRONG_A), entry("2", "B", STRONG_A),
        entry("3", "C", STRONG_B), entry("4", "D", STRONG_B),
    ])
    assert report["reused"] == 4 and report["reused_groups"] == 2


def test_reuse_is_exact_match_only():
    report = health.scan([entry("1", "A", STRONG_A), entry("2", "B", STRONG_A.upper())])
    assert report["reused"] == 0


def test_report_never_contains_a_password():
    passwords = ["sunshine1", STRONG_A, STRONG_B, "Summer2024!!"]
    report = health.scan([entry(str(i), f"Site {i}", pw) for i, pw in enumerate(passwords)])
    text = json.dumps(report)
    for pw in passwords:
        assert pw not in text
    assert all("fingerprint" not in item and "password" not in item for item in report["entries"])


def test_entry_name_counts_as_a_guessable_word():
    report = health.scan([entry("1", "zxqvkjwplm", "zxqvkjwplm")])
    assert report["entries"][0]["weak"]


def test_empty_vault_and_ordering():
    assert health.scan([]) == {"total": 0, "weak": 0, "reused": 0, "reused_groups": 0, "entries": []}
    report = health.scan([entry("1", "zeta", STRONG_A), entry("2", "Alpha", STRONG_B)])
    assert [item["name"] for item in report["entries"]] == ["Alpha", "zeta"]
