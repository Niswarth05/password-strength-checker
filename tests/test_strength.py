import strength


def test_common_password_is_very_weak():
    assert strength.analyze("password")["strength"] == "VERY WEAK"


def test_patterns_are_weak():
    for pw in ("qwerty12345", "abcdefgh", "Summer2024!!", "P@ssw0rd2024"):
        assert strength.analyze(pw)["strength"] in strength.WEAK_LEVELS, pw


def test_random_password_is_very_strong():
    pw = strength.generate_password(20)
    assert len(pw) == 20
    assert strength.analyze(pw)["strength"] == "VERY STRONG"


def test_long_passphrase_is_not_punished_for_missing_digits():
    result = strength.analyze("correct-horse-battery-staple")
    assert result["strength"] == "VERY STRONG"
    assert result["issues"] == []


def test_weak_password_always_explains_why():
    for pw in ("Summer2024!!", "sunshine1"):
        assert strength.analyze(pw)["issues"], pw


def test_words_from_context_lower_the_rating():
    pw = "zxqvkjwplm"
    plain = strength.analyze(pw)["level"]
    with_context = strength.analyze(pw, user_inputs=["zxqvkjwplm"])["level"]
    assert with_context < plain
    assert strength.analyze(pw, user_inputs=["zxqvkjwplm"])["strength"] in strength.WEAK_LEVELS


def test_weak_password_gets_suggestion_based_on_it():
    result = strength.review("sunshine1")
    assert result["weak"]
    suggestion = result["suggestion"]["password"]
    assert len(suggestion) >= 18
    assert result["suggestion"]["strength"] not in strength.WEAK_LEVELS
    assert suggestion.lower() != "sunshine1"


def test_strong_password_gets_no_suggestion():
    result = strength.review("correct horse battery")
    assert not result["weak"] and result["suggestion"] is None


def test_very_long_input_is_handled_quickly():
    assert strength.analyze("a" * 5000)["strength"] == "VERY WEAK"
