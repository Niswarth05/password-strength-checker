import strength


def test_common_password_is_very_weak():
    assert strength.analyze("password")["strength"] == "VERY WEAK"


def test_patterns_are_capped():
    assert strength.analyze("qwerty12345")["strength"] in strength.WEAK_LEVELS
    assert strength.analyze("aaaa1111BBBB!!")["strength"] in strength.WEAK_LEVELS


def test_random_password_is_very_strong():
    pw = strength.generate_password(20)
    assert len(pw) == 20
    assert strength.analyze(pw)["strength"] == "VERY STRONG"


def test_weak_password_gets_suggestion_based_on_it():
    result = strength.review("sunshine1")
    assert result["weak"]
    suggestion = result["suggestion"]["password"]
    assert len(suggestion) >= 16
    assert result["suggestion"]["strength"] not in strength.WEAK_LEVELS
    assert suggestion.lower() != "sunshine1"


def test_strong_password_gets_no_suggestion():
    result = strength.review("x9$Lm2#vQ8!pZr4w")
    assert not result["weak"] and result["suggestion"] is None
