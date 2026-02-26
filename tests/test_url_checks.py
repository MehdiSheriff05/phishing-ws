from services.url_checks import analyze_urls


def test_ip_and_keyword_url_is_flagged():
    result = analyze_urls(["http://10.0.0.1/verify/login"]) 
    assert result["score"] > 0
    assert any("IP address" in reason for reason in result["reasons"])


def test_clean_url_low_score():
    result = analyze_urls(["https://www.python.org/downloads/"])
    assert result["score"] <= 10
