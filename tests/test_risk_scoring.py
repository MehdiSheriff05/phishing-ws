from services.risk_scoring import combine_scores


def test_weighted_risk_level_high():
    out = combine_scores(
        {"score": 90, "reasons": ["text risk"]},
        {"score": 80, "reasons": ["url risk"]},
        {"score": 70, "reasons": ["sender risk"]},
        {"score": 60, "reasons": ["attachment risk"]},
    )
    assert out["risk_level"] == "high"
    assert out["risk_score"] >= 70


def test_weighted_risk_level_low():
    out = combine_scores(
        {"score": 5, "reasons": []},
        {"score": 0, "reasons": []},
        {"score": 5, "reasons": []},
        {"score": 0, "reasons": []},
    )
    assert out["risk_level"] == "low"
