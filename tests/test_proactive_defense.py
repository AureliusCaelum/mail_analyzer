"""Tests for the ProactiveThreatDefense class."""

from analyzer.proactive_defense import ProactiveThreatDefense


def test_analyze_trends_returns_structure():
    """Analyze_trends should return window analysis, forecasts and recommendations."""

    defense = ProactiveThreatDefense()

    sample_emails = [
        {
            "type": "phishing",
            "score": 5,
            "indicators": ["link"],
            "target_department": "IT",
            "target_role": "admin",
        },
        {
            "type": "malware",
            "score": 8,
            "indicators": ["exe"],
            "target_department": "HR",
            "target_role": "user",
        },
    ]

    result = defense.analyze_trends(sample_emails)

    assert "window_analysis" in result
    assert "forecasts" in result
    assert "recommendations" in result
    assert result["window_analysis"]["short"]["total_threats"] == 2

    # Calling again with no new data should keep history
    result = defense.analyze_trends([])
    assert result["window_analysis"]["short"]["total_threats"] >= 2
