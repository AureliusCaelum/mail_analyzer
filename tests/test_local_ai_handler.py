"""Tests für den LocalAIHandler."""

import pytest

from analyzer.ml.local_ai_handler import LocalAIHandler


def test_analyze_email_content_combines_results(monkeypatch):
    """Prüft, ob Ergebnisse der Modelle korrekt kombiniert werden."""
    monkeypatch.setattr(LocalAIHandler, "_check_ollama_available", lambda self: True)
    monkeypatch.setattr(LocalAIHandler, "_check_deepseek_available", lambda self: True)

    handler = LocalAIHandler()

    monkeypatch.setattr(
        handler,
        "_analyze_with_ollama",
        lambda prompt: {
            "spam_probability": 0.6,
            "overall_risk": 0.4,
            "indicators": ["a"],
        },
    )
    monkeypatch.setattr(
        handler,
        "_analyze_with_deepseek",
        lambda prompt: {
            "spam_probability": 0.8,
            "overall_risk": 0.7,
            "indicators": ["b"],
        },
    )

    result = handler.analyze_email_content({"subject": "", "body": "text", "sender": "", "attachments": []})

    assert pytest.approx(result["spam_score"]) == 0.7
    assert pytest.approx(result["risk_score"]) == 0.55
    assert set(result["indicators"]) == {"a", "b"}
    assert result["confidence"] == 1.0
