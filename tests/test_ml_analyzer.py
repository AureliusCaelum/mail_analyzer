"""Tests für den MLAnalyzer mit Regressionsmodell."""
import pytest

try:  # pragma: no cover - abhängigkeiten optional
    from analyzer.ml.ml_analyzer import MLAnalyzer
except Exception:  # pragma: no cover - sklearn o.Ä. nicht verfügbar
    MLAnalyzer = None


@pytest.mark.skipif(MLAnalyzer is None, reason="Sklearn nicht verfügbar")
def test_ml_analyzer_regression(tmp_path):
    """Überprüft, dass der MLAnalyzer einen Regressor nutzt."""
    model_dir = tmp_path / "models"
    analyzer = MLAnalyzer(model_dir=str(model_dir))

    sample_email = {
        "subject": "Test",
        "sender": "user@example.com",
        "body": "Hallo Welt",
        "attachments": [],
    }

    for _ in range(10):
        analyzer.train(sample_email, 0.75)

    result = analyzer.analyze_email(sample_email)
    assert isinstance(result["ml_score"], float)
    assert result["ml_score"] == pytest.approx(0.75, abs=0.25)
    assert result["confidence"] == pytest.approx(1.0)
