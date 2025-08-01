"""
Test-Suite für den Threat Analyzer
"""
import pytest

try:  # pragma: no cover - abhängigkeiten optional
    from analyzer.threat_analyzer import ThreatAnalyzer
except Exception:  # pragma: no cover - z.B. sklearn fehlt
    pytest.skip("Erforderliche Bibliotheken nicht verfügbar", allow_module_level=True)

@pytest.fixture
def analyzer():
    return ThreatAnalyzer()

def test_analyze_email(analyzer):
    """Test der E-Mail-Analyse Funktion"""
    test_email = {
        "subject": "Test E-Mail",
        "sender": "test@example.com",
        "body": "Dies ist eine Test-E-Mail",
        "attachments": []
    }

    result = analyzer.analyze_email(test_email)
    assert isinstance(result, dict), "Analyseergebnis sollte ein Dictionary sein"
    assert "score" in result, "Ergebnis sollte einen Score enthalten"
    assert "level" in result, "Ergebnis sollte ein Bedrohungslevel enthalten"
    assert "indicators" in result, "Ergebnis sollte Bedrohungsindikatoren enthalten"

def test_high_threat_email(analyzer):
    """Test einer E-Mail mit hohem Bedrohungspotential"""
    suspicious_email = {
        "subject": "DRINGEND: Ihr Konto wurde gesperrt",
        "sender": "bank-support@suspicious.com",
        "body": "Klicken Sie hier um Ihr Konto zu entsperren: http://fake-bank.com",
        "attachments": ["update.exe"]
    }

    result = analyzer.analyze_email(suspicious_email)
    assert result["score"] >= 7, "Verdächtige E-Mail sollte hohen Score haben"
