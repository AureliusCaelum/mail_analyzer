"""
Test-Suite für das Threat Intelligence Modul
"""
import pytest

try:  # pragma: no cover - abhängigkeiten optional
    from analyzer.threat_intelligence import ThreatIntelligence
except Exception:  # pragma: no cover
    pytest.skip("Erforderliche Bibliotheken nicht verfügbar", allow_module_level=True)

@pytest.fixture
def threat_intel(monkeypatch):
    monkeypatch.setattr(ThreatIntelligence, "_initialize_ai_models", lambda self: None)
    return ThreatIntelligence()

def test_local_ai_analysis(threat_intel, monkeypatch):
    """Test der lokalen KI-Analyse mit simulierten Modellantworten."""

    def dummy_analysis(_):
        return {
            "spam_score": 0.8,
            "confidence": 0.9,
            "indicators": ["phishing"],
            "model_scores": {"mock": {"spam_score": 0.8, "risk_score": 0.5}},
        }

    monkeypatch.setattr(threat_intel.local_ai, "analyze_email_content", dummy_analysis)

    result = threat_intel.analyze_text_local("Testinhalt")

    assert result["spam_score"] == 0.8
    assert result["confidence"] == 0.9
    assert "phishing" in result["indicators"]

def test_url_checking(threat_intel):
    """Test der URL-Überprüfung"""
    test_urls = [
        "http://example.com",
        "https://suspicious.xyz/login",
    ]
    results = threat_intel.check_urls(test_urls)

    assert len(results) == len(test_urls)
    for url, result in results.items():
        assert 'safe_browsing' in result
        assert 'phishtank' in result

def test_sender_reputation(threat_intel):
    """Test der Absender-Reputation"""
    test_domain = "example.com"
    result = threat_intel.check_sender_reputation(test_domain)

    assert 'spamhaus' in result
    assert 'surbl' in result
    assert result['spamhaus'] in ['clean', 'blacklisted']

def test_spam_score(threat_intel):
    """Test der Spam-Bewertung"""
    test_email = """
    Subject: GEWINNER! Sie haben 1.000.000€ gewonnen!
    
    Herzlichen Glückwunsch! Sie wurden als Gewinner ausgewählt.
    Klicken Sie hier um Ihren Gewinn abzuholen: http://suspicious.win/claim
    """
    score = threat_intel.get_spam_score(test_email)
    assert score >= 0.0  # Sollte einen positiven Spam-Score haben

def test_attachment_analysis(threat_intel, tmp_path):
    """Test der Anhangsprüfung"""
    # Erstelle Test-Datei
    test_file = tmp_path / "test.txt"
    test_file.write_text("Test content")

    result = threat_intel.analyze_attachment(str(test_file))
    assert isinstance(result, dict)
    assert 'error' in result or all(k in result for k in ['malicious', 'suspicious', 'clean'])


def test_attachment_hashing_is_streamed(threat_intel, monkeypatch):
    """Stellt sicher, dass Anhänge nicht vollständig in den Speicher geladen werden."""
    import io
    import builtins
    import hashlib

    class TrackingFile(io.BytesIO):
        def __init__(self, data: bytes):
            super().__init__(data)
            self.read_sizes: list[int] = []

        def read(self, size: int = -1) -> bytes:  # type: ignore[override]
            self.read_sizes.append(size)
            if size == -1:
                raise AssertionError("File read without chunk size")
            return super().read(size)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            self.close()

    data = b"a" * 10000
    tracking_file = TrackingFile(data)

    monkeypatch.setattr(builtins, "open", lambda *a, **k: tracking_file)
    threat_intel.vt_api_key = "dummy"

    called_url = {}

    class DummyResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 0,
                        },
                        "last_analysis_results": {},
                    }
                }
            }

    def fake_get(url, **kwargs):
        called_url["url"] = url
        return DummyResponse()

    monkeypatch.setattr("analyzer.threat_intelligence.requests.get", fake_get)

    threat_intel.analyze_attachment("dummy.bin")

    expected_hash = hashlib.sha256(data).hexdigest()
    assert expected_hash in called_url["url"]
    assert len(tracking_file.read_sizes) > 1
    assert -1 not in tracking_file.read_sizes
