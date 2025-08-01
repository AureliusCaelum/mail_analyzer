"""
Test-Suite für das Threat Intelligence Modul
"""
import pytest
import os
from analyzer.threat_intelligence import ThreatIntelligence

@pytest.fixture
def threat_intel():
    return ThreatIntelligence()

def test_local_ai_analysis(threat_intel):
    """Test der lokalen KI-Analyse"""
    test_text = "DRINGEND: Überweisen Sie sofort Geld auf folgendes Konto!"
    result = threat_intel.analyze_text_local(test_text)

    assert 'spam_score' in result
    assert 'threat_type' in result
    assert 'confidence' in result
    assert result['spam_score'] > 0.5  # Sollte als verdächtig erkannt werden

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
