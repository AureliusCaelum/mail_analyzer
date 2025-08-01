"""
Test-Suite für die Utility-Funktionen
"""
import pytest
import os
from analyzer.utils import (
    setup_logging,
    format_timestamp,
    sanitize_filename,
    create_analysis_report,
    extract_links,
    is_suspicious_sender
)
from datetime import datetime

def test_setup_logging(tmp_path):
    """Test der Logging-Konfiguration"""
    log_file = tmp_path / "test.log"
    os.environ["LOG_FILE"] = str(log_file)
    setup_logging()
    assert log_file.parent.exists(), "Log-Verzeichnis sollte erstellt werden"

def test_format_timestamp():
    """Test der Zeitstempel-Formatierung"""
    test_timestamp = datetime.now().timestamp()
    formatted = format_timestamp(test_timestamp)
    assert isinstance(formatted, str), "Formatierter Zeitstempel sollte ein String sein"
    assert len(formatted) == 19, "Zeitstempel sollte im Format 'YYYY-MM-DD HH:MM:SS' sein"

def test_sanitize_filename():
    """Test der Dateinamen-Bereinigung"""
    test_filename = "Test/File*With:Invalid<Chars>.txt"
    sanitized = sanitize_filename(test_filename)
    assert "/" not in sanitized, "Sanitized Filename sollte keine Schrägstriche enthalten"
    assert "*" not in sanitized, "Sanitized Filename sollte keine Sternchen enthalten"
    assert ":" not in sanitized, "Sanitized Filename sollte keine Doppelpunkte enthalten"
    assert "<" not in sanitized, "Sanitized Filename sollte keine spitzen Klammern enthalten"

def test_create_analysis_report():
    """Test der Berichtserstellung"""
    test_email = {
        "subject": "Test Subject",
        "sender": "test@example.com",
        "attachments": ["test.txt"]
    }
    test_analysis = {
        "score": 3,
        "level": "🟢",
        "indicators": ["Test Indicator"]
    }
    
    report = create_analysis_report(test_email, test_analysis)
    assert isinstance(report, dict), "Bericht sollte ein Dictionary sein"
    assert "timestamp" in report, "Bericht sollte einen Zeitstempel enthalten"
    assert "email" in report, "Bericht sollte E-Mail-Daten enthalten"
    assert "analysis" in report, "Bericht sollte Analyse-Daten enthalten"

def test_extract_links():
    """Test der URL-Extraktion"""
    test_text = "Text mit http://example.com und https://test.com/page Links"
    links = extract_links(test_text)
    assert len(links) == 2, "Sollte zwei Links finden"
    assert "http://example.com" in links, "Sollte den ersten Link enthalten"
    assert "https://test.com/page" in links, "Sollte den zweiten Link enthalten"

def test_is_suspicious_sender():
    """Test der Absender-Überprüfung"""
    trusted_domains = ["@trusted.com", "@safe.org"]
    
    assert is_suspicious_sender("user@malicious.com", trusted_domains), \
        "Unbekannte Domain sollte als verdächtig eingestuft werden"
    
    assert not is_suspicious_sender("user@trusted.com", trusted_domains), \
        "Vertrauenswürdige Domain sollte nicht als verdächtig eingestuft werden"
