"""Test-Suite für den E-Mail Scanner."""

from unittest.mock import MagicMock, patch
import sys

sys.modules["win32com"] = MagicMock()
sys.modules["win32com.client"] = MagicMock()
sys.modules["google"] = MagicMock()
sys.modules["google.oauth2"] = MagicMock()
sys.modules["google.oauth2.credentials"] = MagicMock()
sys.modules["google_auth_oauthlib"] = MagicMock()
sys.modules["google_auth_oauthlib.flow"] = MagicMock()
sys.modules["google.auth"] = MagicMock()
sys.modules["google.auth.transport"] = MagicMock()
sys.modules["google.auth.transport.requests"] = MagicMock()
sys.modules["msal"] = MagicMock()
sys.modules["requests"] = MagicMock()
sys.modules["colorama"] = MagicMock()
mock_traffic_light = MagicMock()
mock_traffic_light.analyze_threat_level = MagicMock()
sys.modules["analyzer.traffic_light"] = mock_traffic_light

from analyzer.email_scanner import get_outlook_emails


def test_get_outlook_emails():
    """Testet den E-Mail-Abruf über einen gestubbten Outlook-Client."""
    dummy_emails = [
        {
            "subject": "Hallo",
            "sender": "alice@example.com",
            "body": "Willkommen",
            "attachments": [],
        },
        {
            "subject": "Report",
            "sender": "bob@example.com",
            "body": "Siehe Anhang",
            "attachments": ["report.pdf"],
        },
    ]

    mock_scanner = MagicMock()
    mock_scanner.get_emails.return_value = dummy_emails

    with patch("analyzer.email_scanner.get_scanner", return_value=mock_scanner):
        emails = get_outlook_emails(max_count=2)

    assert emails == dummy_emails
    assert len(emails) == 2

    first_email = emails[0]
    assert first_email["subject"] == "Hallo"
    assert first_email["sender"] == "alice@example.com"
    assert first_email["attachments"] == []
