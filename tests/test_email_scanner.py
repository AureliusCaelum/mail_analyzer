"""
Test-Suite für den E-Mail Scanner
"""
import pytest
from analyzer.email_scanner import get_outlook_emails

def test_get_outlook_emails():
    """Test der Outlook E-Mail Abruf Funktion"""
    emails = get_outlook_emails(max_count=1)
    assert isinstance(emails, list), "Emails sollten als Liste zurückgegeben werden"

    if emails:
        email = emails[0]
        assert isinstance(email, dict), "Jede E-Mail sollte ein Dictionary sein"
        assert "subject" in email, "E-Mail sollte einen Betreff haben"
        assert "sender" in email, "E-Mail sollte einen Absender haben"
        assert "body" in email, "E-Mail sollte einen Body haben"
        assert "attachments" in email, "E-Mail sollte Anhänge-Information haben"
