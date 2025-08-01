"""Tests for the e-mail scanner module."""

from unittest.mock import MagicMock

import pytest

from analyzer import email_scanner
from analyzer.email_scanner import get_outlook_emails, scan_inbox


def test_get_outlook_emails(monkeypatch):
    """Ensure ``get_outlook_emails`` returns a list of e-mails."""

    class DummyScanner:
        def get_emails(self, max_count):
            return [
                {
                    "subject": "Test",
                    "sender": "tester@example.com",
                    "body": "",
                    "attachments": [],
                }
            ]

    monkeypatch.setattr(email_scanner, "get_scanner", lambda: DummyScanner())

    emails = get_outlook_emails(max_count=1)
    assert isinstance(emails, list), "Emails sollten als Liste zurückgegeben werden"

    if emails:
        email = emails[0]
        assert isinstance(email, dict), "Jede E-Mail sollte ein Dictionary sein"
        assert "subject" in email, "E-Mail sollte einen Betreff haben"
        assert "sender" in email, "E-Mail sollte einen Absender haben"
        assert "body" in email, "E-Mail sollte einen Body haben"
        assert "attachments" in email, "E-Mail sollte Anhänge-Information haben"


def test_scan_inbox_uses_max_count(monkeypatch):
    """``scan_inbox`` should forward only ``max_count`` to ``get_outlook_emails``."""

    dummy_email = {
        "subject": "Hallo",
        "sender": "user@example.com",
        "body": "",
        "attachments": [],
    }

    mock_get = MagicMock(return_value=[dummy_email])
    monkeypatch.setattr(email_scanner, "get_outlook_emails", mock_get)

    results = scan_inbox(folder_name="ignored", max_count=5)

    mock_get.assert_called_once_with(max_count=5)
    assert results[0]["subject"] == "Hallo"
