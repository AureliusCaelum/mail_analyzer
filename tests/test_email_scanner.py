# -*- coding: utf-8 -*-
"""Tests for the e-mail scanner module."""

import sys
from unittest.mock import MagicMock, patch
import pytest

# Externe Abhängigkeiten mocken, damit Imports in email_scanner nicht fehlschlagen
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
import analyzer.email_scanner
from analyzer.email_scanner import get_outlook_emails, scan_inbox


def test_get_outlook_emails_dummy_scanner():
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


def test_get_outlook_emails_structure(monkeypatch):
    """Ensure `get_outlook_emails` returns a list of dicts with the right keys."""
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

    # Scanner stubben
    monkeypatch.setattr(analyzer.email_scanner, "get_scanner", lambda: DummyScanner())

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
    """`scan_inbox` should forward only `max_count` to `get_outlook_emails`."""
    dummy_email = {
        "subject": "Hallo",
        "sender": "user@example.com",
        "body": "",
        "attachments": [],
    }

    mock_get = MagicMock(return_value=[dummy_email])
    monkeypatch.setattr(analyzer.email_scanner, "get_outlook_emails", mock_get)

    results = scan_inbox(folder_name="ignored", max_count=5)

    mock_get.assert_called_once_with(max_count=5)
    assert results[0]["subject"] == "Hallo"
