"""Tests for EmailController."""

from analyzer.email_controller import EmailController


class DummyScanner:
    def __init__(self):
        self.called_with = None

    def get_emails(self, max_count: int):
        self.called_with = max_count
        return [{"subject": "test", "attachments": []}]


class DummyAnalyzer:
    def analyze_email(self, email):
        return {"level": "LOW"}


def test_fetch_emails_calls_dependencies():
    controller = EmailController(DummyScanner(), DummyAnalyzer())
    emails = controller.fetch_emails(5)
    assert emails[0][1]["level"] == "LOW"
