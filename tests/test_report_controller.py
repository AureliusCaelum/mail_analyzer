"""Tests for ReportController."""

from analyzer.report_controller import ReportController


class DummyItem:
    def __init__(self):
        self.email_data = {"subject": "s", "body": "b"}
        self.analysis_result = {"level": "LOW"}


class DummyListWidget:
    def __init__(self):
        self._items = [DummyItem()]

    def count(self):
        return len(self._items)

    def item(self, index):
        return self._items[index]


class DummyGenerator:
    def __init__(self):
        self.received = None

    def create_pdf_report(self, emails):
        self.received = emails
        return "file.pdf"

    def create_excel_report(self, emails):  # pragma: no cover - not used in test
        return "file.xlsx"

    def create_statistical_analysis(self, emails):  # pragma: no cover - not used
        return {"total_emails": len(emails)}


def test_collects_emails_and_generates_pdf():
    generator = DummyGenerator()
    controller = ReportController(generator)
    filename = controller.create_pdf_report(DummyListWidget())
    assert filename == "file.pdf"
    assert generator.received[0]["subject"] == "s"
