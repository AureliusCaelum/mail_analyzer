"""Controller coordinating report generation and statistics."""

from datetime import datetime
from typing import Any, Dict, List, Optional


class ReportController:
    """Aggregate email data and delegate report creation."""

    def __init__(self, generator) -> None:
        self._generator = generator

    def _collect_emails(self, list_widget) -> List[Dict[str, Any]]:
        """Extract email and analysis data from a QListWidget-like object."""
        emails: List[Dict[str, Any]] = []
        for i in range(list_widget.count()):
            item = list_widget.item(i)
            email_data = item.email_data.copy()
            email_data.update(item.analysis_result)
            email_data["timestamp"] = datetime.now().isoformat()
            emails.append(email_data)
        return emails

    def create_pdf_report(self, list_widget) -> Optional[str]:
        """Create a PDF report from the given widget contents."""
        emails = self._collect_emails(list_widget)
        return self._generator.create_pdf_report(emails)

    def create_excel_report(self, list_widget) -> Optional[str]:
        """Create an Excel report from the given widget contents."""
        emails = self._collect_emails(list_widget)
        return self._generator.create_excel_report(emails)

    def create_statistical_analysis(self, list_widget) -> Optional[Dict[str, Any]]:
        """Generate statistical summaries for the given emails."""
        emails = self._collect_emails(list_widget)
        return self._generator.create_statistical_analysis(emails)
