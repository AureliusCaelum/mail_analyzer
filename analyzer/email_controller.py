"""Controller for retrieving and analyzing emails."""

from typing import List, Tuple, Dict


class EmailController:
    """Handle email fetching and analysis."""

    def __init__(self, scanner, analyzer) -> None:
        self._scanner = scanner
        self._analyzer = analyzer

    def fetch_emails(self, max_count: int) -> List[Tuple[Dict, Dict]]:
        """Fetch emails and return analysis results.

        Args:
            max_count: Maximum number of emails to retrieve.

        Returns:
            List[Tuple[Dict, Dict]]: Pairs of raw email data and analysis results.
        """
        emails = self._scanner.get_emails(max_count=max_count)
        results: List[Tuple[Dict, Dict]] = []
        for email in emails:
            analysis = self._analyzer.analyze_email(email)
            results.append((email, analysis))
        return results
