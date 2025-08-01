"""List item representing a scanned email."""

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QListWidgetItem

from config.settings import THREAT_LEVELS


class EmailListItem(QListWidgetItem):
    """Display an email with color-coding for threat level."""

    def __init__(self, email_data: dict, analysis_result: dict) -> None:
        super().__init__()
        self.email_data = email_data
        self.analysis_result = analysis_result
        self.setText(f"{email_data['subject'][:50]}...")
        self._set_color_by_threat_level()

    def _set_color_by_threat_level(self) -> None:
        """Apply background color according to the threat level."""
        level = self.analysis_result["level"]
        if level == THREAT_LEVELS["HIGH"]:
            self.setBackground(QColor(255, 200, 200))  # light red
        elif level == THREAT_LEVELS["MEDIUM"]:
            self.setBackground(QColor(255, 255, 200))  # light yellow
        else:
            self.setBackground(QColor(200, 255, 200))  # light green
