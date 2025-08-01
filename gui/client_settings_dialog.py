"""Dialog to configure email client settings."""

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
)


class ClientSettingsDialog(QDialog):
    """Modal dialog for editing client connection settings.

    Attributes:
        config: ConfigParser object with current settings.
    """

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._init_ui()

    def _init_ui(self) -> None:
        """Construct the dialog layout."""
        self.setWindowTitle("E-Mail-Client Einstellungen")
        layout = QFormLayout()

        # Client selection
        self.client_combo = QComboBox()
        self.client_combo.addItems(["outlook", "gmail", "exchange"])
        current_client = self.config.get("EMAIL", "client", fallback="outlook")
        self.client_combo.setCurrentText(current_client)
        layout.addRow("E-Mail-Client:", self.client_combo)

        # Gmail settings
        self.gmail_creds = QLineEdit(
            self.config.get("GMAIL", "credentials_file", fallback="credentials.json")
        )
        layout.addRow("Gmail Credentials File:", self.gmail_creds)

        # Exchange settings
        self.exchange_client_id = QLineEdit(
            self.config.get("EXCHANGE", "client_id", fallback="")
        )
        self.exchange_tenant_id = QLineEdit(
            self.config.get("EXCHANGE", "tenant_id", fallback="")
        )
        self.exchange_secret = QLineEdit(
            self.config.get("EXCHANGE", "client_secret", fallback="")
        )
        self.exchange_secret.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Exchange Client ID:", self.exchange_client_id)
        layout.addRow("Exchange Tenant ID:", self.exchange_tenant_id)
        layout.addRow("Exchange Client Secret:", self.exchange_secret)

        # Dialog buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

        self.setLayout(layout)

    def get_settings(self) -> dict:
        """Return the user-specified settings.

        Returns:
            dict: Mapping of setting names to values.
        """
        return {
            "client": self.client_combo.currentText(),
            "gmail_credentials": self.gmail_creds.text(),
            "exchange_client_id": self.exchange_client_id.text(),
            "exchange_tenant_id": self.exchange_tenant_id.text(),
            "exchange_secret": self.exchange_secret.text(),
        }
