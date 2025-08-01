"""Outlook E-Mail-Client Integration.

Dieses Modul stellt eine Verbindung zu Microsoft Outlook her, sofern die
entsprechenden Bibliotheken verfügbar sind. In Umgebungen ohne
``win32com``-Unterstützung wird die Integration deaktiviert und es wird ein
Fehler protokolliert, anstatt einen ImportError auszulösen.
"""
import logging
from typing import List, Dict

try:  # pragma: no cover - Plattformabhängigkeit
    import win32com.client  # type: ignore
except Exception:  # pragma: no cover - Modul möglicherweise nicht verfügbar
    win32com = None

from .base import EmailClientBase


class OutlookClient(EmailClientBase):
    def __init__(self):
        self._outlook = None

    @property
    def name(self) -> str:
        return "Microsoft Outlook"

    def connect(self) -> bool:
        if win32com is None:
            logging.error("win32com.client nicht verfügbar. Outlook-Integration deaktiviert.")
            return False

        try:
            self._outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
            return True
        except Exception as e:  # pragma: no cover - schwer zu simulieren
            logging.error(f"Fehler beim Verbinden mit Outlook: {str(e)}")
            return False

    def get_emails(self, max_count: int = 20) -> List[Dict]:
        if not self._outlook:
            if not self.connect():
                return []

        try:
            inbox = self._outlook.GetDefaultFolder(6)  # 6 = Inbox
            messages = inbox.Items
            messages.Sort("[ReceivedTime]", True)

            emails = []
            count = 0
            for message in messages:
                if count >= max_count:
                    break
                try:
                    emails.append({
                        "subject": message.Subject,
                        "sender": message.SenderEmailAddress,
                        "body": message.Body,
                        "attachments": [att.FileName for att in message.Attachments]
                    })
                    count += 1
                except Exception as e:
                    logging.warning(f"Fehler beim Lesen einer E-Mail: {str(e)}")

            return emails
        except Exception as e:
            logging.error(f"Fehler beim Abrufen der E-Mails aus Outlook: {str(e)}")
            return []

    def disconnect(self) -> None:
        self._outlook = None
