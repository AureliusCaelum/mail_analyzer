"""Exchange Online Integration über Microsoft Graph API.

Dieses Modul nutzt die `msal`-Bibliothek. Ist sie nicht verfügbar, wird die
Integration deaktiviert, ohne dass ein ImportError ausgelöst wird.
"""
import json
import logging
import os
from typing import List, Dict

try:  # pragma: no cover - externe Abhängigkeit
    import requests
except Exception:  # pragma: no cover
    requests = None

try:  # pragma: no cover - externe Abhängigkeit
    import msal
except Exception:  # pragma: no cover - Modul möglicherweise nicht verfügbar
    msal = None

from .base import EmailClientBase

class ExchangeOnlineClient(EmailClientBase):
    def __init__(self, client_id: str, tenant_id: str, client_secret: str):
        self._client_id = client_id
        self._tenant_id = tenant_id
        self._client_secret = client_secret
        self._token = None
        self._app = None

    @property
    def name(self) -> str:
        return "Exchange Online"

    def connect(self) -> bool:
        if msal is None or requests is None:
            logging.error("Benötigte Bibliotheken für Exchange nicht verfügbar. Integration deaktiviert.")
            return False

        try:
            # MSAL App initialisieren
            authority = f"https://login.microsoftonline.com/{self._tenant_id}"
            self._app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=authority,
                client_credential=self._client_secret
            )

            # Token abrufen
            scopes = ['https://graph.microsoft.com/.default']
            result = self._app.acquire_token_silent(scopes, account=None)
            if not result:
                result = self._app.acquire_token_for_client(scopes)

            if "access_token" in result:
                self._token = result['access_token']
                return True
            logging.error(f"Fehler beim Token-Abruf: {result.get('error')}")
            return False

        except Exception as e:  # pragma: no cover - schwer zu simulieren
            logging.error(f"Fehler beim Verbinden mit Exchange Online: {str(e)}")
            return False

    def get_emails(self, max_count: int = 20) -> List[Dict]:
        if not self._token:
            if not self.connect():
                return []

        try:
            headers = {
                'Authorization': f'Bearer {self._token}',
                'Content-Type': 'application/json'
            }

            # Microsoft Graph API Aufruf
            url = f"https://graph.microsoft.com/v1.0/me/messages?$top={max_count}&$orderby=receivedDateTime desc"
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            data = response.json()
            emails = []

            for msg in data.get('value', []):
                # Anhänge abrufen
                attachments = []
                if msg.get('hasAttachments', False):
                    att_url = f"https://graph.microsoft.com/v1.0/me/messages/{msg['id']}/attachments"
                    att_response = requests.get(att_url, headers=headers)
                    if att_response.ok:
                        attachments = [att['name'] for att in att_response.json().get('value', [])]

                emails.append({
                    "subject": msg.get('subject', ''),
                    "sender": msg.get('from', {}).get('emailAddress', {}).get('address', ''),
                    "body": msg.get('body', {}).get('content', ''),
                    "attachments": attachments
                })

            return emails

        except Exception as e:
            logging.error(f"Fehler beim Abrufen der E-Mails von Exchange Online: {str(e)}")
            return []

    def disconnect(self) -> None:
        self._token = None
        self._app = None
