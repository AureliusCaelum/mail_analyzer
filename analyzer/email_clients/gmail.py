"""
Gmail IMAP Integration
"""
import imaplib
import email
from email.header import decode_header
import os
from typing import List, Dict
import logging
import pickle

try:  # pragma: no cover - externe Abhängigkeiten
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
except Exception:  # pragma: no cover - Bibliotheken evtl. nicht verfügbar
    Credentials = InstalledAppFlow = Request = None

from .base import EmailClientBase

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


class GmailClient(EmailClientBase):
    def __init__(self, credentials_file: str = 'credentials.json'):
        self._imap = None
        self._credentials_file = credentials_file
        self._token_file = 'token.pickle'
        self._creds = None

    @property
    def name(self) -> str:
        return "Gmail"

    def _get_credentials(self) -> Credentials:
        """Gmail OAuth2 Authentifizierung"""
        if os.path.exists(self._token_file):
            with open(self._token_file, 'rb') as token:
                self._creds = pickle.load(token)

        if not self._creds or not self._creds.valid:
            if self._creds and self._creds.expired and self._creds.refresh_token:
                self._creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self._credentials_file, SCOPES)
                self._creds = flow.run_local_server(port=0)

            with open(self._token_file, 'wb') as token:
                pickle.dump(self._creds, token)

        return self._creds

    def connect(self) -> bool:
        if Credentials is None or InstalledAppFlow is None or Request is None:
            logging.error("Google API Bibliotheken nicht verfügbar. Gmail-Integration deaktiviert.")
            return False

        try:
            self._creds = self._get_credentials()
            self._imap = imaplib.IMAP4_SSL('imap.gmail.com')

            # OAuth2 Authentifizierung
            auth_string = f'user={self._creds.client_id}\1auth=Bearer {self._creds.token}\1\1'
            self._imap.authenticate('XOAUTH2', lambda x: auth_string)

            return True
        except Exception as e:  # pragma: no cover - schwer zu simulieren
            logging.error(f"Fehler beim Verbinden mit Gmail: {str(e)}")
            return False

    def get_emails(self, max_count: int = 20) -> List[Dict]:
        if not self._imap:
            if not self.connect():
                return []

        try:
            self._imap.select('INBOX')
            _, messages = self._imap.search(None, 'ALL')
            email_ids = messages[0].split()[-max_count:]

            emails = []
            for email_id in email_ids:
                _, msg = self._imap.fetch(email_id, '(RFC822)')
                email_body = msg[0][1]
                email_message = email.message_from_bytes(email_body)

                subject = decode_header(email_message["Subject"])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()

                sender = email_message.get("From", "")

                # E-Mail-Body extrahieren
                body = ""
                attachments = []
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode()
                            except Exception:
                                body = part.get_payload()
                        elif part.get_content_disposition() == 'attachment':
                            attachments.append(part.get_filename())
                else:
                    body = email_message.get_payload(decode=True).decode()

                emails.append({
                    "subject": subject,
                    "sender": sender,
                    "body": body,
                    "attachments": attachments
                })

            return emails
        except Exception as e:
            logging.error(f"Fehler beim Abrufen der E-Mails von Gmail: {str(e)}")
            return []

    def disconnect(self) -> None:
        if self._imap:
            try:
                self._imap.close()
                self._imap.logout()
            except Exception:
                pass
            finally:
                self._imap = None
