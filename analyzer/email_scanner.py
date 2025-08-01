"""
E-Mail Scanner Modul
Verwaltet die E-Mail-Client-Integrationen und den Scan-Prozess
"""
import logging
import configparser
import re
from typing import List, Dict
from .email_clients.base import EmailClientBase
from .email_clients.outlook import OutlookClient
from .email_clients.gmail import GmailClient
from .email_clients.exchange import ExchangeOnlineClient

SUSPICIOUS_KEYWORDS = [
    "dringend", "sofort", "passwort", "konto", "überweisen", "zahlung", "gewinnen", "klicken", "anhang öffnen",
    "verifizieren", "bestätigen", "sicherheitswarnung", "bank", "rechnung", "ungewöhnlich", "gesperrt"
]
SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".js", ".vbs", ".scr", ".zip", ".rar"]

class EmailScanner:
    def __init__(self, config_file: str = 'configuration.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self._client = None

    def _initialize_client(self) -> EmailClientBase:
        """Initialisiert den konfigurierten E-Mail-Client"""
        client_type = self.config.get('EMAIL', 'client', fallback='outlook').lower()

        if client_type == 'outlook':
            return OutlookClient()
        elif client_type == 'gmail':
            credentials_file = self.config.get('GMAIL', 'credentials_file', fallback='credentials.json')
            return GmailClient(credentials_file)
        elif client_type == 'exchange':
            client_id = self.config.get('EXCHANGE', 'client_id')
            tenant_id = self.config.get('EXCHANGE', 'tenant_id')
            client_secret = self.config.get('EXCHANGE', 'client_secret')
            return ExchangeOnlineClient(client_id, tenant_id, client_secret)
        else:
            raise ValueError(f"Nicht unterstützter E-Mail-Client: {client_type}")

    def get_emails(self, max_count: int = 20) -> List[Dict]:
        """
        Ruft E-Mails vom konfigurierten Client ab
        """
        try:
            if not self._client:
                self._client = self._initialize_client()
                logging.info(f"Initialisiere {self._client.name} Client")

            if not self._client.connect():
                raise ConnectionError(f"Verbindung zu {self._client.name} fehlgeschlagen")

            emails = self._client.get_emails(max_count)
            logging.info(f"{len(emails)} E-Mails von {self._client.name} abgerufen")
            return emails

        except Exception as e:
            logging.error(f"Fehler beim Abrufen der E-Mails: {str(e)}")
            return []

        finally:
            if self._client:
                self._client.disconnect()

def scan_email(email, trusted_domains=None):
    """Analyze an email for potential security issues and determine its risk level.

    The function safely handles missing fields by using default values when accessing
    the email dictionary and validates the sender against a list of trusted domains.

    Args:
        email (dict): Email data with keys such as "subject", "body", "sender" and
            optionally "attachments".
        trusted_domains (list[str], optional): Domain suffixes that are considered
            trusted. Defaults to ["@ihrefirma.de", "@vertrauenswuerdig.de"] if not
            provided.

    Returns:
        tuple[str, list[str]]: Risk level and list of detected issues.

    The function checks for:
        - Suspicious keywords in the subject and body.
        - Suspicious or shortened links in the body.
        - Suspicious file extensions in attachments.
        - Unknown or external senders.
    """
    if trusted_domains is None:
        trusted_domains = ["@ihrefirma.de", "@vertrauenswuerdig.de"]

    subject = email.get("subject", "") or ""
    body = email.get("body", "") or ""
    sender = email.get("sender", "") or ""

    issues = []

    # Check for suspicious keywords in subject and body
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in subject.lower() or keyword.lower() in body.lower():
            issues.append(f"Verdächtiges Schlüsselwort gefunden: '{keyword}'")

    # Check for suspicious links
    links = re.findall(r'https?://[^\s]+', body)
    for link in links:
        if any(domain in link for domain in ["bit.ly", "tinyurl", "goo.gl", "ow.ly"]):
            issues.append(f"Verdächtiger Kurzlink gefunden: {link}")
        if re.search(r"(login|verify|secure|bank|konto)", link, re.IGNORECASE):
            issues.append(f"Verdächtiger Link gefunden: {link}")

    # Check for suspicious attachments
    for att in email.get("attachments", []):
        if any(att.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            issues.append(f"Verdächtiger Anhang: {att}")

    # Check for unknown sender (simple heuristic)
    if not any(sender.endswith(domain) for domain in trusted_domains):
        issues.append(f"Unbekannter oder externer Absender: {sender}")

    # Determine risk level
    risk = determine_risk_level(issues)

    return risk, issues

def determine_risk_level(issues):
    if any("Verdächtiger Anhang" in i or "Verdächtiger Link" in i for i in issues):
        return "red"
    elif issues:
        return "yellow"
    else:
        return "green"

def scan_inbox(folder_name="Posteingang", max_count=20, trusted_domains=None):
    emails = get_outlook_emails(folder_name, max_count)
    results = []
    for email in emails:
        risk, issues = scan_email(email, trusted_domains=trusted_domains)
        results.append({
            "subject": email["subject"],
            "sender": email["sender"],
            "risk": risk,
            "issues": issues
        })
    return results

# Globale Instanz für einfachen Zugriff
_scanner = None

def get_scanner() -> EmailScanner:
    """Singleton-Zugriff auf den E-Mail-Scanner"""
    global _scanner
    if not _scanner:
        _scanner = EmailScanner()
    return _scanner

def get_outlook_emails(max_count: int = 20) -> List[Dict]:
    """
    Legacy-Funktion für Abwärtskompatibilität
    """
    return get_scanner().get_emails(max_count)
