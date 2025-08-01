"""
E-Mail Scanner Modul
Verwaltet die E-Mail-Client-Integrationen und den Scan-Prozess
"""
import logging
import configparser
import re
from contextlib import contextmanager
from typing import Dict, List

from config import settings
from .utils import extract_links
from .email_clients.base import EmailClientBase
from .email_clients.outlook import OutlookClient
from .email_clients.gmail import GmailClient
from .email_clients.exchange import ExchangeOnlineClient

# Suspicious markers are loaded from configuration to ease localization and updates
SUSPICIOUS_KEYWORDS = tuple(
    kw.lower()
    for keywords in settings.SUSPICIOUS_KEYWORDS.values()
    for kw in keywords
)
SUSPICIOUS_EXTENSIONS = tuple(
    ext.lower()
    for exts in settings.SUSPICIOUS_EXTENSIONS.values()
    for ext in exts
)
SHORTENER_PATTERN = re.compile(r"(bit\.ly|tinyurl|goo\.gl|ow\.ly)", re.IGNORECASE)
SUSPICIOUS_LINK_PATTERN = re.compile(r"(login|verify|secure|bank|konto)", re.IGNORECASE)

class EmailScanner:
    def __init__(self, config_file: str = "configuration.ini"):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

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

    @contextmanager
    def _client_context(self) -> EmailClientBase:
        """Provide a connected mail client and ensure cleanup."""
        client = self._initialize_client()
        logging.info(f"Initialisiere {client.name} Client")
        if not client.connect():
            raise ConnectionError(f"Verbindung zu {client.name} fehlgeschlagen")
        try:
            yield client
        finally:
            client.disconnect()

    def get_emails(self, max_count: int = 20) -> List[Dict]:
        """Ruft E-Mails vom konfigurierten Client ab."""
        try:
            with self._client_context() as client:
                emails = client.get_emails(max_count)
                logging.info(
                    f"{len(emails)} E-Mails von {client.name} abgerufen"
                )
                return emails
        except ConnectionError as exc:
            logging.error(f"Verbindungsfehler: {exc}")
        except Exception as exc:  # Fallback for unerwartete Fehler
            logging.error(f"Fehler beim Abrufen der E-Mails: {exc}")
        return []

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

    subject = email.get("subject") or ""
    body = email.get("body") or ""
    sender = email.get("sender") or ""

    subject_lower = subject.lower()
    body_lower = body.lower()
    issues: List[str] = []

    # Check for suspicious keywords in subject and body
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in subject_lower or keyword in body_lower:
            issues.append(f"Verdächtiges Schlüsselwort gefunden: '{keyword}'")

    # Check for suspicious links
    for link in extract_links(body):
        if SHORTENER_PATTERN.search(link):
            issues.append(f"Verdächtiger Kurzlink gefunden: {link}")
        if SUSPICIOUS_LINK_PATTERN.search(link):
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

def determine_risk_level(issues: List[str]) -> str:
    """Map detected issues to a configured threat level.

    Args:
        issues (list[str]): Collection of issue descriptions.

    Returns:
        str: Emoji from :data:`config.settings.THREAT_LEVELS` representing the
            assessed risk.
    """
    if any("Verdächtiger Anhang" in i or "Verdächtiger Link" in i for i in issues):
        return settings.THREAT_LEVELS["HIGH"]
    if issues:
        return settings.THREAT_LEVELS["MEDIUM"]
    return settings.THREAT_LEVELS["LOW"]

def scan_inbox(max_count: int = 20, trusted_domains=None):
    """Scannt E-Mails im Posteingang und bewertet deren Risiko.

    Args:
        max_count (int): Maximale Anzahl abzurufender E-Mails.
        trusted_domains (list[str] | None): Liste vertrauenswürdiger Domains,
            die bei der Bewertung berücksichtigt werden.

    Returns:
        List[Dict]: Eine Liste mit Ergebnissen pro E-Mail.
    """
    emails = get_outlook_emails(max_count=max_count)
    results = []
    for email in emails:
        risk, issues = scan_email(email, trusted_domains=trusted_domains)
        results.append({
            "subject": email["subject"],
            "sender": email["sender"],
            "risk": risk,
            "issues": issues,
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
