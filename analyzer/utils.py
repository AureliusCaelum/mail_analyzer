"""
Utility-Funktionen für den Mail Analyzer
"""
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime
from config.settings import LOG_FILE, LOG_FORMAT
import re

def setup_logging():
    """Konfiguriert das Logging-System"""
    log_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    formatter = logging.Formatter(LOG_FORMAT)

    # File Handler mit Rotation
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Root Logger Setup
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def format_timestamp(timestamp):
    """Formatiert einen Zeitstempel in lesbares Format"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def sanitize_filename(filename):
    """Bereinigt Dateinamen von ungültigen Zeichen"""
    return "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.'))

def create_analysis_report(email_data, threat_analysis):
    """Erstellt einen formatierten Analysebericht"""
    return {
        "timestamp": format_timestamp(datetime.now().timestamp()),
        "email": {
            "subject": email_data.get("subject", ""),
            "sender": email_data.get("sender", ""),
            "attachment_count": len(email_data.get("attachments", []))
        },
        "analysis": threat_analysis
    }

def extract_links(text):
    """
    Extracts all URLs from the given text.
    """
    return re.findall(r'https?://[^\s]+', text or "")

def is_suspicious_sender(sender, trusted_domains=None):
    """
    Checks if the sender is suspicious (not in trusted domains).
    """
    if trusted_domains is None:
        trusted_domains = ["@ihrefirma.de", "@vertrauenswuerdig.de"]
    return not any(sender.endswith(domain) for domain in trusted_domains)

def has_suspicious_attachment(attachments, suspicious_extensions=None):
    """
    Checks if any attachment has a suspicious file extension.
    """
    if suspicious_extensions is None:
        suspicious_extensions = [".exe", ".bat", ".js", ".vbs", ".scr", ".zip", ".rar"]
    return any(att.lower().endswith(tuple(suspicious_extensions)) for att in attachments)
