"""
Mail Analyzer Package
Dieses Paket enthält die Hauptkomponenten für die E-Mail-Analyse.
"""

from .email_scanner import get_outlook_emails
from .utils import setup_logging

__all__ = ["get_outlook_emails", "setup_logging"]

__version__ = '0.1.0'
