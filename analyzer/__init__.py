"""
Mail Analyzer Package
Dieses Paket enthält die Hauptkomponenten für die E-Mail-Analyse.
"""

from .email_scanner import get_outlook_emails
from .traffic_light import analyze_threat_level
from .utils import setup_logging

__version__ = '0.1.0'
