"""
Mail Analyzer Package
Dieses Paket enthält die Hauptkomponenten für die E-Mail-Analyse.
"""

# Optionale Importe, um Tests ohne externe Abhängigkeiten zu ermöglichen.
try:  # pragma: no cover - optional Import
    from .email_scanner import get_outlook_emails
except Exception:  # pragma: no cover - fehlende Abhängigkeiten
    get_outlook_emails = None

# Optionaler Import, da Funktion in manchen Umgebungen nicht benötigt wird.
try:  # pragma: no cover - optional Import
    from .traffic_light import analyze_threat_level
except Exception:  # pragma: no cover - fehlende Abhängigkeiten oder fehlende Funktion
    analyze_threat_level = None

from .utils import setup_logging

__all__ = ["get_outlook_emails", "analyze_threat_level", "setup_logging"]

__version__ = '0.1.0'
