"""
Traffic Light System für die Bedrohungsbewertung
Implementiert ein Ampelsystem zur visuellen Darstellung der Bedrohungsstufe
"""
from typing import Dict
from config.settings import THREAT_LEVELS

try:  # pragma: no cover - optionale Abhängigkeit
    from colorama import Fore, Style, init
    init()
except Exception:  # pragma: no cover - Modul möglicherweise nicht verfügbar
    class _Dummy:
        RED = YELLOW = GREEN = WHITE = ""
        RESET_ALL = ""

    Fore = Style = _Dummy()


class TrafficLight:
    def __init__(self):
        self.color_map = {
            THREAT_LEVELS["LOW"]: Fore.GREEN,
            THREAT_LEVELS["MEDIUM"]: Fore.YELLOW,
            THREAT_LEVELS["HIGH"]: Fore.RED
        }

    def display_threat_level(self, analysis_result: Dict) -> str:
        """
        Zeigt das Bedrohungslevel mit entsprechender Farbe an
        """
        threat_level = analysis_result.get('level', THREAT_LEVELS["LOW"])
        color = self.color_map.get(threat_level, Fore.WHITE)

        output = (
            f"\n{color}{'='*50}\n"
            f"Bedrohungslevel: {threat_level}\n"
            f"Score: {analysis_result.get('score', 0)}/10\n"
        )

        if analysis_result.get('indicators'):
            output += "Gefundene Indikatoren:\n"
            for indicator in analysis_result['indicators']:
                output += f"- {indicator}\n"

        output += f"{'='*50}{Style.RESET_ALL}\n"

        return output

    def get_recommendation(self, analysis_result: Dict) -> str:
        """
        Gibt eine Handlungsempfehlung basierend auf dem Bedrohungslevel
        """
        threat_level = analysis_result.get('level')

        if threat_level == THREAT_LEVELS["HIGH"]:
            return ("WARNUNG: Diese E-Mail stellt ein hohes Risiko dar!\n"
                   "Empfehlung: Nicht öffnen und IT-Sicherheit informieren.")

        elif threat_level == THREAT_LEVELS["MEDIUM"]:
            return ("VORSICHT: Diese E-Mail enthält verdächtige Elemente.\n"
                   "Empfehlung: Vorsichtig prüfen und im Zweifel IT-Support kontaktieren.")

        return ("INFO: Diese E-Mail erscheint sicher.\n"
               "Empfehlung: Normal fortfahren, aber immer aufmerksam bleiben.")
