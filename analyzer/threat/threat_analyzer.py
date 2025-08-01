"""
Threat Analyzer Komponente
Analysiert E-Mails auf verschiedene Bedrohungsindikatoren mit KI-Unterstützung
"""
from typing import Dict, List, Optional
import re
import logging
from urllib.parse import urlparse

from ..ml.ml_analyzer import MLAnalyzer
from .threat_intelligence import ThreatIntelligence
from ..context_analyzer import ContextAwareAnalyzer
from .threat_clustering import ThreatClusterAnalyzer
from .proactive_defense import ProactiveThreatDefense
from ..utils import get_threat_level
from config.settings import (
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_URL_PATTERNS,
    SUSPICIOUS_TLD,
    SCORING_WEIGHTS,
)


class ThreatAnalyzer:
    def __init__(self):
        self.threat_score = 0.0
        self.threat_indicators = []
        self.urls_found = set()
        self.ml_analyzer = MLAnalyzer()
        self.threat_intel = ThreatIntelligence()
        self.context_analyzer = ContextAwareAnalyzer()
        self.cluster_analyzer = ThreatClusterAnalyzer()
        self.proactive_defense = ProactiveThreatDefense()

    def analyze_email(self, email_data: Dict, user_context: Optional[Dict] = None) -> Dict:
        """Analysiert eine E-Mail auf verschiedene Bedrohungsindikatoren"""
        self.threat_score = 0.0
        self.threat_indicators = []
        self.urls_found.clear()

        # Traditionelle regelbasierte Analyse
        sender_score = self._check_sender(email_data.get('sender', ''))
        subject_score = self._check_subject(email_data.get('subject', ''))
        body_score = self._check_body(email_data.get('body', ''))
        attachment_score = self._check_attachments(email_data.get('attachments', []))

        # ML-basierte Analyse
        ml_result = self.ml_analyzer.analyze_email(email_data)
        ml_score = ml_result.get('ml_score', 0.0)
        ml_confidence = ml_result.get('confidence', 0.0)

        # Kontextbasierte Analyse
        if user_context:
            context_result = self.context_analyzer.analyze_with_context(email_data, user_context)
            context_score = context_result.get('context_score', 0.0)
            self.threat_indicators.extend(context_result.get('role_specific_threats', []))
        else:
            context_score = 0.0

        # Cluster-basierte Analyse
        cluster_result = self.cluster_analyzer.analyze_email_patterns([email_data])
        if cluster_result.get('new_patterns'):
            self.threat_indicators.append("Neues Bedrohungsmuster erkannt")
            cluster_score = 2.0
        else:
            cluster_score = 0.0

        # Proaktive Verteidigung
        proactive_result = self.proactive_defense.analyze_trends([{
            'type': self._determine_threat_type(email_data),
            'score': (sender_score + subject_score + body_score + attachment_score) / 4,
            'indicators': self.threat_indicators.copy(),
            'target_department': user_context.get('department') if user_context else None,
            'target_role': user_context.get('role') if user_context else None
        }])

        # Gewichtete Kombination aller Scores
        weights = {
            'rule_based': 0.4,
            'ml': 0.2 if ml_confidence > 0.7 else 0.1,
            'context': 0.2 if user_context else 0.0,
            'cluster': 0.1,
            'proactive': 0.1
        }

        self.threat_score = (
            (sender_score + subject_score + body_score + attachment_score) / 4 * weights['rule_based'] +
            ml_score * weights['ml'] +
            context_score * weights['context'] +
            cluster_score * weights['cluster']
        ) / sum(weights.values())

        # Normalisierung auf 0-10 Skala
        self.threat_score = min(10.0, self.threat_score * 10)

        # Füge proaktive Empfehlungen hinzu
        if proactive_result.get('recommendations'):
            self.threat_indicators.extend(proactive_result['recommendations'])

        return {
            'score': round(self.threat_score, 2),
            'level': get_threat_level(self.threat_score, use_icon=True),
            'indicators': self.threat_indicators,
            'analyzed_urls': list(self.urls_found),
            'ml_confidence': ml_confidence,
            'context_analysis': context_result if user_context else None,
            'cluster_analysis': cluster_result,
            'trend_analysis': proactive_result
        }

    def _determine_threat_type(self, email_data: Dict) -> str:
        """Bestimmt den Typ der Bedrohung"""
        if any(ext in str(email_data.get('attachments', [])) for ext in SUSPICIOUS_EXTENSIONS['high_risk']):
            return "malware"
        elif any(kw in email_data.get('body', '').lower() for kw in ['bank', 'konto', 'password', 'anmelden']):
            return "phishing"
        elif any(kw in email_data.get('subject', '').lower() for kw in ['gewinn', 'prize', 'lottery']):
            return "scam"
        return "suspicious"

    def _perform_threat_intel_analysis(self, email_data: Dict) -> float:
        """Führt eine umfassende Threat Intelligence Analyse durch"""
        score = 0.0

        # Lokale KI-Analyse
        local_ai_result = self.threat_intel.analyze_text_local(
            f"{email_data.get('subject', '')} {email_data.get('body', '')}"
        )
        if local_ai_result.get('spam_score', 0) > 0.7:
            score += 2.0
            self.threat_indicators.append("Hohe Spam-Wahrscheinlichkeit (Lokale KI)")

        # Domain-Reputation prüfen
        sender = email_data.get('sender', '')
        if '@' in sender:
            domain = sender.split('@')[1]
            reputation = self.threat_intel.check_sender_reputation(domain)
            if reputation.get('spamhaus') == 'blacklisted' or reputation.get('surbl') == 'blacklisted':
                score += 3.0
                self.threat_indicators.append(f"Domain {domain} ist auf Blacklists")

        # URLs überprüfen
        urls = self._extract_urls(email_data.get('body', ''))
        if urls:
            url_results = self.threat_intel.check_urls(urls)
            for url, result in url_results.items():
                if result.get('safe_browsing') == 'suspicious':
                    score += 2.5
                    self.threat_indicators.append(f"Verdächtige URL gefunden: {url}")
                if result.get('phishtank') == 'suspicious':
                    score += 2.0
                    self.threat_indicators.append(f"Mögliche Phishing-URL: {url}")

        # SpamAssassin Score
        spam_score = self.threat_intel.get_spam_score(
            f"Subject: {email_data.get('subject', '')}\n\n{email_data.get('body', '')}"
        )
        if spam_score > 5.0:
            score += 1.5
            self.threat_indicators.append(f"Hoher SpamAssassin Score: {spam_score}")

        return min(10.0, score)  # Normalisiere auf max 10

    def _check_sender(self, sender: str) -> float:
        """Überprüft die Absenderadresse auf verdächtige Muster"""
        score = 0.0

        if not sender:
            self.threat_indicators.append("Fehlender Absender")
            return SCORING_WEIGHTS['sender']['suspicious_domain']

        # E-Mail-Adresse extrahieren
        email_match = re.search(r'<?([\w\.-]+@[\w\.-]+\.\w+)>?', sender)
        if not email_match:
            self.threat_indicators.append("Ungültiges E-Mail-Format")
            return SCORING_WEIGHTS['sender']['suspicious_domain']

        email = email_match.group(1).lower()
        domain = email.split('@')[1]

        # Überprüfe auf verdächtige Domain-Endungen
        if any(tld in domain for tld in SUSPICIOUS_TLD):
            self.threat_indicators.append(f"Verdächtige Domain-Endung: {domain}")
            score += SCORING_WEIGHTS['sender']['suspicious_domain']

        # Überprüfe auf gefälschte Anzeigenamen
        display_name = sender.split('<')[0].strip() if '<' in sender else ''
        if display_name and any(keyword in display_name.lower() for keyword in SUSPICIOUS_KEYWORDS['high_risk']):
            self.threat_indicators.append("Möglicherweise gefälschter Anzeigename")
            score += SCORING_WEIGHTS['sender']['spoofed_display_name']

        return score

    def _check_subject(self, subject: str) -> float:
        """Überprüft den Betreff auf verdächtige Schlüsselwörter"""
        score = 0.0
        if not subject:
            return score

        subject_lower = subject.lower()

        # Überprüfe verschiedene Risikostufen von Schlüsselwörtern
        for keyword in SUSPICIOUS_KEYWORDS['high_risk']:
            if keyword in subject_lower:
                self.threat_indicators.append(f"Hochrisiko-Schlüsselwort im Betreff: {keyword}")
                score += SCORING_WEIGHTS['subject']['high_risk_keyword']

        for keyword in SUSPICIOUS_KEYWORDS['medium_risk']:
            if keyword in subject_lower:
                self.threat_indicators.append(f"Mittleres Risiko-Schlüsselwort im Betreff: {keyword}")
                score += SCORING_WEIGHTS['subject']['medium_risk_keyword']

        for keyword in SUSPICIOUS_KEYWORDS['low_risk']:
            if keyword in subject_lower:
                self.threat_indicators.append(f"Niedrigrisiko-Schlüsselwort im Betreff: {keyword}")
                score += SCORING_WEIGHTS['subject']['low_risk_keyword']

        return score

    def _check_body(self, body: str) -> float:
        """Überprüft den E-Mail-Body auf verdächtige Inhalte"""
        score = 0.0
        if not body:
            return score

        body_lower = body.lower()

        # Schlüsselwort-Überprüfung
        for risk_level, keywords in SUSPICIOUS_KEYWORDS.items():
            for keyword in keywords:
                if keyword in body_lower:
                    weight = SCORING_WEIGHTS['body'][f'{risk_level}_keyword']
                    self.threat_indicators.append(f"{risk_level.replace('_', ' ').title()}-Schlüsselwort im Text: {keyword}")
                    score += weight

        # URL-Überprüfung
        urls = self._extract_urls(body)
        if urls:
            score += self._analyze_urls(urls)

        # Dringlichkeitssprache
        urgency_indicators = ['sofort', 'dringend', 'eilig', 'wichtig', 'warnung', 'jetzt']
        if any(indicator in body_lower for indicator in urgency_indicators):
            self.threat_indicators.append("Dringlichkeitssprache im Text")
            score += SCORING_WEIGHTS['body']['urgent_language']

        return score

    def _check_attachments(self, attachments: List[str]) -> float:
        """Überprüft Anhänge auf verdächtige Dateitypen"""
        score = 0.0
        if not attachments:
            return score

        # Mehrere Anhänge erhöhen das Risiko
        if len(attachments) > 1:
            self.threat_indicators.append(f"Mehrere Anhänge ({len(attachments)})")
            score += SCORING_WEIGHTS['attachments']['multiple_attachments']

        for attachment in attachments:
            attachment_lower = attachment.lower()

            # Überprüfe auf verschiedene Risikostufen von Dateierweiterungen
            for ext in SUSPICIOUS_EXTENSIONS['high_risk']:
                if attachment_lower.endswith(ext):
                    self.threat_indicators.append(f"Hochrisiko-Anhang: {attachment}")
                    score += SCORING_WEIGHTS['attachments']['high_risk_extension']
                    break

            for ext in SUSPICIOUS_EXTENSIONS['medium_risk']:
                if attachment_lower.endswith(ext):
                    self.threat_indicators.append(f"Mittleres Risiko-Anhang: {attachment}")
                    score += SCORING_WEIGHTS['attachments']['medium_risk_extension']
                    break

            for ext in SUSPICIOUS_EXTENSIONS['low_risk']:
                if attachment_lower.endswith(ext):
                    self.threat_indicators.append(f"Niedrigrisiko-Anhang: {attachment}")
                    score += SCORING_WEIGHTS['attachments']['low_risk_extension']
                    break

        return score

    def _extract_urls(self, text: str) -> List[str]:
        """Extrahiert URLs aus dem Text"""
        urls = []
        for pattern in SUSPICIOUS_URL_PATTERNS:
            urls.extend(re.findall(pattern, text))
        return list(set(urls))  # Entferne Duplikate

    def _analyze_urls(self, urls: List[str]) -> float:
        """Analysiert gefundene URLs auf Verdächtigkeit"""
        score = 0.0
        self.urls_found.update(urls)

        if len(urls) > 3:
            self.threat_indicators.append(f"Viele URLs gefunden ({len(urls)})")
            score += SCORING_WEIGHTS['body']['multiple_urls']

        for url in urls:
            try:
                parsed = urlparse(url if '://' in url else 'http://' + url)
                domain = parsed.netloc.lower()

                # Überprüfe auf verdächtige TLDs
                if any(tld in domain for tld in SUSPICIOUS_TLD):
                    self.threat_indicators.append(f"Verdächtige URL-Domain: {domain}")
                    score += SCORING_WEIGHTS['body']['suspicious_url']

                # Optional: URL-Überprüfung gegen Phishing-Datenbanken
                # Dies könnte in einer erweiterten Version implementiert werden

            except Exception as e:
                logging.warning(f"Fehler bei der URL-Analyse: {str(e)}")

        return score

