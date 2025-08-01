"""
Threat Intelligence Modul
Integriert verschiedene Malware- und Spam-Datenbanken sowie KI-Modelle
"""
import os
import hashlib
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

try:  # pragma: no cover - optionale Abhängigkeiten
    import requests
except Exception:  # pragma: no cover
    requests = None

try:  # pragma: no cover
    from transformers import pipeline
except Exception:  # pragma: no cover
    pipeline = None

try:  # pragma: no cover
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover
    SentenceTransformer = None

try:  # pragma: no cover
    import torch
except Exception:  # pragma: no cover
    torch = None

from .local_ai_handler import LocalAIHandler

class ThreatIntelligence:
    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuse_ipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.local_ai = LocalAIHandler()
        self.model = None
        self.transformer = None
        self._initialize_ai_models()

    def _initialize_ai_models(self):
        """Initialisiert die lokalen KI-Modelle"""
        if pipeline is None or SentenceTransformer is None or torch is None:
            logging.warning("Transformers-Bibliotheken nicht verfügbar. KI-Analyse deaktiviert.")
            self.model = None
            self.transformer = None
            return

        try:
            # Lade das kleinere BERT-Modell für Textklassifikation
            self.model = pipeline(
                "text-classification",
                model="bert-base-german-cased",
                device=-1 if not torch.cuda.is_available() else 0
            )

            # Lade SentenceTransformer für semantische Analyse
            self.transformer = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
            logging.info("KI-Modelle erfolgreich geladen")

        except Exception as e:  # pragma: no cover - Modellladefehler
            logging.error(f"Fehler beim Laden der KI-Modelle: {str(e)}")
            self.model = None
            self.transformer = None

    def analyze_attachment(self, file_path: str) -> Dict:
        """Analysiert einen E-Mail-Anhang mit VirusTotal"""
        try:
            if not self.vt_api_key:
                return {"error": "Kein VirusTotal API-Schlüssel konfiguriert"}

            # Berechne Datei-Hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # VirusTotal API Abfrage
            headers = {
                "x-apikey": self.vt_api_key
            }
            if requests is None:
                return {"error": "requests nicht verfügbar"}

            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "clean": stats.get('undetected', 0),
                    "engines": data['data']['attributes']['last_analysis_results']
                }
            else:
                return {"error": f"VirusTotal API Fehler: {response.status_code}"}

        except Exception as e:
            logging.error(f"Fehler bei der VirusTotal-Analyse: {str(e)}")
            return {"error": str(e)}

    def check_urls(self, urls: List[str]) -> Dict[str, Dict]:
        """Überprüft URLs gegen verschiedene Datenbanken"""
        results = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {
                executor.submit(self._check_single_url, url): url
                for url in urls
            }

            for future in future_to_url:
                url = future_to_url[future]
                try:
                    results[url] = future.result()
                except Exception as e:
                    results[url] = {"error": str(e)}

        return results

    def _check_single_url(self, url: str) -> Dict:
        """Überprüft eine einzelne URL gegen verschiedene Datenbanken"""
        results = {}

        # Google Safe Browsing API Check
        try:
            safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            payload = {
                "client": {
                    "clientId": "your-client-id",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            if requests is None:
                results["safe_browsing"] = "error"
            else:
                response = requests.post(safe_browsing_url, json=payload)
                results["safe_browsing"] = "clean" if response.status_code == 200 and not response.json() else "suspicious"
        except Exception:  # pragma: no cover - Netzwerkausnahme
            results["safe_browsing"] = "error"

        # PhishTank Check
        try:
            phishtank_url = f"http://checkurl.phishtank.com/checkurl/"
            if requests is None:
                results["phishtank"] = "error"
            else:
                response = requests.post(phishtank_url, data={"url": url})
                results["phishtank"] = "suspicious" if "phish" in response.text.lower() else "clean"
        except Exception:  # pragma: no cover
            results["phishtank"] = "error"

        return results

    def analyze_text_local(self, text: str) -> Dict:
        """Analysiert Text mit lokalen KI-Modellen"""
        result = {
            "spam_score": 0.0,
            "threat_type": "unknown",
            "confidence": 0.0
        }

        try:
            # Lokale KI-Analyse mit Ollama/DeepSeek
            local_ai_result = self.local_ai.analyze_email_content({
                "subject": "",  # Wird später gefüllt
                "body": text,
                "sender": "",
                "attachments": []
            })

            if local_ai_result:
                result.update({
                    "spam_score": local_ai_result.get("spam_score", 0.0),
                    "confidence": local_ai_result.get("confidence", 0.0),
                    "indicators": local_ai_result.get("indicators", []),
                    "model_scores": local_ai_result.get("model_scores", {})
                })

            # Fallback auf transformers wenn lokale KI nicht verfügbar
            if result["confidence"] < 0.5 and self.transformer:
                # Semantische Analyse mit vordefinierten Bedrohungsmustern
                threat_patterns = [
                    "Dies ist eine dringende Zahlungsaufforderung",
                    "Ihr Konto wurde gesperrt",
                    "Gewinnen Sie einen Preis"
                ]

                # Berechne Text-Embedding
                text_embedding = self.transformer.encode(text)
                pattern_embeddings = self.transformer.encode(threat_patterns)

                # Berechne Ähnlichkeiten
                similarities = torch.nn.functional.cosine_similarity(
                    torch.tensor(text_embedding).unsqueeze(0),
                    torch.tensor(pattern_embeddings),
                    dim=1
                )

                # Höchste Ähnlichkeit als Spam-Score
                result["spam_score"] = float(similarities.max())

        except Exception as e:
            logging.error(f"Fehler bei der lokalen KI-Analyse: {str(e)}")

        return result

    def check_sender_reputation(self, sender_domain: str) -> Dict:
        """Überprüft die Reputation einer Absender-Domain"""
        results = {}

        # Spamhaus ZEN Check
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            query = f"{sender_domain}.zen.spamhaus.org"
            resolver.query(query, "A")
            results["spamhaus"] = "blacklisted"
        except:
            results["spamhaus"] = "clean"

        # SURBL Check
        try:
            query = f"{sender_domain}.multi.surbl.org"
            resolver.query(query, "A")
            results["surbl"] = "blacklisted"
        except:
            results["surbl"] = "clean"

        return results

    def get_spam_score(self, email_content: str) -> float:
        """Berechnet einen Spam-Score basierend auf SpamAssassin-Regeln"""
        try:
            import spamassassin
            sa = spamassassin.SpamAssassin()
            score = sa.score(email_content)
            return score
        except:
            return 0.0
