"""
Lokale KI-Modelle Integration (Ollama und DeepSeek)
"""
import os
import json
import logging
from typing import Dict, Optional, List
import httpx
from concurrent.futures import ThreadPoolExecutor

class LocalAIHandler:
    def __init__(self):
        self.ollama_url = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
        self.deepseek_url = os.getenv('DEEPSEEK_HOST', 'http://localhost:8080')
        self.models = {
            'ollama': {
                'model': 'llama2',  # Standard-Modell, kann in der Konfiguration geändert werden
                'available': self._check_ollama_available()
            },
            'deepseek': {
                'model': 'deepseek-coder',  # Standard-Modell
                'available': self._check_deepseek_available()
            }
        }

    def _check_ollama_available(self) -> bool:
        """Prüft, ob Ollama verfügbar ist"""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.ollama_url}/api/tags")
                return response.status_code == 200
        except Exception as e:
            logging.warning(f"Ollama nicht verfügbar: {str(e)}")
            return False

    def _check_deepseek_available(self) -> bool:
        """Prüft, ob DeepSeek verfügbar ist"""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.deepseek_url}/v1/models")
                return response.status_code == 200
        except Exception as e:
            logging.warning(f"DeepSeek nicht verfügbar: {str(e)}")
            return False

    async def analyze_email_content(self, email_data: Dict) -> Dict:
        """Analysiert E-Mail-Inhalt mit verfügbaren lokalen KI-Modellen"""
        results = {}

        # Bereite den Prompt vor
        prompt = self._prepare_email_prompt(email_data)

        # Parallel-Analyse mit verfügbaren Modellen
        with ThreadPoolExecutor() as executor:
            if self.models['ollama']['available']:
                ollama_future = executor.submit(self._analyze_with_ollama, prompt)
            if self.models['deepseek']['available']:
                deepseek_future = executor.submit(self._analyze_with_deepseek, prompt)

            # Sammle Ergebnisse
            if self.models['ollama']['available']:
                results['ollama'] = ollama_future.result()
            if self.models['deepseek']['available']:
                results['deepseek'] = deepseek_future.result()

        return self._combine_analysis_results(results)

    def _prepare_email_prompt(self, email_data: Dict) -> str:
        """Bereitet den Prompt für die KI-Analyse vor"""
        return f"""Analysiere diese E-Mail auf potenzielle Bedrohungen:

Betreff: {email_data.get('subject', '')}
Von: {email_data.get('sender', '')}
Anhänge: {', '.join(email_data.get('attachments', []))}

Inhalt:
{email_data.get('body', '')}

Bewerte folgende Aspekte:
1. Spam-Wahrscheinlichkeit (0-1)
2. Phishing-Indikatoren
3. Verdächtige URLs oder Anhänge
4. Dringlichkeitsmerkmale
5. Gesamtrisikobewertung (0-10)

Antworte im JSON-Format."""

    def _analyze_with_ollama(self, prompt: str) -> Dict:
        """Führt Analyse mit Ollama durch"""
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.models['ollama']['model'],
                        "prompt": prompt,
                        "stream": False
                    }
                )
                response.raise_for_status()
                result = response.json()

                # Versuche JSON aus der Antwort zu extrahieren
                try:
                    return json.loads(result['response'])
                except:
                    # Fallback für nicht-JSON Antworten
                    return {
                        "error": "Konnte Ollama-Antwort nicht parsen",
                        "raw_response": result['response']
                    }

        except Exception as e:
            logging.error(f"Fehler bei Ollama-Analyse: {str(e)}")
            return {"error": str(e)}

    def _analyze_with_deepseek(self, prompt: str) -> Dict:
        """Führt Analyse mit DeepSeek durch"""
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    f"{self.deepseek_url}/v1/chat/completions",
                    json={
                        "model": self.models['deepseek']['model'],
                        "messages": [
                            {"role": "system", "content": "Du bist ein E-Mail-Sicherheitsexperte."},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.3
                    }
                )
                response.raise_for_status()
                result = response.json()

                try:
                    return json.loads(result['choices'][0]['message']['content'])
                except:
                    return {
                        "error": "Konnte DeepSeek-Antwort nicht parsen",
                        "raw_response": result['choices'][0]['message']['content']
                    }

        except Exception as e:
            logging.error(f"Fehler bei DeepSeek-Analyse: {str(e)}")
            return {"error": str(e)}

    def _combine_analysis_results(self, results: Dict) -> Dict:
        """Kombiniert die Ergebnisse der verschiedenen Modelle"""
        combined = {
            "spam_score": 0.0,
            "risk_score": 0.0,
            "indicators": [],
            "confidence": 0.0,
            "model_scores": {}
        }

        valid_results = 0

        for model, result in results.items():
            if "error" not in result:
                combined["model_scores"][model] = {
                    "spam_score": result.get("spam_probability", 0.0),
                    "risk_score": result.get("overall_risk", 0.0)
                }

                # Akkumuliere Scores
                combined["spam_score"] += result.get("spam_probability", 0.0)
                combined["risk_score"] += result.get("overall_risk", 0.0)

                # Sammle eindeutige Indikatoren
                if "indicators" in result:
                    combined["indicators"].extend(result["indicators"])

                valid_results += 1

        # Berechne Durchschnitte
        if valid_results > 0:
            combined["spam_score"] /= valid_results
            combined["risk_score"] /= valid_results
            combined["confidence"] = valid_results / len(results)  # Konfidenz basierend auf verfügbaren Modellen

        # Entferne Duplikate aus Indikatoren
        combined["indicators"] = list(set(combined["indicators"]))

        return combined
