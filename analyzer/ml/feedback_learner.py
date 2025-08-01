"""
Feedback Learning System
Lernt automatisch aus Benutzerinteraktionen und passt die Analyse entsprechend an
"""
import os
import json
import logging
from typing import Dict, List

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from datetime import datetime


class FeedbackLearner:
    def __init__(
        self,
        model_dir: str = "models/feedback",
        original_weight: float = 0.7,
        feedback_weight: float = 0.3,
        feedback_scale: float = 10.0,
        confidence_threshold: float = 0.8,
        high_confidence_threshold: float = 0.9,
    ):
        """Initialisiere FeedbackLearner.

        Args:
            model_dir: Verzeichnis zur Speicherung des Modells.
            original_weight: Gewicht der ursprünglichen Analyse.
            feedback_weight: Gewicht des Feedback-Modells.
            feedback_scale: Skalierung des Feedback-Scores.
            confidence_threshold: Mindestkonfidenz für Anpassungen.
            high_confidence_threshold: Schwelle für das Hinzufügen eines Indikators.
        """
        self.model_dir = model_dir
        self.feedback_file = os.path.join(model_dir, "feedback_data.json")
        self.model_file = os.path.join(model_dir, "feedback_model.joblib")
        self.vectorizer_file = os.path.join(model_dir, "feedback_vectorizer.joblib")
        self.version_file = os.path.join(model_dir, "feedback_model.version")

        os.makedirs(model_dir, exist_ok=True)

        self.feedback_data = self._load_feedback_data()
        self.model = self._load_model()
        self.vectorizer = self._load_vectorizer()

        # Schwellenwerte für Modellanpassung
        self.min_feedback_samples = 50
        self.retraining_threshold = 10  # Neue Samples für Neutraining

        # Gewichtungen für adjust_analysis
        self.original_weight = original_weight
        self.feedback_weight = feedback_weight
        self.feedback_scale = feedback_scale
        self.confidence_threshold = confidence_threshold
        self.high_confidence_threshold = high_confidence_threshold

    def add_feedback(self, email_data: Dict, analysis_result: Dict, user_feedback: Dict) -> None:
        """
        Speichert Benutzerfeedback für eine analysierte E-Mail

        user_feedback = {
            "is_correct": bool,
            "correct_category": str,  # "spam", "phishing", "safe", etc.
            "notes": str
        }
        """
        feedback_entry = {
            "timestamp": datetime.now().isoformat(),
            "email_data": {
                "subject": email_data.get("subject", ""),
                "sender": email_data.get("sender", ""),
                "has_attachments": bool(email_data.get("attachments", [])),
                "body_length": len(email_data.get("body", "")),
            },
            "analysis": {
                "score": analysis_result.get("score", 0),
                "level": analysis_result.get("level", "LOW"),
                "indicators": analysis_result.get("indicators", [])
            },
            "user_feedback": user_feedback
        }

        self.feedback_data.append(feedback_entry)
        self._save_feedback_data()

        # Prüfe ob Neutraining erforderlich
        if len(self.feedback_data) >= self.min_feedback_samples and \
           len(self.feedback_data) % self.retraining_threshold == 0:
            self._retrain_model()

    def adjust_analysis(self, email_data: Dict, preliminary_analysis: Dict) -> Dict:
        """Passt die Analyse basierend auf gelerntem Feedback an"""
        if not self.model or not self.vectorizer:
            return preliminary_analysis

        try:
            # Feature-Extraktion
            features = self._extract_features(email_data)
            X = self.vectorizer.transform([features])

            # Vorhersage
            feedback_score = self.model.predict_proba(X)[0]
            confidence = max(feedback_score)

            # Wenn Konfidenz hoch genug, passe Analyse an
            if confidence > self.confidence_threshold:
                adjusted_score = (
                    preliminary_analysis["score"] * self.original_weight +
                    feedback_score[1] * self.feedback_scale * self.feedback_weight
                )

                preliminary_analysis["score"] = min(10.0, adjusted_score)
                preliminary_analysis["feedback_confidence"] = confidence

                if confidence > self.high_confidence_threshold:
                    preliminary_analysis["indicators"].append(
                        "Anpassung basierend auf Unternehmensfeedback"
                    )

            return preliminary_analysis

        except Exception as e:
            logging.error(f"Fehler bei der Feedback-basierten Anpassung: {str(e)}")
            return preliminary_analysis

    def get_learning_stats(self) -> Dict:
        """Liefert Statistiken über das Lernverhalten"""
        if not self.feedback_data:
            return {"error": "Keine Feedback-Daten verfügbar"}

        total_samples = len(self.feedback_data)
        correct_predictions = sum(
            1 for entry in self.feedback_data
            if entry["user_feedback"]["is_correct"]
        )

        categories = {}
        for entry in self.feedback_data:
            cat = entry["user_feedback"]["correct_category"]
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_samples": total_samples,
            "accuracy": correct_predictions / total_samples,
            "category_distribution": categories,
            "last_retrain": self._get_last_retrain_date(),
            "model_version": self._get_model_version()
        }

    def _extract_features(self, email_data: Dict) -> str:
        """Extrahiert Features für das Feedback-Modell"""
        features = []

        # Kombiniere relevante E-Mail-Eigenschaften
        features.append(email_data.get("subject", ""))
        features.append(email_data.get("sender", ""))

        # Füge Metadaten hinzu
        attachments = email_data.get("attachments", [])
        features.append(f"has_attachments_{bool(attachments)}")
        features.append(f"attachment_count_{len(attachments)}")

        # Extrahiere Domain
        if "@" in email_data.get("sender", ""):
            features.append(f"domain_{email_data['sender'].split('@')[1]}")

        return " ".join(features)

    def _retrain_model(self) -> None:
        """Trainiert das Feedback-Modell neu"""
        try:
            # Bereite Trainingsdaten vor
            X_text = [
                self._extract_features(entry["email_data"])
                for entry in self.feedback_data
            ]

            y = [
                1 if entry["user_feedback"]["is_correct"] else 0
                for entry in self.feedback_data
            ]

            # Trainiere Vectorizer und Modell
            self.vectorizer = TfidfVectorizer(max_features=1000)
            X = self.vectorizer.fit_transform(X_text)

            self.model = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                random_state=42
            )
            self.model.fit(X, y)

            # Speichere Modelle
            self._save_models()
            logging.info("Feedback-Modell erfolgreich neu trainiert")

        except Exception as e:
            logging.error(f"Fehler beim Neutraining des Feedback-Modells: {str(e)}")

    def _load_feedback_data(self) -> List:
        """Lädt gespeicherte Feedback-Daten"""
        try:
            if os.path.exists(self.feedback_file):
                with open(self.feedback_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logging.error(f"Fehler beim Laden der Feedback-Daten: {str(e)}")
            return []

    def _save_feedback_data(self) -> None:
        """Speichert Feedback-Daten"""
        try:
            with open(self.feedback_file, 'w') as f:
                json.dump(self.feedback_data, f, indent=2)
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Feedback-Daten: {str(e)}")

    def _load_model(self):
        """Lädt das gespeicherte Feedback-Modell"""
        try:
            if os.path.exists(self.model_file):
                return joblib.load(self.model_file)
            return GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                random_state=42
            )
        except Exception as e:
            logging.error(f"Fehler beim Laden des Feedback-Modells: {str(e)}")
            return None

    def _load_vectorizer(self):
        """Lädt den gespeicherten Vectorizer"""
        try:
            if os.path.exists(self.vectorizer_file):
                return joblib.load(self.vectorizer_file)
            return TfidfVectorizer(max_features=1000)
        except Exception as e:
            logging.error(f"Fehler beim Laden des Vectorizers: {str(e)}")
            return None

    def _save_models(self) -> None:
        """Speichert Modell, Vectorizer und Version"""
        try:
            joblib.dump(self.model, self.model_file)
            joblib.dump(self.vectorizer, self.vectorizer_file)
            with open(self.version_file, "w", encoding="utf-8") as version_file:
                version_file.write(datetime.now().isoformat())
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Modelle: {str(e)}")

    def _get_last_retrain_date(self) -> str:
        """Ermittelt das Datum des letzten Trainings"""
        try:
            return datetime.fromtimestamp(
                os.path.getmtime(self.model_file)
            ).isoformat()
        except Exception:
            return "Unbekannt"

    def _get_model_version(self) -> str:
        """Liest die gespeicherte Modellversion"""
        try:
            with open(self.version_file, "r", encoding="utf-8") as version_file:
                return version_file.read().strip()
        except Exception:
            return "unbekannt"
