"""
Machine Learning Komponente für die E-Mail-Analyse
Implementiert ein lokales Modell, das kontinuierlich aus den analysierten E-Mails lernt
"""
import os
import pickle

try:  # pragma: no cover - optionale Abhängigkeit
    import joblib
except Exception:  # pragma: no cover
    joblib = None

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error
import logging
from typing import Dict, List, Tuple, Optional
import json

class MLAnalyzer:
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.vectorizer_path = os.path.join(model_dir, "vectorizer.joblib")
        self.model_path = os.path.join(model_dir, "email_classifier.joblib")
        self.training_data_path = os.path.join(model_dir, "training_data.json")

        # Erstelle Modellverzeichnis, falls nicht vorhanden
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)

        # Lade oder initialisiere Modelle
        self.vectorizer = self._load_vectorizer()
        self.model = self._load_model()
        self.training_data = self._load_training_data()

    def analyze_email(self, email_data: Dict) -> Dict:
        """Analysiert eine E-Mail mit dem ML-Modell"""
        try:
            if not self.model or not self.vectorizer:
                return {"ml_score": 0.0, "confidence": 0.0}

            # Feature-Extraktion
            features = self._extract_features(email_data)
            X = self.vectorizer.transform([features])

            # Vorhersage
            prediction = self.model.predict(X)[0]

            return {
                "ml_score": float(prediction),
                # Bei Regressionsmodellen liegen keine Wahrscheinlichkeiten vor.
                # Wir geben daher eine konstante Konfidenz von 1.0 zurück.
                "confidence": 1.0,
                "ml_features": self._get_important_features(features)
            }

        except Exception as e:
            logging.error(f"Fehler bei der ML-Analyse: {str(e)}")
            return {"ml_score": 0.0, "confidence": 0.0}

    def train(self, email_data: Dict, threat_score: float):
        """Trainiert das Modell mit einer neuen E-Mail"""
        try:
            # Speichere Trainingsdaten
            features = self._extract_features(email_data)
            self.training_data.append({
                "features": features,
                "score": threat_score,
                "metadata": {
                    "timestamp": email_data.get("timestamp", ""),
                    "sender_domain": email_data.get("sender", "").split("@")[-1],
                }
            })

            # Trainiere neu, wenn genügend neue Daten vorhanden sind
            if len(self.training_data) % 10 == 0:  # Alle 10 E-Mails neu trainieren
                self._retrain_model()
                self._save_training_data()

        except Exception as e:
            logging.error(f"Fehler beim Training: {str(e)}")

    def _extract_features(self, email_data: Dict) -> str:
        """Extrahiert Features aus einer E-Mail"""
        features = []

        # Kombiniere relevante E-Mail-Felder
        features.append(email_data.get("subject", ""))
        features.append(email_data.get("body", ""))
        features.append(email_data.get("sender", ""))

        # Füge Anhangsinformationen hinzu
        attachments = email_data.get("attachments", [])
        features.extend([os.path.splitext(att)[1] for att in attachments])

        return " ".join(features)

    def _retrain_model(self):
        """Trainiert das Modell neu mit allen verfügbaren Daten"""
        if len(self.training_data) < 10:
            return

        # Bereite Trainingsdaten vor
        X = [item["features"] for item in self.training_data]
        y = [item["score"] for item in self.training_data]

        # Aktualisiere Vectorizer
        self.vectorizer = TfidfVectorizer(max_features=1000)
        X_vectorized = self.vectorizer.fit_transform(X)

        # Aufteilung in Trainings- und Testdaten zur Auswertung
        X_train, X_test, y_train, y_test = train_test_split(
            X_vectorized, y, test_size=0.2, random_state=42
        )

        # Trainiere Regressionsmodell
        self.model = RandomForestRegressor(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)

        # Bewertung des Modells
        predictions = self.model.predict(X_test)
        mse = mean_squared_error(y_test, predictions)
        logging.info(f"ML-Modell neu trainiert. MSE: {mse:.4f}")

        # Speichere aktualisierte Modelle
        self._save_models()

    def _get_important_features(self, features: str) -> List[Tuple[str, float]]:
        """Ermittelt die wichtigsten Features für die Klassifizierung"""
        if not self.model or not self.vectorizer:
            return []

        # Transformiere Features
        feature_vector = self.vectorizer.transform([features])

        # Hole Feature-Namen und Wichtigkeiten
        feature_names = self.vectorizer.get_feature_names_out()
        importances = self.model.feature_importances_

        # Finde die wichtigsten Features
        important_features = []
        for i, importance in enumerate(importances):
            if importance > 0.01:  # Nur Features mit Wichtigkeit > 1%
                important_features.append((feature_names[i], float(importance)))

        return sorted(important_features, key=lambda x: x[1], reverse=True)[:5]

    def _load_vectorizer(self) -> Optional[TfidfVectorizer]:
        """Lädt den gespeicherten Vectorizer oder erstellt einen neuen"""
        try:
            if os.path.exists(self.vectorizer_path):
                if joblib:
                    return joblib.load(self.vectorizer_path)
                with open(self.vectorizer_path, "rb") as f:
                    return pickle.load(f)
            return TfidfVectorizer(max_features=1000)
        except Exception as e:
            logging.error(f"Fehler beim Laden des Vectorizers: {str(e)}")
            return TfidfVectorizer(max_features=1000)

    def _load_model(self) -> Optional[RandomForestRegressor]:
        """Lädt das gespeicherte Modell oder erstellt ein neues"""
        try:
            if os.path.exists(self.model_path):
                if joblib:
                    return joblib.load(self.model_path)
                with open(self.model_path, "rb") as f:
                    return pickle.load(f)
            return RandomForestRegressor(n_estimators=100, random_state=42)
        except Exception as e:
            logging.error(f"Fehler beim Laden des Modells: {str(e)}")
            return RandomForestRegressor(n_estimators=100, random_state=42)

    def _load_training_data(self) -> List:
        """Lädt gespeicherte Trainingsdaten"""
        try:
            if os.path.exists(self.training_data_path):
                with open(self.training_data_path, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logging.error(f"Fehler beim Laden der Trainingsdaten: {str(e)}")
            return []

    def _save_models(self):
        """Speichert Vectorizer und Modell"""
        try:
            if joblib:
                joblib.dump(self.vectorizer, self.vectorizer_path)
                joblib.dump(self.model, self.model_path)
            else:
                with open(self.vectorizer_path, "wb") as f:
                    pickle.dump(self.vectorizer, f)
                with open(self.model_path, "wb") as f:
                    pickle.dump(self.model, f)
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Modelle: {str(e)}")

    def _save_training_data(self):
        """Speichert Trainingsdaten"""
        try:
            with open(self.training_data_path, 'w') as f:
                json.dump(self.training_data, f)
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Trainingsdaten: {str(e)}")
