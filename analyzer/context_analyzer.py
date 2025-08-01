"""
Kontext-bewusstes Learning System
Berücksichtigt Unternehmensstruktur und Benutzerrollen bei der Bedrohungsanalyse
"""
import os
import json
import logging
from typing import Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import joblib

# Gewichtungen für abteilungsspezifische Analyse
SENDER_MATCH_WEIGHT = 0.3
SUBJECT_MATCH_WEIGHT = 0.3
MAX_CLEARANCE_BONUS = 0.4

class ContextAwareAnalyzer:
    def __init__(self, storage_dir: str = "models/context"):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)

        self.context_file = os.path.join(storage_dir, "organization_context.json")
        self.models_dir = os.path.join(storage_dir, "role_models")
        os.makedirs(self.models_dir, exist_ok=True)

        self.org_context = self._load_organization_context()
        self.role_models = {}
        self._load_role_models()

    def analyze_with_context(self, email_data: Dict, user_context: Dict) -> Dict:
        """
        Analysiert eine E-Mail unter Berücksichtigung des Benutzer- und Organisationskontexts

        user_context = {
            "department": str,
            "role": str,
            "clearance_level": int,  # 1-5
            "common_contacts": List[str]  # Häufige Kontakte
        }
        """
        analysis = {
            "context_score": 0.0,
            "context_factors": [],
            "role_specific_threats": [],
            "suggested_actions": []
        }

        try:
            # Rollenbasierte Analyse
            role_score = self._analyze_role_specific(email_data, user_context)

            # Abteilungsspezifische Analyse
            dept_score = self._analyze_department_specific(email_data, user_context)

            # Kontaktbasierte Analyse
            contact_score = self._analyze_contact_patterns(email_data, user_context)

            # Kombination der Scores
            analysis["context_score"] = self._combine_scores(
                role_score, dept_score, contact_score
            )

            # Anomalie-Erkennung für den spezifischen Kontext
            if self._is_contextual_anomaly(email_data, user_context):
                analysis["context_factors"].append(
                    "Ungewöhnliches Kommunikationsmuster für diese Rolle/Abteilung"
                )

            # Rollenspezifische Bedrohungen
            threats = self._get_role_specific_threats(email_data, user_context)
            if threats:
                analysis["role_specific_threats"].extend(threats)

            # Handlungsempfehlungen
            analysis["suggested_actions"] = self._generate_actions(
                analysis["context_score"],
                user_context
            )

        except Exception as e:
            logging.error(f"Fehler bei der Kontextanalyse: {str(e)}")

        return analysis

    def update_organization_context(self, context_data: Dict) -> None:
        """Aktualisiert den Organisationskontext mit neuen Informationen"""
        try:
            self.org_context.update(context_data)
            self._save_organization_context()

            # Aktualisiere Modelle bei signifikanten Änderungen
            if self._requires_model_update(context_data):
                self._retrain_role_models()

        except Exception as e:
            logging.error(f"Fehler beim Aktualisieren des Organisationskontexts: {str(e)}")

    def add_communication_pattern(self, pattern_data: Dict) -> None:
        """
        Fügt ein neues Kommunikationsmuster hinzu

        pattern_data = {
            "department": str,
            "role": str,
            "sender": str,
            "frequency": str,  # "daily", "weekly", "monthly"
            "typical_subjects": List[str],
            "typical_times": List[str],
            "importance": int  # 1-5
        }
        """
        try:
            if "communication_patterns" not in self.org_context:
                self.org_context["communication_patterns"] = []

            self.org_context["communication_patterns"].append({
                **pattern_data,
                "added": datetime.now().isoformat()
            })

            self._save_organization_context()
            self._update_role_model(pattern_data["role"])

        except Exception as e:
            logging.error(f"Fehler beim Hinzufügen des Kommunikationsmusters: {str(e)}")

    def _analyze_role_specific(self, email_data: Dict, user_context: Dict) -> float:
        """Analysiert E-Mail basierend auf der Benutzerrolle"""
        role = user_context.get("role")
        if not role or role not in self.role_models:
            return 0.0

        try:
            model = self.role_models[role]
            features = self._extract_role_features(email_data, user_context)

            # Anomalie-Score (-1 bis 1, wobei -1 am anomalsten)
            score = model.score_samples([features])[0]

            # Normalisiere auf 0-1 Skala
            return (score + 1) / 2

        except Exception as e:
            logging.error(f"Fehler bei der rollenspezifischen Analyse: {str(e)}")
            return 0.0

    def _analyze_department_specific(self, email_data: Dict, user_context: Dict) -> float:
        """Analysiert E-Mail im Kontext der Abteilung"""
        department = user_context.get("department")
        if not department:
            return 0.0

        score = 0.0
        dept_patterns = self._get_department_patterns(department)

        if dept_patterns:
            # Prüfe typische Kommunikationsmuster
            sender_match = any(
                pattern["sender"] == email_data.get("sender")
                for pattern in dept_patterns
            )
            score += SENDER_MATCH_WEIGHT if sender_match else 0

            # Prüfe übliche Betreffzeilen
            subject = email_data.get("subject", "").lower()
            subject_match = any(
                any(s.lower() in subject for s in pattern.get("typical_subjects", []))
                for pattern in dept_patterns
            )
            score += SUBJECT_MATCH_WEIGHT if subject_match else 0

            # Berücksichtige Clearance-Level
            clearance = user_context.get("clearance_level", 1)
            score += min(clearance / 10, MAX_CLEARANCE_BONUS)

        return score

    def _analyze_contact_patterns(self, email_data: Dict, user_context: Dict) -> float:
        """Analysiert E-Mail basierend auf bekannten Kontaktmustern"""
        common_contacts = set(user_context.get("common_contacts", []))
        sender = email_data.get("sender", "")

        if not common_contacts or not sender:
            return 0.0

        # Grundvertrauen für bekannte Kontakte
        if sender in common_contacts:
            return 0.8

        # Prüfe auf ähnliche Domains
        sender_domain = sender.split('@')[1] if '@' in sender else ""
        if sender_domain:
            for contact in common_contacts:
                if '@' in contact and contact.split('@')[1] == sender_domain:
                    return 0.5

        return 0.2  # Grundwert für unbekannte Absender

    def _is_contextual_anomaly(self, email_data: Dict, user_context: Dict) -> bool:
        """Erkennt kontextbezogene Anomalien"""
        patterns = self.org_context.get("communication_patterns", [])
        role_patterns = [p for p in patterns if p["role"] == user_context.get("role")]

        if not role_patterns:
            return False

        anomalies = []

        # Prüfe Zeitliche Muster
        current_hour = datetime.now().hour
        typical_hours = set()
        for pattern in role_patterns:
            typical_hours.update(int(t.split(':')[0]) for t in pattern.get("typical_times", []))

        if typical_hours and current_hour not in typical_hours:
            anomalies.append("Unübliche Zeit für diese Kommunikation")

        # Prüfe Absender-Muster
        typical_senders = {p["sender"] for p in role_patterns}
        if typical_senders and email_data.get("sender") not in typical_senders:
            anomalies.append("Unüblicher Absender für diese Rolle")

        return len(anomalies) > 0

    def _get_role_specific_threats(self, email_data: Dict, user_context: Dict) -> List[str]:
        """Identifiziert rollenspezifische Bedrohungen"""
        threats = []
        role = user_context.get("role", "").lower()

        # Beispiel-Mapping von Rollen zu spezifischen Bedrohungen
        role_threats = {
            "finance": [
                ("bank", "Möglicher Banking-Trojaner"),
                ("rechnung", "Gefälschte Rechnung"),
                ("zahlung", "Gefälschte Zahlungsaufforderung")
            ],
            "hr": [
                ("bewerbung", "Gefälschte Bewerbung"),
                ("lebenslauf", "Manipulierter Lebenslauf"),
                ("vertrag", "Gefälschter Arbeitsvertrag")
            ],
            "it": [
                ("admin", "Gefälschte Admin-Anfrage"),
                ("passwort", "Passwort-Phishing"),
                ("zugang", "Unbefugter Zugriffsversuch")
            ]
        }

        if role in role_threats:
            content = f"{email_data.get('subject', '')} {email_data.get('body', '')}".lower()
            for keyword, threat in role_threats[role]:
                if keyword in content:
                    threats.append(threat)

        return threats

    def _generate_actions(self, context_score: float, user_context: Dict) -> List[str]:
        """Generiert kontextspezifische Handlungsempfehlungen"""
        actions = []
        clearance = user_context.get("clearance_level", 1)

        if context_score < 0.3:
            actions.append("Sofort IT-Sicherheit informieren")
            actions.append("E-Mail nicht öffnen oder beantworten")

        elif context_score < 0.6:
            if clearance >= 4:
                actions.append("Eigenständige Prüfung durch erfahrenen Mitarbeiter")
            else:
                actions.append("Vorgesetzten zur Prüfung vorlegen")

        else:
            actions.append("Normale Vorsichtsmaßnahmen beachten")

        return actions

    def _combine_scores(self, role_score: float, dept_score: float, contact_score: float) -> float:
        """Kombiniert verschiedene Kontext-Scores"""
        weights = {
            'role': 0.4,
            'department': 0.3,
            'contact': 0.3
        }

        combined = (
            role_score * weights['role'] +
            dept_score * weights['department'] +
            contact_score * weights['contact']
        )

        return min(1.0, max(0.0, combined))

    def _extract_role_features(self, email_data: Dict, user_context: Dict) -> np.ndarray:
        """Extrahiert Features für die rollenspezifische Analyse"""
        features = []

        # Zeitliche Features
        hour = datetime.now().hour
        features.append(hour / 24.0)  # Normalisierte Stunde

        # Sender-Features
        sender = email_data.get("sender", "")
        known_contact = 1.0 if sender in user_context.get("common_contacts", []) else 0.0
        features.append(known_contact)

        # Berechtigungslevel
        clearance = user_context.get("clearance_level", 1)
        features.append(clearance / 5.0)  # Normalisiert auf 0-1

        # Anhang-Features
        has_attachments = 1.0 if email_data.get("attachments") else 0.0
        features.append(has_attachments)

        return np.array(features)

    def _load_organization_context(self) -> Dict:
        """Lädt den Organisationskontext"""
        try:
            if os.path.exists(self.context_file):
                with open(self.context_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logging.error(f"Fehler beim Laden des Organisationskontexts: {str(e)}")
            return {}

    def _save_organization_context(self) -> None:
        """Speichert den Organisationskontext"""
        try:
            with open(self.context_file, 'w') as f:
                json.dump(self.org_context, f, indent=2)
        except Exception as e:
            logging.error(f"Fehler beim Speichern des Organisationskontexts: {str(e)}")

    def _load_role_models(self) -> None:
        """Lädt die rollenspezifischen Modelle"""
        try:
            for role in self.org_context.get("roles", []):
                model_path = os.path.join(self.models_dir, f"{role}_model.joblib")
                if os.path.exists(model_path):
                    self.role_models[role] = joblib.load(model_path)
                else:
                    self.role_models[role] = IsolationForest(
                        contamination=0.1,
                        random_state=42
                    )
        except Exception as e:
            logging.error(f"Fehler beim Laden der Rollenmodelle: {str(e)}")

    def _save_role_model(self, role: str) -> None:
        """Speichert ein rollenspezifisches Modell"""
        try:
            if role in self.role_models:
                model_path = os.path.join(self.models_dir, f"{role}_model.joblib")
                joblib.dump(self.role_models[role], model_path)
        except Exception as e:
            logging.error(f"Fehler beim Speichern des Rollenmodells: {str(e)}")

    def _update_role_model(self, role: str) -> None:
        """Aktualisiert ein rollenspezifisches Modell"""
        if role not in self.role_models:
            self.role_models[role] = IsolationForest(
                contamination=0.1,
                random_state=42
            )
        self._save_role_model(role)

    def _requires_model_update(self, context_data: Dict) -> bool:
        """Prüft ob die Modelle aktualisiert werden müssen"""
        # Prüfe auf signifikante Änderungen im Kontext
        return any(
            key in context_data for key in
            ['roles', 'departments', 'communication_patterns']
        )

    def _get_department_patterns(self, department: str) -> List[Dict]:
        """Holt die Kommunikationsmuster einer Abteilung"""
        patterns = self.org_context.get("communication_patterns", [])
        return [p for p in patterns if p.get("department") == department]
