"""
Threat Clustering System
Erkennt automatisch neue Bedrohungsmuster durch Clustering ähnlicher E-Mails
"""
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Optional
import json
import os

class ThreatClusterAnalyzer:
    def __init__(self, storage_dir: str = "models/clusters"):
        self.storage_dir = storage_dir
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)

        self.cluster_history_file = os.path.join(storage_dir, "cluster_history.json")
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.clustering = DBSCAN(
            eps=0.3,          # Maximale Distanz zwischen Samples im Cluster
            min_samples=3,    # Minimale Anzahl von Samples pro Cluster
            metric='cosine'
        )

        self.cluster_history = self._load_cluster_history()
        self.current_clusters = {}
        self.detection_window = timedelta(hours=24)  # Zeitfenster für Clustering

    def analyze_email_patterns(self, new_emails: List[Dict]) -> Dict:
        """Analysiert neue E-Mails auf Clustering-Muster"""
        if not new_emails:
            return {}

        try:
            # Feature-Extraktion
            email_features = [
                self._extract_email_features(email)
                for email in new_emails
            ]

            # Vektorisierung
            X = self.vectorizer.fit_transform(email_features)

            # Clustering
            labels = self.clustering.fit_predict(X)

            # Analyse der Cluster
            clusters = {}
            for i, label in enumerate(labels):
                if label != -1:  # Ignoriere Noise-Points
                    if label not in clusters:
                        clusters[label] = []
                    clusters[label].append(new_emails[i])

            # Identifiziere neue Bedrohungsmuster
            new_patterns = self._identify_new_patterns(clusters)

            # Update Cluster-Historie
            self._update_cluster_history(new_patterns)

            return {
                "clusters": clusters,
                "new_patterns": new_patterns,
                "total_clusters": len(clusters),
                "noise_points": list(labels).count(-1)
            }

        except Exception as e:
            logging.error(f"Fehler bei der Cluster-Analyse: {str(e)}")
            return {}

    def _extract_email_features(self, email: Dict) -> str:
        """Extrahiert Features für das Clustering"""
        features = []

        # Basis-Features
        features.append(email.get("subject", ""))
        features.append(email.get("body", ""))

        # Sender-Domain
        sender = email.get("sender", "")
        if "@" in sender:
            features.append(f"domain_{sender.split('@')[1]}")

        # Anhänge
        attachments = email.get("attachments", [])
        for att in attachments:
            features.append(f"attachment_{os.path.splitext(att)[1]}")

        # URLs
        if "analyzed_urls" in email:
            for url in email["analyzed_urls"]:
                features.append(f"url_{url}")

        # Bedrohungsindikatoren
        if "indicators" in email:
            features.extend(email["indicators"])

        return " ".join(features)

    def _identify_new_patterns(self, clusters: Dict) -> List[Dict]:
        """Identifiziert neue Bedrohungsmuster in den Clustern"""
        new_patterns = []

        for cluster_id, emails in clusters.items():
            # Berechne Cluster-Charakteristiken
            common_indicators = self._find_common_indicators(emails)
            threat_scores = [email.get("score", 0) for email in emails]
            avg_score = np.mean(threat_scores)

            # Prüfe ob ähnliches Muster bereits bekannt
            if not self._is_known_pattern(common_indicators):
                pattern = {
                    "id": f"pattern_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{cluster_id}",
                    "timestamp": datetime.now().isoformat(),
                    "characteristics": common_indicators,
                    "avg_threat_score": avg_score,
                    "sample_size": len(emails),
                    "examples": [
                        {
                            "subject": email.get("subject", ""),
                            "indicators": email.get("indicators", [])
                        }
                        for email in emails[:3]  # Nur die ersten 3 Beispiele
                    ]
                }
                new_patterns.append(pattern)

        return new_patterns

    def _find_common_indicators(self, emails: List[Dict]) -> Dict:
        """Findet gemeinsame Indikatoren in einem Cluster"""
        all_indicators = []
        domains = []
        attachments = []
        urls = []

        for email in emails:
            all_indicators.extend(email.get("indicators", []))

            if "@" in email.get("sender", ""):
                domains.append(email["sender"].split("@")[1])

            attachments.extend(email.get("attachments", []))
            urls.extend(email.get("analyzed_urls", []))

        # Finde häufige Elemente
        from collections import Counter

        return {
            "common_indicators": [
                ind for ind, count in Counter(all_indicators).items()
                if count >= len(emails) * 0.5  # Mindestens in 50% der E-Mails
            ],
            "common_domains": [
                dom for dom, count in Counter(domains).items()
                if count >= len(emails) * 0.3
            ],
            "common_attachment_types": [
                os.path.splitext(att)[1] for att, count in Counter(attachments).items()
                if count >= len(emails) * 0.3
            ],
            "common_url_patterns": [
                url for url, count in Counter(urls).items()
                if count >= len(emails) * 0.3
            ]
        }

    def _is_known_pattern(self, characteristics: Dict) -> bool:
        """Prüft ob ein ähnliches Muster bereits bekannt ist"""
        if not self.cluster_history:
            return False

        for pattern in self.cluster_history:
            if pattern.get("characteristics"):
                # Berechne Ähnlichkeit der Indikatoren
                known_indicators = set(pattern["characteristics"].get("common_indicators", []))
                new_indicators = set(characteristics.get("common_indicators", []))

                if known_indicators and new_indicators:
                    similarity = len(known_indicators & new_indicators) / len(known_indicators | new_indicators)
                    if similarity > 0.7:  # 70% Ähnlichkeit
                        return True

        return False

    def _load_cluster_history(self) -> List[Dict]:
        """Lädt die Cluster-Historie"""
        try:
            if os.path.exists(self.cluster_history_file):
                with open(self.cluster_history_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logging.error(f"Fehler beim Laden der Cluster-Historie: {str(e)}")
            return []

    def _update_cluster_history(self, new_patterns: List[Dict]) -> None:
        """Aktualisiert die Cluster-Historie"""
        try:
            # Füge neue Muster hinzu
            self.cluster_history.extend(new_patterns)

            # Begrenze Historie auf die letzten 1000 Muster
            if len(self.cluster_history) > 1000:
                self.cluster_history = self.cluster_history[-1000:]

            # Speichere aktualisierte Historie
            with open(self.cluster_history_file, 'w') as f:
                json.dump(self.cluster_history, f, indent=2)

        except Exception as e:
            logging.error(f"Fehler beim Aktualisieren der Cluster-Historie: {str(e)}")

    def get_cluster_statistics(self) -> Dict:
        """Liefert Statistiken über erkannte Cluster"""
        stats = {
            "total_patterns": len(self.cluster_history),
            "patterns_last_24h": 0,
            "avg_threat_score": 0.0,
            "common_characteristics": {
                "indicators": [],
                "domains": [],
                "attachment_types": [],
                "url_patterns": []
            }
        }

        if not self.cluster_history:
            return stats

        # Analysiere Muster der letzten 24 Stunden
        cutoff = datetime.now() - timedelta(hours=24)
        recent_patterns = [
            pattern for pattern in self.cluster_history
            if datetime.fromisoformat(pattern["timestamp"]) > cutoff
        ]

        stats["patterns_last_24h"] = len(recent_patterns)

        # Berechne durchschnittlichen Bedrohungsscore
        scores = [p.get("avg_threat_score", 0) for p in self.cluster_history]
        if scores:
            stats["avg_threat_score"] = np.mean(scores)

        # Sammle häufige Charakteristiken
        all_characteristics = {
            "indicators": [],
            "domains": [],
            "attachment_types": [],
            "url_patterns": []
        }

        for pattern in self.cluster_history:
            chars = pattern.get("characteristics", {})
            all_characteristics["indicators"].extend(chars.get("common_indicators", []))
            all_characteristics["domains"].extend(chars.get("common_domains", []))
            all_characteristics["attachment_types"].extend(chars.get("common_attachment_types", []))
            all_characteristics["url_patterns"].extend(chars.get("common_url_patterns", []))

        # Finde häufigste Elemente
        from collections import Counter
        for key in all_characteristics:
            if all_characteristics[key]:
                stats["common_characteristics"][key] = [
                    item for item, count in Counter(all_characteristics[key]).most_common(5)
                ]

        return stats
