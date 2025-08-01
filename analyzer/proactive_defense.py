
"""Module for proactive threat trend analysis.

This module contains the :class:`ProactiveThreatDefense` which keeps a
light‑weight history of analyzed e‑mails. From this history it derives simple
trend metrics and naive forecasts that can be consumed by the
``ThreatAnalyzer`` and the Qt based ``ThreatDashboard``.

The goal of the implementation is not to be statistically perfect but to
offer structured results that can easily be extended.  External dependencies
are intentionally kept minimal in order to remain easy to run in testing
environments.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional


@dataclass
class ThreatRecord:
    """Internal representation of a single threat entry.

    Attributes:
        timestamp: Time when the threat was recorded.
        type: Categorised threat type (e.g. ``"phishing"``).
        score: Normalised severity score between 0 and 10.
        indicators: List of textual indicators that lead to the score.
        target_department: Optional department information for targeted mails.
        target_role: Optional role information for targeted mails.
    """

    timestamp: datetime
    type: str
    score: float
    indicators: List[str] = field(default_factory=list)
    target_department: Optional[str] = None
    target_role: Optional[str] = None


class ProactiveThreatDefense:
    """Analyse historical e‑mail threats to identify trends.

    The class stores a history of :class:`ThreatRecord` instances.  Calling
    :meth:`analyze_trends` with new e‑mails extends this history and returns
    aggregated statistics that are used by :class:`ThreatAnalyzer` and
    :class:`ThreatDashboard`.
    """

    def __init__(self) -> None:
        self._history: List[ThreatRecord] = []

    # ------------------------------------------------------------------
    def analyze_trends(self, emails: List[Dict]) -> Dict[str, Dict]:
        """Analyse current threat trends and optionally update the history.

        Args:
            emails: List of dictionaries describing detected threats. Each
                dictionary should at least provide ``type`` and ``score``
                keys.  Additional metadata such as ``indicators`` or
                ``target_department`` is stored for potential later use.  The
                list may be empty when only the current trend information is
                required (e.g. by the dashboard).

        Returns:
            Dict[str, Dict]: A dictionary with three main keys:

            ``window_analysis``
                Statistics for predefined time windows (24h, 7d, 30d). Each
                window contains ``total_threats``, ``avg_severity`` and a
                ``type_distribution`` mapping.

            ``forecasts``
                Naive forecasts for the next 24 hours and the next week as well
                as a very rough ``confidence`` indicator.

            ``recommendations``
                List of human readable recommendations derived from the recent
                history (e.g. which threat type is most common).

        The method deliberately uses simple calculations to stay lightweight
        but covers common edge cases such as empty histories or missing
        fields in input dictionaries.
        """

        now = datetime.now()

        # ------------------------------------------------------------------
        # Update history with new threat entries
        for email in emails or []:
            record = ThreatRecord(
                timestamp=email.get("timestamp", now),
                type=email.get("type", "unknown"),
                score=float(email.get("score", 0.0)),
                indicators=list(email.get("indicators", [])),
                target_department=email.get("target_department"),
                target_role=email.get("target_role"),
            )
            self._history.append(record)

        # ------------------------------------------------------------------
        # Analyse different time windows
        windows = {
            "short": timedelta(hours=24),
            "medium": timedelta(days=7),
            "long": timedelta(days=30),
        }

        window_analysis: Dict[str, Dict[str, object]] = {}
        for name, delta in windows.items():
            start_time = now - delta
            window_records = [r for r in self._history if r.timestamp >= start_time]

            if window_records:
                avg_severity = sum(r.score for r in window_records) / len(window_records)
                type_counts = Counter(r.type for r in window_records)
            else:  # No data in this window
                avg_severity = 0.0
                type_counts = Counter()

            window_analysis[name] = {
                "total_threats": len(window_records),
                "avg_severity": round(avg_severity, 2),
                "type_distribution": dict(type_counts),
            }

        # ------------------------------------------------------------------
        # Simple forecasts based on recent averages
        short_total = window_analysis["short"]["total_threats"] or 0
        medium_total = window_analysis["medium"]["total_threats"] or 0

        # Use last 24h count as forecast for next 24h
        predicted_24h = int(short_total)

        # Average per day over the last week to forecast the coming week
        predicted_week = int((medium_total / 7) * 7) if medium_total else 0

        forecasts = {
            "next_24h": {"predicted_threats": predicted_24h},
            "next_week": {"predicted_threats": predicted_week},
            # confidence grows with available data but is capped to 0.99
            "confidence": round(min(len(self._history) / 100, 0.99), 2),
        }

        # ------------------------------------------------------------------
        # Generate simple recommendations
        recommendations: List[str] = []
        short_dist = window_analysis["short"]["type_distribution"]
        if short_dist:
            dominant = max(short_dist, key=short_dist.get)
            recommendations.append(
                f"Verstärkte Überwachung für {dominant}-Mails empfohlen"
            )

        if window_analysis["short"]["avg_severity"] > 7:
            recommendations.append(
                "Hohe durchschnittliche Schwere im letzten Tag beobachten"
            )

        return {
            "window_analysis": window_analysis,
            "forecasts": forecasts,
            "recommendations": recommendations,
        }
