"""
Dashboard für Bedrohungsanalyse und Trends
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QComboBox, QScrollArea,
    QFrame, QGridLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtChart import (
    QChart, QChartView, QPieSeries, QLineSeries,
    QValueAxis, QBarSeries, QBarSet
)
import pandas as pd
import numpy as np
from typing import Dict, List
from datetime import datetime, timedelta

class ThreatDashboard(QWidget):
    def __init__(self, threat_analyzer, parent=None):
        super().__init__(parent)
        self.threat_analyzer = threat_analyzer
        self.initUI()

        # Auto-Update Timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(300000)  # Alle 5 Minuten aktualisieren

    def initUI(self):
        layout = QVBoxLayout(self)

        # Obere Leiste mit Kontrollelementen
        control_bar = QHBoxLayout()
        update_btn = QPushButton("Aktualisieren")
        update_btn.clicked.connect(self.update_dashboard)

        time_range = QComboBox()
        time_range.addItems(["24 Stunden", "7 Tage", "30 Tage"])
        time_range.currentTextChanged.connect(self.update_dashboard)

        control_bar.addWidget(update_btn)
        control_bar.addWidget(QLabel("Zeitraum:"))
        control_bar.addWidget(time_range)
        control_bar.addStretch()

        layout.addLayout(control_bar)

        # Tabs für verschiedene Ansichten
        tabs = QTabWidget()

        # Übersichts-Tab
        overview_tab = self._create_overview_tab()
        tabs.addTab(overview_tab, "Übersicht")

        # Trend-Tab
        trends_tab = self._create_trends_tab()
        tabs.addTab(trends_tab, "Trends")

        # Cluster-Tab
        clusters_tab = self._create_clusters_tab()
        tabs.addTab(clusters_tab, "Cluster")

        # Vorhersage-Tab
        forecast_tab = self._create_forecast_tab()
        tabs.addTab(forecast_tab, "Vorhersagen")

        layout.addWidget(tabs)

        self.update_dashboard()

    def _create_overview_tab(self) -> QWidget:
        """Erstellt den Übersichts-Tab mit wichtigen Metriken"""
        tab = QWidget()
        layout = QGridLayout(tab)

        # Bedrohungslevel-Verteilung (Tortendiagramm)
        threat_chart = QChart()
        threat_series = QPieSeries()
        threat_series.append("Hoch", 0)
        threat_series.append("Mittel", 0)
        threat_series.append("Niedrig", 0)

        threat_chart.addSeries(threat_series)
        threat_chart.setTitle("Bedrohungslevel-Verteilung")

        threat_view = QChartView(threat_chart)
        layout.addWidget(threat_view, 0, 0)

        # Aktivitätsverlauf (Liniendiagramm)
        activity_chart = QChart()
        activity_series = QLineSeries()

        activity_chart.addSeries(activity_series)
        activity_chart.setTitle("Aktivitätsverlauf")

        activity_view = QChartView(activity_chart)
        layout.addWidget(activity_view, 0, 1)

        # Statistik-Widgets
        stats_frame = QFrame()
        stats_frame.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Sunken)
        stats_layout = QVBoxLayout(stats_frame)

        self.stats_labels = {
            'total': QLabel("Analysierte E-Mails: 0"),
            'threats': QLabel("Erkannte Bedrohungen: 0"),
            'accuracy': QLabel("Erkennungsgenauigkeit: 0%")
        }

        for label in self.stats_labels.values():
            stats_layout.addWidget(label)

        layout.addWidget(stats_frame, 1, 0)

        return tab

    def _create_trends_tab(self) -> QWidget:
        """Erstellt den Trends-Tab mit Trendanalysen"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Trend-Diagramm
        trend_chart = QChart()
        self.trend_series = QLineSeries()

        trend_chart.addSeries(self.trend_series)
        trend_chart.setTitle("Bedrohungstrends")

        # Achsen
        axis_x = QValueAxis()
        axis_x.setTitleText("Zeit")
        trend_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        self.trend_series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setTitleText("Bedrohungslevel")
        trend_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        self.trend_series.attachAxis(axis_y)

        trend_view = QChartView(trend_chart)
        layout.addWidget(trend_view)

        # Trend-Details
        details_frame = QFrame()
        details_layout = QVBoxLayout(details_frame)

        self.trend_labels = {
            'direction': QLabel("Trendrichtung: -"),
            'velocity': QLabel("Veränderungsrate: -"),
            'forecast': QLabel("Prognose: -")
        }

        for label in self.trend_labels.values():
            details_layout.addWidget(label)

        layout.addWidget(details_frame)

        return tab

    def _create_clusters_tab(self) -> QWidget:
        """Erstellt den Cluster-Tab mit Bedrohungsmustern"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Cluster-Visualisierung
        cluster_chart = QChart()
        self.cluster_series = QBarSeries()

        cluster_chart.addSeries(self.cluster_series)
        cluster_chart.setTitle("Bedrohungsmuster")

        cluster_view = QChartView(cluster_chart)
        layout.addWidget(cluster_view)

        # Cluster-Details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        details_widget = QWidget()
        self.cluster_layout = QVBoxLayout(details_widget)

        scroll.setWidget(details_widget)
        layout.addWidget(scroll)

        return tab

    def _create_forecast_tab(self) -> QWidget:
        """Erstellt den Vorhersage-Tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Vorhersage-Diagramm
        forecast_chart = QChart()
        self.forecast_series = QLineSeries()

        forecast_chart.addSeries(self.forecast_series)
        forecast_chart.setTitle("Bedrohungsvorhersage")

        # Achsen
        axis_x = QValueAxis()
        axis_x.setTitleText("Zeit")
        forecast_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        self.forecast_series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setTitleText("Vorhergesagtes Bedrohungslevel")
        forecast_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        self.forecast_series.attachAxis(axis_y)

        forecast_view = QChartView(forecast_chart)
        layout.addWidget(forecast_view)

        # Vorhersage-Details
        details_frame = QFrame()
        details_layout = QVBoxLayout(details_frame)

        self.forecast_labels = {
            'next_24h': QLabel("Nächste 24h: -"),
            'next_week': QLabel("Nächste Woche: -"),
            'confidence': QLabel("Konfidenz: -")
        }

        for label in self.forecast_labels.values():
            details_layout.addWidget(label)

        layout.addWidget(details_frame)

        return tab

    def update_dashboard(self):
        """Aktualisiert alle Dashboard-Komponenten"""
        try:
            # Hole aktuelle Daten
            trends = self.threat_analyzer.proactive_defense.analyze_trends([])
            clusters = self.threat_analyzer.cluster_analyzer.analyze_email_patterns([])

            # Aktualisiere Übersicht
            self._update_overview_charts(trends)

            # Aktualisiere Trends
            self._update_trend_charts(trends)

            # Aktualisiere Cluster
            self._update_cluster_view(clusters)

            # Aktualisiere Vorhersagen
            self._update_forecasts(trends)

        except Exception as e:
            print(f"Fehler beim Aktualisieren des Dashboards: {str(e)}")

    def _update_overview_charts(self, trends: Dict):
        """Aktualisiert die Übersichts-Diagramme"""
        if not trends:
            return

        # Aktualisiere Statistiken
        stats = trends.get('window_analysis', {}).get('short', {})
        if stats:
            self.stats_labels['total'].setText(f"Analysierte E-Mails: {stats.get('total_threats', 0)}")
            self.stats_labels['threats'].setText(
                f"Erkannte Bedrohungen: {sum(stats.get('type_distribution', {}).values())}"
            )

    def _update_trend_charts(self, trends: Dict):
        """Aktualisiert die Trend-Diagramme"""
        if not trends:
            return

        # Aktualisiere Trendlinien
        self.trend_series.clear()

        trend_data = trends.get('window_analysis', {})
        for window, data in trend_data.items():
            if 'avg_severity' in data:
                self.trend_series.append(
                    datetime.now().timestamp(),
                    data['avg_severity']
                )

    def _update_cluster_view(self, clusters: Dict):
        """Aktualisiert die Cluster-Visualisierung"""
        if not clusters:
            return

        # Lösche alte Cluster-Details
        for i in reversed(range(self.cluster_layout.count())):
            self.cluster_layout.itemAt(i).widget().setParent(None)

        # Füge neue Cluster hinzu
        for cluster_id, data in clusters.get('clusters', {}).items():
            label = QLabel(f"Cluster {cluster_id}")
            label.setStyleSheet("font-weight: bold;")
            self.cluster_layout.addWidget(label)

            details = QLabel(f"Größe: {len(data)}\nHäufige Merkmale: {', '.join(data[:3])}")
            self.cluster_layout.addWidget(details)

    def _update_forecasts(self, trends: Dict):
        """Aktualisiert die Vorhersage-Visualisierung"""
        if not trends:
            return

        forecasts = trends.get('forecasts', {})

        # Aktualisiere Vorhersage-Labels
        if 'next_24h' in forecasts:
            self.forecast_labels['next_24h'].setText(
                f"Nächste 24h: {forecasts['next_24h'].get('predicted_threats', 0)} Bedrohungen"
            )

        if 'next_week' in forecasts:
            self.forecast_labels['next_week'].setText(
                f"Nächste Woche: {forecasts['next_week'].get('predicted_threats', 0)} Bedrohungen"
            )

        # Aktualisiere Vorhersage-Linie
        self.forecast_series.clear()
        current_time = datetime.now().timestamp()

        for i in range(24):  # 24-Stunden-Vorhersage
            if 'next_24h' in forecasts:
                self.forecast_series.append(
                    current_time + i * 3600,  # Stündliche Punkte
                    forecasts['next_24h'].get('predicted_threats', 0)
                )
