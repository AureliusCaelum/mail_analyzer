"""
Hauptfenster der Mail Analyzer GUI
"""
import sys
import os
import configparser
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QLabel, QTextEdit, QPushButton,
    QTabWidget, QSplitter, QProgressBar, QMessageBox, QComboBox,
    QDialog, QFormLayout, QLineEdit, QDialogButtonBox, QProgressDialog
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from datetime import datetime
from PyQt6.QtGui import QColor, QFont, QAction

from analyzer.email_scanner import get_scanner
from analyzer.threat_analyzer import ThreatAnalyzer
from analyzer.traffic_light import TrafficLight
from analyzer.update_manager import UpdateManager
from config.settings import MAX_EMAILS_TO_SCAN, THREAT_LEVELS
from analyzer.report_generator import ReportGenerator
from .threat_dashboard import ThreatDashboard
from .context_config import ContextRuleConfig

class ClientSettingsDialog(QDialog):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self.initUI()

    def initUI(self):
        self.setWindowTitle('E-Mail-Client Einstellungen')
        layout = QFormLayout()

        # Client-Auswahl
        self.client_combo = QComboBox()
        self.client_combo.addItems(['outlook', 'gmail', 'exchange'])
        current_client = self.config.get('EMAIL', 'client', fallback='outlook')
        self.client_combo.setCurrentText(current_client)
        layout.addRow('E-Mail-Client:', self.client_combo)

        # Gmail-Einstellungen
        self.gmail_creds = QLineEdit(self.config.get('GMAIL', 'credentials_file', fallback='credentials.json'))
        layout.addRow('Gmail Credentials File:', self.gmail_creds)

        # Exchange-Einstellungen
        self.exchange_client_id = QLineEdit(self.config.get('EXCHANGE', 'client_id', fallback=''))
        self.exchange_tenant_id = QLineEdit(self.config.get('EXCHANGE', 'tenant_id', fallback=''))
        self.exchange_secret = QLineEdit(self.config.get('EXCHANGE', 'client_secret', fallback=''))
        self.exchange_secret.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addRow('Exchange Client ID:', self.exchange_client_id)
        layout.addRow('Exchange Tenant ID:', self.exchange_tenant_id)
        layout.addRow('Exchange Client Secret:', self.exchange_secret)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

        self.setLayout(layout)

    def get_settings(self):
        return {
            'client': self.client_combo.currentText(),
            'gmail_credentials': self.gmail_creds.text(),
            'exchange_client_id': self.exchange_client_id.text(),
            'exchange_tenant_id': self.exchange_tenant_id.text(),
            'exchange_secret': self.exchange_secret.text()
        }

class EmailListItem(QListWidgetItem):
    def __init__(self, email_data, analysis_result):
        super().__init__()
        self.email_data = email_data
        self.analysis_result = analysis_result
        self.setText(f"{email_data['subject'][:50]}...")
        self._set_color_by_threat_level()

    def _set_color_by_threat_level(self):
        level = self.analysis_result['level']
        if level == THREAT_LEVELS["HIGH"]:
            self.setBackground(QColor(255, 200, 200))  # Hellrot
        elif level == THREAT_LEVELS["MEDIUM"]:
            self.setBackground(QColor(255, 255, 200))  # Hellgelb
        else:
            self.setBackground(QColor(200, 255, 200))  # Hellgrün


class EmailRefreshWorker(QThread):
    """Worker-Thread zum Abrufen und Analysieren von E-Mails."""

    progress = pyqtSignal(int, int)
    result = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, scanner, analyzer, parent=None):
        super().__init__(parent)
        self._scanner = scanner
        self._analyzer = analyzer

    def run(self):
        """Führt das Laden und Analysieren der E-Mails aus."""
        try:
            emails = self._scanner.get_emails(max_count=MAX_EMAILS_TO_SCAN)
            total = len(emails) or 1
            results = []

            for index, email in enumerate(emails, start=1):
                analysis = self._analyzer.analyze_email(email)
                results.append((email, analysis))
                self.progress.emit(index, total)

            self.result.emit(results)
        except Exception as exc:  # pragma: no cover - GUI feedback
            self.error.emit(str(exc))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.analyzer = ThreatAnalyzer()
        self.traffic_light = TrafficLight()
        self.config = configparser.ConfigParser()
        self.config.read('configuration.ini')
        self.scanner = get_scanner()
        self.update_manager = UpdateManager()
        self.report_generator = ReportGenerator()

        # Timer für automatische Updates
        self.update_check_timer = QTimer()
        self.update_check_timer.timeout.connect(self.check_for_updates)
        self.update_check_timer.start(86400000)  # Einmal täglich prüfen

        self.initUI()

        # Sofortige Update-Prüfung beim Start
        QTimer.singleShot(1000, self.check_for_updates)

    def initUI(self):
        self.setWindowTitle('Mail Analyzer')
        self.setGeometry(100, 100, 1200, 800)

        # Hauptlayout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)

        # Splitter für flexible Größenanpassung
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # Linke Seite - E-Mail-Liste
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        # Client-Auswahl und Einstellungen
        client_layout = QHBoxLayout()
        self.client_label = QLabel(f"Aktiver Client: {self.scanner._client.name if self.scanner._client else 'Nicht verbunden'}")
        self.settings_button = QPushButton("Client Einstellungen")
        self.settings_button.clicked.connect(self.show_client_settings)
        client_layout.addWidget(self.client_label)
        client_layout.addWidget(self.settings_button)
        left_layout.addLayout(client_layout)

        # Aktualisieren-Button und Fortschrittsanzeige
        refresh_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Aktualisieren")
        self.refresh_button.clicked.connect(self.refresh_emails)
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        refresh_layout.addWidget(self.refresh_button)
        refresh_layout.addWidget(self.progress_bar)
        left_layout.addLayout(refresh_layout)

        # E-Mail-Liste
        self.email_list = QListWidget()
        self.email_list.itemClicked.connect(self.show_email_details)
        left_layout.addWidget(self.email_list)

        splitter.addWidget(left_widget)

        # Rechte Seite - Details
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        # Tabs für verschiedene Ansichten
        self.tab_widget = QTabWidget()

        # Übersicht-Tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        self.threat_level_label = QLabel()
        self.threat_level_label.setFont(QFont('Arial', 14, QFont.Weight.Bold))
        overview_layout.addWidget(self.threat_level_label)

        self.email_details = QTextEdit()
        self.email_details.setReadOnly(True)
        overview_layout.addWidget(self.email_details)

        # Analyse-Tab
        analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(analysis_tab)
        self.analysis_details = QTextEdit()
        self.analysis_details.setReadOnly(True)
        analysis_layout.addWidget(self.analysis_details)

        # Rohdaten-Tab
        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        self.raw_email = QTextEdit()
        self.raw_email.setReadOnly(True)
        raw_layout.addWidget(self.raw_email)

        # Tabs hinzufügen
        self.tab_widget.addTab(overview_tab, "Übersicht")
        self.tab_widget.addTab(analysis_tab, "Analyse")
        self.tab_widget.addTab(raw_tab, "Rohdaten")

        right_layout.addWidget(self.tab_widget)
        splitter.addWidget(right_widget)

        # Initiale Größenverteilung
        splitter.setSizes([400, 800])

        # Erste E-Mail-Liste laden
        self.refresh_emails()

        # Menüleiste erstellen
        menubar = self.menuBar()

        # Hilfe-Menü
        help_menu = menubar.addMenu('&Hilfe')

        # Update-Aktion
        check_update_action = QAction('Nach Updates suchen', self)
        check_update_action.triggered.connect(self.check_for_updates)
        help_menu.addAction(check_update_action)

        # Über-Aktion
        about_action = QAction('Über Mail Analyzer', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        # Berichte-Menü
        reports_menu = menubar.addMenu('&Berichte')

        # PDF-Bericht erstellen
        pdf_report_action = QAction('PDF-Bericht erstellen', self)
        pdf_report_action.triggered.connect(self.create_pdf_report)
        reports_menu.addAction(pdf_report_action)

        # Excel-Bericht erstellen
        excel_report_action = QAction('Excel-Bericht erstellen', self)
        excel_report_action.triggered.connect(self.create_excel_report)
        reports_menu.addAction(excel_report_action)

        # Statistiken anzeigen
        stats_action = QAction('Statistiken anzeigen', self)
        stats_action.triggered.connect(self.show_statistics)
        reports_menu.addAction(stats_action)

        reports_menu.addSeparator()

        # Automatische Berichte
        auto_reports_menu = reports_menu.addMenu('Automatische Berichte')

        daily_report_action = QAction('Täglicher Bericht aktivieren', self)
        daily_report_action.setCheckable(True)
        daily_report_action.triggered.connect(lambda: self.toggle_auto_reports('daily'))
        auto_reports_menu.addAction(daily_report_action)

        weekly_report_action = QAction('Wöchentlicher Bericht aktivieren', self)
        weekly_report_action.setCheckable(True)
        weekly_report_action.triggered.connect(lambda: self.toggle_auto_reports('weekly'))
        auto_reports_menu.addAction(weekly_report_action)

        # Menüleiste erweitern
        menubar = self.menuBar()

        # Ansicht-Menü
        view_menu = menubar.addMenu('&Ansicht')

        # Dashboard-Aktion
        show_dashboard_action = QAction('Dashboard', self)
        show_dashboard_action.triggered.connect(self.show_dashboard)
        view_menu.addAction(show_dashboard_action)

        # Einstellungen-Menü
        settings_menu = menubar.addMenu('&Einstellungen')

        # Kontext-Regeln
        context_rules_action = QAction('Kontext-Regeln', self)
        context_rules_action.triggered.connect(self.show_context_rules)
        settings_menu.addAction(context_rules_action)

    def show_client_settings(self):
        dialog = ClientSettingsDialog(self.config, self)
        if dialog.exec():
            settings = dialog.get_settings()

            # Konfiguration aktualisieren
            self.config['EMAIL']['client'] = settings['client']
            self.config['GMAIL']['credentials_file'] = settings['gmail_credentials']
            self.config['EXCHANGE']['client_id'] = settings['exchange_client_id']
            self.config['EXCHANGE']['tenant_id'] = settings['exchange_tenant_id']
            self.config['EXCHANGE']['client_secret'] = settings['exchange_secret']

            # Konfiguration speichern
            with open('configuration.ini', 'w') as configfile:
                self.config.write(configfile)

            # Scanner neu initialisieren
            self.scanner = get_scanner()
            self.refresh_emails()

            self.client_label.setText(f"Aktiver Client: {self.scanner._client.name if self.scanner._client else 'Nicht verbunden'}")

    def refresh_emails(self):
        """Startet das asynchrone Aktualisieren der E-Mail-Liste."""
        self.progress_bar.show()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.refresh_button.setEnabled(False)
        self.email_list.clear()

        self._refresh_worker = EmailRefreshWorker(self.scanner, self.analyzer)
        self._refresh_worker.progress.connect(self._update_refresh_progress)
        self._refresh_worker.result.connect(self._populate_email_list)
        self._refresh_worker.error.connect(self._handle_refresh_error)
        self._refresh_worker.finished.connect(self._refresh_finished)
        self._refresh_worker.start()

    def _update_refresh_progress(self, current, total):
        """Aktualisiert den Fortschrittsbalken während des Ladens."""
        total = total or 1
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(min(current, total))

    def _populate_email_list(self, results):
        """Füllt die E-Mail-Liste mit den vom Worker gelieferten Daten."""
        for email, analysis in results:
            item = EmailListItem(email, analysis)
            self.email_list.addItem(item)

    def _handle_refresh_error(self, message):
        """Zeigt eine Fehlermeldung aus dem Worker an."""
        QMessageBox.critical(self, "Fehler", f"Fehler beim Laden der E-Mails: {message}")

    def _refresh_finished(self):
        """Beendet den Aktualisierungsvorgang und stellt den UI-Zustand wieder her."""
        self.progress_bar.hide()
        self.refresh_button.setEnabled(True)
        self._refresh_worker = None

    def show_email_details(self, item):
        """Zeigt Details der ausgewählten E-Mail"""
        email = item.email_data
        analysis = item.analysis_result

        # Bedrohungslevel-Anzeige
        threat_text = self.traffic_light.get_recommendation(analysis)
        self.threat_level_label.setText(
            f"Bedrohungslevel: {analysis['level']} (Score: {analysis['score']})"
        )

        # Übersicht-Tab
        details_text = (
            f"Betreff: {email['subject']}\n"
            f"Von: {email['sender']}\n\n"
            f"Bedrohungseinschätzung:\n{threat_text}\n\n"
            f"Anhänge: {', '.join(email['attachments']) if email['attachments'] else 'Keine'}"
        )
        self.email_details.setText(details_text)

        # Analyse-Tab
        analysis_text = "Gefundene Indikatoren:\n\n"
        for indicator in analysis['indicators']:
            analysis_text += f"• {indicator}\n"

        if 'analyzed_urls' in analysis and analysis['analyzed_urls']:
            analysis_text += "\nGefundene URLs:\n"
            for url in analysis['analyzed_urls']:
                analysis_text += f"• {url}\n"

        self.analysis_details.setText(analysis_text)

        # Rohdaten-Tab
        raw_text = f"E-Mail-Body:\n\n{email['body']}"
        self.raw_email.setText(raw_text)

    def check_for_updates(self):
        """Prüft auf verfügbare Updates"""
        update_info = self.update_manager.check_for_updates()

        if update_info:
            reply = QMessageBox.question(
                self,
                'Update verfügbar',
                f'Eine neue Version ({update_info["version"]}) ist verfügbar!\n\n'
                f'Änderungen:\n{update_info["description"]}\n\n'
                'Möchten Sie das Update jetzt herunterladen und installieren?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.download_and_install_update(update_info)

    def download_and_install_update(self, update_info):
        """Lädt das Update herunter und installiert es"""
        try:
            # Download-Dialog
            progress = QProgressDialog(
                "Update wird heruntergeladen...",
                "Abbrechen",
                0, 0,
                self
            )
            progress.setWindowTitle("Update")
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.show()

            # Update herunterladen
            download_path = os.path.join(os.path.dirname(__file__), "update.zip")
            if self.update_manager.download_update(update_info['download_url'], download_path):
                progress.close()

                # Installation
                if self.update_manager.install_update(download_path):
                    QMessageBox.information(
                        self,
                        "Update erfolgreich",
                        "Das Update wurde erfolgreich installiert. "
                        "Bitte starten Sie die Anwendung neu."
                    )
                    QApplication.quit()
                else:
                    raise Exception("Installation fehlgeschlagen")
            else:
                raise Exception("Download fehlgeschlagen")

        except Exception as e:
            QMessageBox.critical(
                self,
                "Update fehlgeschlagen",
                f"Fehler beim Update: {str(e)}"
            )
            progress.close()

    def show_about(self):
        """Zeigt Informationen über die Anwendung"""
        QMessageBox.about(
            self,
            "Über Mail Analyzer",
            f"Mail Analyzer v{self.update_manager.current_version}\n\n"
            "Ein Werkzeug zur Erkennung verdächtiger E-Mails.\n\n"
            "© 2025 Ihr Unternehmen"
        )

    def create_pdf_report(self):
        """Erstellt einen PDF-Bericht der aktuellen Analyse"""
        try:
            emails = []
            for i in range(self.email_list.count()):
                item = self.email_list.item(i)
                email_data = item.email_data.copy()
                email_data.update(item.analysis_result)
                email_data['timestamp'] = datetime.now().isoformat()
                emails.append(email_data)

            filename = self.report_generator.create_pdf_report(emails)
            if filename:
                QMessageBox.information(
                    self,
                    "Bericht erstellt",
                    f"Der PDF-Bericht wurde erstellt unter:\n{filename}"
                )
                os.startfile(filename)  # Öffnet den Bericht
        except Exception as e:
            QMessageBox.critical(
                self,
                "Fehler",
                f"Fehler bei der PDF-Erstellung: {str(e)}"
            )

    def create_excel_report(self):
        """Erstellt einen Excel-Bericht der aktuellen Analyse"""
        try:
            emails = []
            for i in range(self.email_list.count()):
                item = self.email_list.item(i)
                email_data = item.email_data.copy()
                email_data.update(item.analysis_result)
                email_data['timestamp'] = datetime.now().isoformat()
                emails.append(email_data)

            filename = self.report_generator.create_excel_report(emails)
            if filename:
                QMessageBox.information(
                    self,
                    "Bericht erstellt",
                    f"Der Excel-Bericht wurde erstellt unter:\n{filename}"
                )
                os.startfile(filename)  # Öffnet den Bericht
        except Exception as e:
            QMessageBox.critical(
                self,
                "Fehler",
                f"Fehler bei der Excel-Erstellung: {str(e)}"
            )

    def show_statistics(self):
        """Zeigt ein Fenster mit statistischen Auswertungen"""
        try:
            emails = []
            for i in range(self.email_list.count()):
                item = self.email_list.item(i)
                email_data = item.email_data.copy()
                email_data.update(item.analysis_result)
                email_data['timestamp'] = datetime.now().isoformat()
                emails.append(email_data)

            stats = self.report_generator.create_statistical_analysis(emails)
            if stats:
                dialog = QDialog(self)
                dialog.setWindowTitle("Statistische Auswertung")
                dialog.setMinimumSize(600, 400)

                layout = QVBoxLayout()
                text = QTextEdit()
                text.setReadOnly(True)

                # Formatierte Statistiken
                stats_text = "Statistische Auswertung\n\n"
                stats_text += f"Gesamtzahl E-Mails: {stats['total_emails']}\n\n"

                stats_text += "Bedrohungslevel:\n"
                for level, count in stats['threat_levels'].items():
                    stats_text += f"- {level}: {count}\n"

                stats_text += "\nHäufigste Indikatoren:\n"
                sorted_indicators = sorted(
                    stats['common_indicators'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
                for indicator, count in sorted_indicators:
                    stats_text += f"- {indicator}: {count}\n"

                stats_text += "\nHäufigste Absender-Domains:\n"
                sorted_domains = sorted(
                    stats['sender_domains'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
                for domain, count in sorted_domains:
                    stats_text += f"- {domain}: {count}\n"

                text.setText(stats_text)
                layout.addWidget(text)

                close_button = QPushButton("Schließen")
                close_button.clicked.connect(dialog.close)
                layout.addWidget(close_button)

                dialog.setLayout(layout)
                dialog.exec()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Fehler",
                f"Fehler bei der statistischen Analyse: {str(e)}"
            )

    def toggle_auto_reports(self, period):
        """Aktiviert oder deaktiviert automatische Berichte"""
        try:
            # Konfiguration aktualisieren
            if not self.config.has_section('REPORTS'):
                self.config.add_section('REPORTS')

            current = self.config.getboolean('REPORTS', f'{period}_reports', fallback=False)
            self.config['REPORTS'][f'{period}_reports'] = str(not current)

            with open('configuration.ini', 'w') as configfile:
                self.config.write(configfile)

            status = "aktiviert" if not current else "deaktiviert"
            QMessageBox.information(
                self,
                "Automatische Berichte",
                f"{period.capitalize()}-Berichte wurden {status}."
            )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Fehler",
                f"Fehler beim Ändern der Berichtseinstellungen: {str(e)}"
            )

    def show_dashboard(self):
        """Zeigt das Threat Dashboard an"""
        dashboard = ThreatDashboard(self.analyzer)
        dialog = QDialog(self)
        dialog.setWindowTitle("Threat Dashboard")
        dialog.setModal(False)
        dialog.resize(1000, 600)

        layout = QVBoxLayout(dialog)
        layout.addWidget(dashboard)

        dialog.show()

    def show_context_rules(self):
        """Zeigt die Kontext-Regel-Konfiguration an"""
        config = ContextRuleConfig(self.analyzer.context_analyzer)
        dialog = QDialog(self)
        dialog.setWindowTitle("Kontext-Regeln konfigurieren")
        dialog.setModal(True)
        dialog.resize(800, 600)

        layout = QVBoxLayout(dialog)
        layout.addWidget(config)

        dialog.exec()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
