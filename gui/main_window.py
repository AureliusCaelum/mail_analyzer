"""
Hauptfenster der Mail Analyzer GUI
"""
import sys
import os
import configparser
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QMessageBox,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QAction, QDesktopServices, QUrl

from analyzer.email_scanner import get_scanner
from analyzer.threat_analyzer import ThreatAnalyzer
from analyzer.traffic_light import TrafficLight
from analyzer.update_manager import UpdateManager
from analyzer.report_generator import ReportGenerator
from analyzer.email_controller import EmailController
from analyzer.report_controller import ReportController
from config.settings import MAX_EMAILS_TO_SCAN
from .threat_dashboard import ThreatDashboard
from .context_config import ContextRuleConfig
from .client_settings_dialog import ClientSettingsDialog
from .email_list_item import EmailListItem

class MainWindow(QMainWindow):
    """Main application window for the Mail Analyzer."""

    def __init__(self) -> None:
        super().__init__()
        self.analyzer = ThreatAnalyzer()
        self.traffic_light = TrafficLight()
        self.config = configparser.ConfigParser()
        self.config.read("configuration.ini")
        self.scanner = get_scanner()
        self.update_manager = UpdateManager()
        self.report_generator = ReportGenerator()
        self.email_controller = EmailController(self.scanner, self.analyzer)
        self.report_controller = ReportController(self.report_generator)

        # Timer für automatische Updates
        self.update_check_timer = QTimer()
        self.update_check_timer.timeout.connect(self.check_for_updates)
        self.update_check_timer.start(86400000)  # Einmal täglich prüfen

        self._setup_ui()

        # Sofortige Update-Prüfung beim Start
        QTimer.singleShot(1000, self.check_for_updates)

    def _setup_ui(self) -> None:
        """Initialise widgets, layouts and menus."""
        self.setWindowTitle("Mail Analyzer")
        self.setGeometry(100, 100, 1200, 800)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        splitter.addWidget(self._setup_left_panel())
        splitter.addWidget(self._setup_tabs())
        splitter.setSizes([400, 800])

        self._load_initial_emails()
        self._setup_menu()

    def _setup_left_panel(self) -> QWidget:
        """Create the left panel containing the email list."""
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        client_layout = QHBoxLayout()
        self.client_label = QLabel(
            f"Aktiver Client: {self.scanner._client.name if self.scanner._client else 'Nicht verbunden'}"
        )
        self.settings_button = QPushButton("Client Einstellungen")
        self.settings_button.clicked.connect(self.show_client_settings)
        client_layout.addWidget(self.client_label)
        client_layout.addWidget(self.settings_button)
        left_layout.addLayout(client_layout)

        refresh_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Aktualisieren")
        self.refresh_button.clicked.connect(self.refresh_emails)
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        refresh_layout.addWidget(self.refresh_button)
        refresh_layout.addWidget(self.progress_bar)
        left_layout.addLayout(refresh_layout)

        self.email_list = QListWidget()
        self.email_list.itemClicked.connect(self.show_email_details)
        left_layout.addWidget(self.email_list)

        return left_widget

    def _setup_tabs(self) -> QWidget:
        """Create the right panel with tabbed email details."""
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        self.tab_widget = QTabWidget()

        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        self.threat_level_label = QLabel()
        self.threat_level_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        overview_layout.addWidget(self.threat_level_label)

        self.email_details = QTextEdit()
        self.email_details.setReadOnly(True)
        overview_layout.addWidget(self.email_details)

        analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(analysis_tab)
        self.analysis_details = QTextEdit()
        self.analysis_details.setReadOnly(True)
        analysis_layout.addWidget(self.analysis_details)

        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        self.raw_email = QTextEdit()
        self.raw_email.setReadOnly(True)
        raw_layout.addWidget(self.raw_email)

        self.tab_widget.addTab(overview_tab, "Übersicht")
        self.tab_widget.addTab(analysis_tab, "Analyse")
        self.tab_widget.addTab(raw_tab, "Rohdaten")

        right_layout.addWidget(self.tab_widget)
        return right_widget

    def _setup_menu(self) -> None:
        """Configure the application menu bar."""
        menubar = self.menuBar()

        help_menu = menubar.addMenu("&Hilfe")
        check_update_action = QAction("Nach Updates suchen", self)
        check_update_action.triggered.connect(self.check_for_updates)
        help_menu.addAction(check_update_action)

        about_action = QAction("Über Mail Analyzer", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        reports_menu = menubar.addMenu("&Berichte")
        pdf_report_action = QAction("PDF-Bericht erstellen", self)
        pdf_report_action.triggered.connect(self.create_pdf_report)
        reports_menu.addAction(pdf_report_action)

        excel_report_action = QAction("Excel-Bericht erstellen", self)
        excel_report_action.triggered.connect(self.create_excel_report)
        reports_menu.addAction(excel_report_action)

        stats_action = QAction("Statistiken anzeigen", self)
        stats_action.triggered.connect(self.show_statistics)
        reports_menu.addAction(stats_action)

        reports_menu.addSeparator()
        auto_reports_menu = reports_menu.addMenu("Automatische Berichte")

        daily_report_action = QAction("Täglicher Bericht aktivieren", self)
        daily_report_action.setCheckable(True)
        daily_report_action.triggered.connect(lambda: self.toggle_auto_reports("daily"))
        auto_reports_menu.addAction(daily_report_action)

        weekly_report_action = QAction("Wöchentlicher Bericht aktivieren", self)
        weekly_report_action.setCheckable(True)
        weekly_report_action.triggered.connect(lambda: self.toggle_auto_reports("weekly"))
        auto_reports_menu.addAction(weekly_report_action)

        view_menu = menubar.addMenu("&Ansicht")
        show_dashboard_action = QAction("Dashboard", self)
        show_dashboard_action.triggered.connect(self.show_dashboard)
        view_menu.addAction(show_dashboard_action)

        settings_menu = menubar.addMenu("&Einstellungen")
        context_rules_action = QAction("Kontext-Regeln", self)
        context_rules_action.triggered.connect(self.show_context_rules)
        settings_menu.addAction(context_rules_action)

    def _load_initial_emails(self) -> None:
        """Populate the email list on startup."""
        self.refresh_emails()

    def show_client_settings(self) -> None:
        """Open the settings dialog for selecting the mail client."""
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
            self.email_controller = EmailController(self.scanner, self.analyzer)
            self.refresh_emails()

            self.client_label.setText(
                f"Aktiver Client: {self.scanner._client.name if self.scanner._client else 'Nicht verbunden'}"
            )

    def refresh_emails(self) -> None:
        """Refresh the email list by fetching and analysing messages."""
        self.progress_bar.show()
        self.progress_bar.setRange(0, 0)
        self.refresh_button.setEnabled(False)

        try:
            self.email_list.clear()
            for email, analysis in self.email_controller.fetch_emails(MAX_EMAILS_TO_SCAN):
                item = EmailListItem(email, analysis)
                self.email_list.addItem(item)
        except Exception as exc:  # pragma: no cover - GUI message box
            QMessageBox.critical(self, "Fehler", f"Fehler beim Laden der E-Mails: {exc}")
        finally:
            self.progress_bar.hide()
            self.refresh_button.setEnabled(True)

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

    def create_pdf_report(self) -> None:
        """Generate a PDF report for the current email list."""
        try:
            filename = self.report_controller.create_pdf_report(self.email_list)
            if filename:
                QMessageBox.information(
                    self,
                    "Bericht erstellt",
                    f"Der PDF-Bericht wurde erstellt unter:\n{filename}"
                )
                QDesktopServices.openUrl(QUrl.fromLocalFile(filename))
        except Exception as exc:  # pragma: no cover - GUI message box
            QMessageBox.critical(self, "Fehler", f"Fehler bei der PDF-Erstellung: {exc}")

    def create_excel_report(self) -> None:
        """Generate an Excel report for the current email list."""
        try:
            filename = self.report_controller.create_excel_report(self.email_list)
            if filename:
                QMessageBox.information(
                    self,
                    "Bericht erstellt",
                    f"Der Excel-Bericht wurde erstellt unter:\n{filename}"
                )
                QDesktopServices.openUrl(QUrl.fromLocalFile(filename))
        except Exception as exc:  # pragma: no cover
            QMessageBox.critical(self, "Fehler", f"Fehler bei der Excel-Erstellung: {exc}")

    def show_statistics(self) -> None:
        """Display statistical summaries in a dialog."""
        try:
            stats = self.report_controller.create_statistical_analysis(self.email_list)
            if stats:
                dialog = QDialog(self)
                dialog.setWindowTitle("Statistische Auswertung")
                dialog.setMinimumSize(600, 400)

                layout = QVBoxLayout()
                text = QTextEdit()
                text.setReadOnly(True)

                stats_text = "Statistische Auswertung\n\n"
                stats_text += f"Gesamtzahl E-Mails: {stats['total_emails']}\n\n"
                stats_text += "Bedrohungslevel:\n"
                for level, count in stats['threat_levels'].items():
                    stats_text += f"- {level}: {count}\n"

                stats_text += "\nHäufigste Indikatoren:\n"
                sorted_indicators = sorted(
                    stats['common_indicators'].items(), key=lambda x: x[1], reverse=True
                )[:10]
                for indicator, count in sorted_indicators:
                    stats_text += f"- {indicator}: {count}\n"

                stats_text += "\nHäufigste Absender-Domains:\n"
                sorted_domains = sorted(
                    stats['sender_domains'].items(), key=lambda x: x[1], reverse=True
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
        except Exception as exc:  # pragma: no cover
            QMessageBox.critical(self, "Fehler", f"Fehler bei der statistischen Analyse: {exc}")

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
