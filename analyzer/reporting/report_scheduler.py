"""Automatischer Report-Scheduler für periodische Berichtserstellung."""
import time
import schedule
import threading
import logging
from datetime import datetime
import configparser

from .report_generator import ReportGenerator

class ReportScheduler:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('configuration.ini')
        self.report_generator = ReportGenerator()
        self.running = False
        self.thread = None

    def start(self):
        """Startet den Scheduler in einem separaten Thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._run_scheduler)
            self.thread.daemon = True
            self.thread.start()
            logging.info("Report-Scheduler gestartet")

    def stop(self):
        """Stoppt den Scheduler"""
        self.running = False
        if self.thread:
            self.thread.join()
            logging.info("Report-Scheduler gestoppt")

    def _run_scheduler(self):
        """Hauptschleife des Schedulers"""
        # Tägliche Berichte um 23:00 Uhr
        if self.config.getboolean('REPORTS', 'daily_reports', fallback=False):
            schedule.every().day.at("23:00").do(
                self.report_generator.generate_periodic_report,
                period='daily'
            )

        # Wöchentliche Berichte jeden Sonntag um 23:30 Uhr
        if self.config.getboolean('REPORTS', 'weekly_reports', fallback=False):
            schedule.every().sunday.at("23:30").do(
                self.report_generator.generate_periodic_report,
                period='weekly'
            )

        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Prüfe jede Minute

    def reload_config(self):
        """Lädt die Konfiguration neu und aktualisiert den Zeitplan"""
        self.config.read('configuration.ini')
        schedule.clear()
        if self.running:
            self._run_scheduler()
