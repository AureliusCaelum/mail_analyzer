"""
Report Generator für Mail Analyzer
Generiert verschiedene Arten von Berichten und Statistiken
"""
import os
from datetime import datetime, timedelta
import json
import logging
from typing import Dict, List

import pandas as pd
from fpdf import FPDF

from ..utils import get_threat_level


class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def create_pdf_report(
        self, emails: List[Dict], period: str = "daily"
    ) -> str:
        """Erstellt einen PDF-Bericht über analysierte E-Mails."""
        try:
            pdf = FPDF()
            pdf.add_page()

            # Titel
            pdf.set_font("Arial", "B", 16)
            pdf.cell(
                0,
                10,
                f"Mail Analyzer - {period.capitalize()} Report",
                ln=True,
                align="C",
            )
            pdf.ln(10)

            # Datum
            pdf.set_font("Arial", "", 12)
            pdf.cell(
                0,
                10,
                f"Erstellt am: {datetime.now().strftime('%d.%m.%Y %H:%M')}",
                ln=True,
            )
            pdf.ln(10)

            # Zusammenfassung
            threat_levels = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for email in emails:
                level = get_threat_level(email["score"])
                threat_levels[level] += 1

            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Zusammenfassung", ln=True)
            pdf.set_font("Arial", "", 12)
            pdf.cell(0, 10, f"Analysierte E-Mails: {len(emails)}", ln=True)
            pdf.cell(
                0,
                10,
                f"Hohes Risiko: {threat_levels['HIGH']}",
                ln=True,
            )
            pdf.cell(
                0,
                10,
                f"Mittleres Risiko: {threat_levels['MEDIUM']}",
                ln=True,
            )
            pdf.cell(
                0,
                10,
                f"Niedriges Risiko: {threat_levels['LOW']}",
                ln=True,
            )
            pdf.ln(10)

            # Detaillierte Auflistung
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Detaillierte Auflistung', ln=True)
            pdf.set_font('Arial', '', 10)

            for email in emails:
                pdf.cell(
                    0,
                    10,
                    f"Betreff: {email['subject'][:50]}...",
                    ln=True,
                )
                pdf.cell(0, 10, f"Von: {email['sender']}", ln=True)
                pdf.cell(
                    0,
                    10,
                    f"Risiko: {get_threat_level(email['score'])}",
                    ln=True,
                )
                if email.get("indicators"):
                    pdf.multi_cell(
                        0,
                        10,
                        f"Indikatoren: {', '.join(email['indicators'])}",
                    )
                pdf.ln(5)

            # Speichern
            filename = os.path.join(
                self.output_dir,
                f"mail_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            )
            pdf.output(filename)
            return filename

        except Exception as e:
            logging.error(f"Fehler bei der PDF-Erstellung: {str(e)}")
            return None

    def create_excel_report(self, emails: List[Dict]) -> str:
        """Erstellt einen Excel-Bericht mit detaillierten Analysedaten."""
        try:
            df = pd.DataFrame(emails)

            # Zusätzliche Statistiken berechnen
            df["threat_level"] = df["score"].apply(get_threat_level)
            df['date'] = pd.to_datetime(df['timestamp'])

            # Excel erstellen
            filename = os.path.join(
                self.output_dir,
                f"mail_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
            )

            with pd.ExcelWriter(filename, engine='xlsxwriter') as writer:
                # Haupttabelle
                df.to_excel(
                    writer,
                    sheet_name="Detailed Analysis",
                    index=False,
                )

                # Zusammenfassung
                summary = pd.DataFrame({
                    'Metric': [
                        'Total Emails',
                        'High Risk',
                        'Medium Risk',
                        'Low Risk',
                    ],
                    'Count': [
                        len(df),
                        len(df[df['threat_level'] == 'HIGH']),
                        len(df[df['threat_level'] == 'MEDIUM']),
                        len(df[df['threat_level'] == 'LOW']),
                    ],
                })
                summary.to_excel(writer, sheet_name='Summary', index=False)

                # Grafiken erstellen
                workbook = writer.book
                worksheet = workbook.add_worksheet('Charts')

                # Bedrohungslevel-Verteilung
                chart = workbook.add_chart({'type': 'pie'})
                chart.add_series(
                    {
                        'name': 'Threat Levels',
                        'categories': ['Summary', 1, 0, 4, 0],
                        'values': ['Summary', 1, 1, 4, 1],
                    }
                )
                worksheet.insert_chart('B2', chart)

            return filename

        except Exception as e:
            logging.error(f"Fehler bei der Excel-Erstellung: {str(e)}")
            return None

    def create_statistical_analysis(self, emails: List[Dict]) -> Dict:
        """Erstellt eine statistische Analyse der E-Mail-Daten"""
        try:
            stats = {
                'total_emails': len(emails),
                'threat_levels': {
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                },
                'common_indicators': {},
                'sender_domains': {},
                'attachment_types': {},
                'hourly_distribution': {str(i): 0 for i in range(24)},
                'weekly_distribution': {str(i): 0 for i in range(7)}
            }

            for email in emails:
                # Bedrohungslevel
                level = get_threat_level(email["score"])
                stats["threat_levels"][level] += 1

                # Indikatoren
                for indicator in email.get('indicators', []):
                    stats['common_indicators'][indicator] = \
                        stats['common_indicators'].get(indicator, 0) + 1

                # Absender-Domains
                domain = email['sender'].split('@')[-1]
                stats['sender_domains'][domain] = \
                    stats['sender_domains'].get(domain, 0) + 1

                # Anhänge
                for attachment in email.get('attachments', []):
                    ext = os.path.splitext(attachment)[1]
                    stats['attachment_types'][ext] = \
                        stats['attachment_types'].get(ext, 0) + 1

                # Zeitliche Verteilung
                if 'timestamp' in email:
                    dt = datetime.fromisoformat(email['timestamp'])
                    stats['hourly_distribution'][str(dt.hour)] += 1
                    stats['weekly_distribution'][str(dt.weekday())] += 1

            return stats

        except Exception as e:
            logging.error(f"Fehler bei der statistischen Analyse: {str(e)}")
            return None

    def generate_periodic_report(self, period: str = 'daily') -> None:
        """Generiert periodische Berichte (täglich/wöchentlich)"""
        try:
            # Lade gespeicherte E-Mail-Daten
            data_file = os.path.join(self.output_dir, 'email_data.json')
            if os.path.exists(data_file):
                with open(data_file, 'r') as f:
                    all_emails = json.load(f)

                # Filtere nach Zeitraum
                now = datetime.now()
                if period == 'daily':
                    start_date = now - timedelta(days=1)
                else:  # weekly
                    start_date = now - timedelta(days=7)

                filtered_emails = [
                    email for email in all_emails
                    if datetime.fromisoformat(email['timestamp']) >= start_date
                ]

                # Generiere Berichte
                self.create_pdf_report(filtered_emails, period)
                self.create_excel_report(filtered_emails)

                # Erstelle statistische Analyse
                stats = self.create_statistical_analysis(filtered_emails)
                if stats:
                    date_str = datetime.now().strftime('%Y%m%d')
                    stats_file = os.path.join(
                        self.output_dir,
                        f"statistics_{period}_{date_str}.json",
                    )
                    with open(stats_file, 'w') as f:
                        json.dump(stats, f, indent=2)

        except Exception as e:
            logging.error(
                f"Fehler bei der Erstellung des {period} Berichts: {str(e)}"
            )
