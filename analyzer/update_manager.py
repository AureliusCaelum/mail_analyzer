"""
Update-Manager für automatische Software-Updates
"""
import os
import json
import logging
import requests
from datetime import datetime
from packaging import version

class UpdateManager:
    def __init__(self):
        self.current_version = "0.1.0"  # Aktuelle Softwareversion
        self.github_api_url = "https://api.github.com/repos/your-repo/mail-analyzer/releases/latest"
        self.update_info_file = "update_info.json"
        self.last_check = None

    def check_for_updates(self) -> dict:
        """
        Prüft, ob Updates verfügbar sind
        Returns:
            dict: Update-Informationen oder None wenn kein Update verfügbar
        """
        try:
            # Prüfe nicht öfter als einmal täglich
            if self._should_check():
                response = requests.get(self.github_api_url)
                response.raise_for_status()
                latest_release = response.json()
                
                latest_version = latest_release["tag_name"].lstrip("v")
                
                if version.parse(latest_version) > version.parse(self.current_version):
                    update_info = {
                        "version": latest_version,
                        "description": latest_release["body"],
                        "download_url": latest_release["assets"][0]["browser_download_url"],
                        "last_checked": datetime.now().isoformat()
                    }
                    self._save_update_info(update_info)
                    return update_info
                
                self._save_last_check()
            
            return None

        except Exception as e:
            logging.error(f"Fehler bei der Update-Prüfung: {str(e)}")
            return None

    def download_update(self, download_url: str, target_path: str) -> bool:
        """
        Lädt das Update herunter
        """
        try:
            response = requests.get(download_url, stream=True)
            response.raise_for_status()
            
            with open(target_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return True

        except Exception as e:
            logging.error(f"Fehler beim Download des Updates: {str(e)}")
            return False

    def _should_check(self) -> bool:
        """Prüft, ob eine neue Update-Prüfung durchgeführt werden soll"""
        if not os.path.exists(self.update_info_file):
            return True

        try:
            with open(self.update_info_file, 'r') as f:
                data = json.load(f)
                last_checked = datetime.fromisoformat(data.get('last_checked', '2000-01-01'))
                return (datetime.now() - last_checked).days >= 1
        except:
            return True

    def _save_update_info(self, info: dict):
        """Speichert Update-Informationen"""
        try:
            with open(self.update_info_file, 'w') as f:
                json.dump(info, f, indent=2)
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Update-Informationen: {str(e)}")

    def _save_last_check(self):
        """Speichert den Zeitpunkt der letzten Prüfung"""
        try:
            with open(self.update_info_file, 'w') as f:
                json.dump({"last_checked": datetime.now().isoformat()}, f, indent=2)
        except Exception as e:
            logging.error(f"Fehler beim Speichern des Prüfzeitpunkts: {str(e)}")

    def install_update(self, update_file: str) -> bool:
        """
        Installiert das heruntergeladene Update
        """
        try:
            # Hier würde die Update-Installation implementiert werden
            # z.B. Extraktion eines ZIP-Archives, Ausführen von Skripten etc.
            return True
        except Exception as e:
            logging.error(f"Fehler bei der Update-Installation: {str(e)}")
            return False
