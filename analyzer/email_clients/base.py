"""
Basis-Interface für E-Mail-Client-Integrationen
"""
from abc import ABC, abstractmethod
from typing import List, Dict

class EmailClientBase(ABC):
    """Basis-Klasse für E-Mail-Client-Integrationen"""

    @abstractmethod
    def connect(self) -> bool:
        """Verbindung zum E-Mail-Client herstellen"""
        pass

    @abstractmethod
    def get_emails(self, max_count: int = 20) -> List[Dict]:
        """E-Mails vom Client abrufen"""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Verbindung trennen"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name des E-Mail-Clients"""
        pass
