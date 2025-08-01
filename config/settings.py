"""
Globale Konfigurationseinstellungen für den E-Mail-Analyzer
"""

# E-Mail-Einstellungen
MAX_EMAILS_TO_SCAN = 50
DEFAULT_FOLDER = "Posteingang"

# Bedrohungsstufen
THREAT_LEVELS = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🔴"
}

# Logging-Einstellungen
LOG_FILE = "logs/email_analysis.log"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Analyse-Einstellungen
SCAN_ATTACHMENTS = True
SCAN_LINKS = True
SCAN_SENDER = True
SCAN_CONTENT = True

# Zeitliche Einstellungen
SCAN_INTERVAL = 300  # 5 Minuten
MAX_AGE_DAYS = 30  # Maximales Alter der zu scannenden E-Mails

# Bedrohungserkennungsregeln
SUSPICIOUS_EXTENSIONS = {
    'high_risk': ['.exe', '.bat', '.cmd', '.scr', '.js', '.vbs', '.ps1', '.msi', '.reg'],
    'medium_risk': ['.zip', '.rar', '.7z', '.iso', '.jar', '.msc'],
    'low_risk': ['.pdf', '.doc', '.docx', '.xls', '.xlsx']
}

SUSPICIOUS_KEYWORDS = {
    'high_risk': [
        'password', 'passwort', 'konto', 'account', 'bank', 'verify', 'verifizieren',
        'urgent', 'dringend', 'immediate', 'sofort', 'lawsuit', 'klage',
        'inheritance', 'erbe', 'winner', 'gewinner', 'bitcoin', 'wallet'
    ],
    'medium_risk': [
        'update', 'aktualisierung', 'security', 'sicherheit', 'support',
        'invoice', 'rechnung', 'payment', 'zahlung', 'überweisen',
        'subscription', 'abonnement', 'trial', 'testversion'
    ],
    'low_risk': [
        'newsletter', 'angebot', 'offer', 'sale', 'rabatt',
        'confirmation', 'bestätigung', 'reminder', 'erinnerung'
    ]
}

SUSPICIOUS_URL_PATTERNS = [
    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
    r'(?:https?://)?(?:[\w-]+\.)+[\w-]+(?:/[\w-./?%&=]*)?'
]

SUSPICIOUS_TLD = [
    '.xyz', '.top', '.work', '.date', '.loan', '.agency', '.guru',
    '.win', '.pro', '.stream', '.gdn', '.bid', '.click'
]

SCORING_WEIGHTS = {
    'sender': {
        'suspicious_domain': 2.0,
        'spoofed_display_name': 2.5,
        'public_provider': 1.0
    },
    'subject': {
        'high_risk_keyword': 2.0,
        'medium_risk_keyword': 1.5,
        'low_risk_keyword': 0.5
    },
    'body': {
        'high_risk_keyword': 1.5,
        'medium_risk_keyword': 1.0,
        'low_risk_keyword': 0.3,
        'suspicious_url': 2.0,
        'multiple_urls': 1.0,
        'urgent_language': 1.5
    },
    'attachments': {
        'high_risk_extension': 3.0,
        'medium_risk_extension': 2.0,
        'low_risk_extension': 0.5,
        'multiple_attachments': 1.0
    }
}
