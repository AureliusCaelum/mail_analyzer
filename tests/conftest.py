"""Testkonfigurationen und Fixtures."""

import sys
import types

# Stub-Modul für win32com, um Tests ohne Windows-Abhängigkeiten zu ermöglichen.
win32com = types.ModuleType("win32com")
win32com.client = types.ModuleType("win32com.client")
sys.modules.setdefault("win32com", win32com)
sys.modules.setdefault("win32com.client", win32com.client)

# Stub-Module für Google-APIs, um externe Abhängigkeiten zu vermeiden.
google = types.ModuleType("google")
oauth2 = types.ModuleType("google.oauth2")
credentials = types.ModuleType("credentials")
class _DummyCredentials:
    pass
credentials.Credentials = _DummyCredentials
oauth2.credentials = credentials
google.oauth2 = oauth2
sys.modules.setdefault("google", google)
sys.modules.setdefault("google.oauth2", oauth2)
sys.modules.setdefault("google.oauth2.credentials", credentials)

google_auth_oauthlib = types.ModuleType("google_auth_oauthlib")
flow = types.ModuleType("google_auth_oauthlib.flow")

class _DummyInstalledAppFlow:
    @classmethod
    def from_client_secrets_file(cls, *args, **kwargs):  # pragma: no cover - stub
        return cls()

    def run_local_server(self, *args, **kwargs):  # pragma: no cover - stub
        return _DummyCredentials()

flow.InstalledAppFlow = _DummyInstalledAppFlow
google_auth_oauthlib.flow = flow
sys.modules.setdefault("google_auth_oauthlib", google_auth_oauthlib)
sys.modules.setdefault("google_auth_oauthlib.flow", flow)

colorama = types.ModuleType("colorama")
class _DummyFore:
    RED = GREEN = YELLOW = RESET = ""

class _DummyStyle:
    RESET_ALL = ""

def _dummy_init(*args, **kwargs):  # pragma: no cover - stub
    return None

colorama.Fore = _DummyFore()
colorama.Style = _DummyStyle()
colorama.init = _dummy_init
sys.modules.setdefault("colorama", colorama)

httpx = types.ModuleType("httpx")

class _DummyHttpxClient:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):  # pragma: no cover - stub
        return self

    def __exit__(self, *args):  # pragma: no cover - stub
        return False

    def get(self, *args, **kwargs):  # pragma: no cover - stub
        return types.SimpleNamespace(status_code=200, json=lambda: {})

    def post(self, *args, **kwargs):  # pragma: no cover - stub
        return types.SimpleNamespace(status_code=200, json=lambda: {}, raise_for_status=lambda: None)

httpx.Client = _DummyHttpxClient
sys.modules.setdefault("httpx", httpx)

requests = types.ModuleType("requests")
requests.get = lambda *args, **kwargs: types.SimpleNamespace(status_code=200, json=lambda: {})  # pragma: no cover - stub
requests.post = lambda *args, **kwargs: types.SimpleNamespace(status_code=200, json=lambda: {})  # pragma: no cover - stub
sys.modules.setdefault("requests", requests)

transformers = types.ModuleType("transformers")
transformers.pipeline = lambda *args, **kwargs: lambda x: []  # pragma: no cover - stub
sys.modules.setdefault("transformers", transformers)

sentence_transformers = types.ModuleType("sentence_transformers")

class _DummySentenceTransformer:
    def __init__(self, *args, **kwargs):
        pass

    def encode(self, *args, **kwargs):  # pragma: no cover - stub
        return [0.0]

sentence_transformers.SentenceTransformer = _DummySentenceTransformer
sys.modules.setdefault("sentence_transformers", sentence_transformers)

torch = types.ModuleType("torch")
torch.tensor = lambda x: x  # pragma: no cover - stub
torch.nn = types.SimpleNamespace(functional=types.SimpleNamespace(cosine_similarity=lambda a, b, dim: [0.0]))
sys.modules.setdefault("torch", torch)
