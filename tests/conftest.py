"""Test configuration and environment stubs."""

import sys
import types

def _ensure_module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules.setdefault(name, module)
    return sys.modules[name]

# Stub win32com so that Outlook-related modules can be imported on any system.
win32com = _ensure_module("win32com")
win32com.client = _ensure_module("win32com.client")

# Stub a minimal subset of the Google modules used by gmail.py and OAuth flows.
google = _ensure_module("google")
google.oauth2 = _ensure_module("google.oauth2")
google.oauth2.credentials = _ensure_module("google.oauth2.credentials")
google.oauth2.credentials.Credentials = object

google_auth = _ensure_module("google.auth")
google_auth.transport = _ensure_module("google.auth.transport")
google_auth.transport.requests = _ensure_module("google.auth.transport.requests")
google_auth.transport.requests.Request = object

# Stub google_auth_oauthlib for local server flows.
google_auth_oauthlib = _ensure_module("google_auth_oauthlib")
google_auth_oauthlib.flow = _ensure_module("google_auth_oauthlib.flow")
class _DummyInstalledAppFlow:
    @classmethod
    def from_client_secrets_file(cls, *args, **kwargs):
        return cls()
    def run_local_server(self, *args, **kwargs):
        return google.oauth2.credentials.Credentials()
google_auth_oauthlib.flow.InstalledAppFlow = _DummyInstalledAppFlow

# Stub msal for Exchange client imports.
_ensure_module("msal")

# Stub requests since it's imported by some clients.
requests = _ensure_module("requests")
requests.get = lambda *args, **kwargs: types.SimpleNamespace(status_code=200, json=lambda: {})
requests.post = lambda *args, **kwargs: types.SimpleNamespace(status_code=200, json=lambda: {})

# Stub colorama used by various CLI utilities.
colorama = _ensure_module("colorama")
colorama.Fore = types.SimpleNamespace(RED="", YELLOW="", GREEN="", WHITE="")
colorama.Style = types.SimpleNamespace(RESET_ALL="")
colorama.init = lambda *args, **kwargs: None

# Stub httpx for HTTP client usages.
httpx = _ensure_module("httpx")
class _DummyHttpxClient:
    def __init__(self, *args, **kwargs): pass
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def get(self, *args, **kwargs): return types.SimpleNamespace(status_code=200, json=lambda: {})
    def post(self, *args, **kwargs): return types.SimpleNamespace(status_code=200, json=lambda: {}, raise_for_status=lambda: None)
httpx.Client = _DummyHttpxClient

# Stub transformers pipeline for ML inference.
transformers = _ensure_module("transformers")
transformers.pipeline = lambda *args, **kwargs: (lambda x: [])

# Stub sentence_transformers for embedding generation.
sentence_transformers = _ensure_module("sentence_transformers")
class _DummySentenceTransformer:
    def __init__(self, *args, **kwargs): pass
    def encode(self, *args, **kwargs): return [0.0]
sentence_transformers.SentenceTransformer = _DummySentenceTransformer

# Stub torch for tensor operations in tests.
torch = _ensure_module("torch")
torch.tensor = lambda x: x
torch.nn = types.SimpleNamespace(
    functional=types.SimpleNamespace(
        cosine_similarity=lambda a, b, dim: [0.0]
    )
)
