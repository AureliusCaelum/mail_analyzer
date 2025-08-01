"""Test configuration and environment stubs."""

import sys
import types


def _ensure_module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules.setdefault(name, module)
    return sys.modules[name]


# Stub ``win32com`` so that Outlook-related modules can be imported on systems
# without the actual dependency.
win32com = _ensure_module("win32com")
win32com.client = _ensure_module("win32com.client")


# Stub a minimal subset of the Google modules used by ``gmail.py``. Only the
# attributes accessed during import are provided.
google = _ensure_module("google")
google.oauth2 = _ensure_module("google.oauth2")
google.oauth2.credentials = _ensure_module("google.oauth2.credentials")
google.oauth2.credentials.Credentials = object

google_auth_oauthlib = _ensure_module("google_auth_oauthlib")
google_auth_oauthlib.flow = _ensure_module("google_auth_oauthlib.flow")
google_auth_oauthlib.flow.InstalledAppFlow = object

google.auth = _ensure_module("google.auth")
google.auth.transport = _ensure_module("google.auth.transport")
google.auth.transport.requests = _ensure_module("google.auth.transport.requests")
google.auth.transport.requests.Request = object

# Stub "msal" for Exchange client imports.
_ensure_module("msal")

# ``requests`` is imported by the Exchange client but not used in tests.
_ensure_module("requests")

# Minimal stub for ``colorama`` used by the traffic light module.
colorama = _ensure_module("colorama")
colorama.Fore = types.SimpleNamespace(RED="", YELLOW="", GREEN="", WHITE="")
colorama.Style = types.SimpleNamespace(RESET_ALL="")
colorama.init = lambda *args, **kwargs: None

