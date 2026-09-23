"""Shared Keycloak settings. Values are read from the .env file (never hard-code the secret)."""
import os
from dotenv import load_dotenv

load_dotenv()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8081")
REALM = os.getenv("KEYCLOAK_REALM", "MyTesting")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "mac-2-mac")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
RESOURCE_SERVER_CLIENT_ID = os.getenv("RESOURCE_SERVER_CLIENT_ID", CLIENT_ID)
PERMISSION = os.getenv("KEYCLOAK_PERMISSION", "Read Resource#read")  # "<resource>#<scope>"

BASE = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect"
TOKEN_URL = f"{BASE}/token"
CERTS_URL = f"{BASE}/certs"
INTROSPECT_URL = f"{BASE}/token/introspect"
