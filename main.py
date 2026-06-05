"""
CyberArk PVWA MCP Server

Manages privileged accounts via CyberArk Self-Hosted PAM REST API.

Required:
  CYBERARK_PVWA_URL       - Base URL, e.g. https://my.pvwa.com

PVWA authentication (applied in priority order):
  PVWA_SAML_ENABLED       - true | false (default false) — SAML-first via IdP token exchange
  PVWA_SAML_APP_KEY        - PVWA entity/app ID at the IdP (required when SAML enabled)
  CYBERARK_AUTH_TYPE      - CyberArk (default) | LDAP | Windows | RADIUS
  CYBERARK_USERNAME       - Optional pre-configured username; prompted at runtime if absent
  CYBERARK_PASSWORD       - Optional pre-configured password; prompted at runtime if absent
  CYBERARK_VERIFY_SSL     - true (default) | false (lab only)

MCP endpoint authentication:
  OAUTH_ENABLED           - true | false (default false)
  OAUTH_ISSUER            - Public URL of this server
  OAUTH_CLIENT_ID         - Static client ID (internal OAuth only)
  OAUTH_CLIENT_SECRET     - Static client secret (internal OAuth only)
  OAUTH_TOKEN_EXPIRY      - Token TTL in seconds (default 3600)
  OAUTH_PRIVATE_KEY_PEM   - RSA private key PEM (auto-generated if absent)

External IdP (overrides internal OAuth when set):
  IDP_ISSUER              - Issuer URL of the external IdP
  IDP_CLIENT_ID / IDP_CLIENT_SECRET / IDP_SCOPE / IDP_AUDIENCE
"""

import os
import re
import json
import xml.etree.ElementTree as ET
import base64
import hashlib
import secrets
import uuid
import time
import logging
import urllib.parse
from contextvars import ContextVar
from typing import Any, Optional

import httpx
import asyncio
import uvicorn
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PVWA_URL = os.environ.get("CYBERARK_PVWA_URL", "").rstrip("/")
AUTH_TYPE = os.environ.get("CYBERARK_AUTH_TYPE", "CyberArk")
USERNAME = os.environ.get("CYBERARK_USERNAME", "")
PASSWORD = os.environ.get("CYBERARK_PASSWORD", "")
VERIFY_SSL = os.environ.get("CYBERARK_VERIFY_SSL", "true").lower() != "false"
PVWA_SAML_ENABLED = os.environ.get("PVWA_SAML_ENABLED", "false").lower() == "true"
PVWA_SAML_APP_KEY = os.environ.get("PVWA_SAML_APP_KEY", "")   # SAML app key/UUID at the IdP
PVWA_SAML_SSO_URL = os.environ.get("PVWA_SAML_SSO_URL", "")  # Direct IdP SSO URL (skips discovery)

BASE_API = f"{PVWA_URL}/PasswordVault/API"

# ---------------------------------------------------------------------------
# OAuth 2.1 Configuration
# ---------------------------------------------------------------------------

OAUTH_ENABLED = os.environ.get("OAUTH_ENABLED", "false").lower() == "true"
OAUTH_ISSUER = os.environ.get("OAUTH_ISSUER", "http://localhost:8000").rstrip("/")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "mcp-client")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
OAUTH_TOKEN_EXPIRY = int(os.environ.get("OAUTH_TOKEN_EXPIRY", "3600"))

# External IdP (Okta / CyberArk Identity)
IDP_ISSUER = os.environ.get("IDP_ISSUER", "").rstrip("/")
IDP_DISCOVERY_URL = os.environ.get("IDP_DISCOVERY_URL", "")
IDP_CLIENT_ID = os.environ.get("IDP_CLIENT_ID", "")
IDP_CLIENT_SECRET = os.environ.get("IDP_CLIENT_SECRET", "")
IDP_AUDIENCE = os.environ.get("IDP_AUDIENCE", "")
IDP_SCOPE = os.environ.get("IDP_SCOPE", "openid profile")
USE_EXTERNAL_IDP = bool(IDP_ISSUER or IDP_DISCOVERY_URL)

# IdP metadata + JWKS cache
_idp_meta: dict = {}
_idp_jwks_cache: dict = {"keys": [], "at": 0}
_JWKS_TTL = 3600

# Per-request bearer token (set in MCP endpoint, read in PVWAClient for SAML)
_bearer_ctx: ContextVar[str] = ContextVar("bearer", default="")

_KID = str(uuid.uuid4())[:8]

_pem_env = os.environ.get("OAUTH_PRIVATE_KEY_PEM", "")
if _pem_env:
    _private_key = load_pem_private_key(_pem_env.encode(), password=None, backend=default_backend())
else:
    _private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

_public_key = _private_key.public_key()
_private_pem = _private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
_public_pem = _public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _b64url(n: int) -> str:
    blen = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(blen, "big")).rstrip(b"=").decode()


def _jwks() -> dict:
    nums = _public_key.public_numbers()
    return {"keys": [{"kty": "RSA", "use": "sig", "kid": _KID, "alg": "RS256", "n": _b64url(nums.n), "e": _b64url(nums.e)}]}


def _issue_token(client_id: str, scope: str = "mcp:read mcp:write") -> str:
    now = int(time.time())
    payload = {"iss": OAUTH_ISSUER, "sub": client_id, "aud": OAUTH_ISSUER,
               "iat": now, "exp": now + OAUTH_TOKEN_EXPIRY, "jti": str(uuid.uuid4()), "scope": scope}
    return pyjwt.encode(payload, _private_pem, algorithm="RS256", headers={"kid": _KID})


async def _get_idp_meta() -> dict:
    global _idp_meta
    if _idp_meta:
        return _idp_meta
    discovery = IDP_DISCOVERY_URL or f"{IDP_ISSUER}/.well-known/openid-configuration"
    async with httpx.AsyncClient() as c:
        r = await c.get(discovery, follow_redirects=True)
        r.raise_for_status()
        _idp_meta = r.json()
    logger.info("IdP metadata loaded from %s", discovery)
    return _idp_meta


async def _get_idp_jwks() -> list:
    global _idp_jwks_cache
    now = time.time()
    if _idp_jwks_cache["keys"] and now - _idp_jwks_cache["at"] < _JWKS_TTL:
        return _idp_jwks_cache["keys"]
    meta = await _get_idp_meta()
    jwks_uri = meta.get("jwks_uri", "")
    async with httpx.AsyncClient() as c:
        r = await c.get(jwks_uri)
        r.raise_for_status()
        data = r.json()
    _idp_jwks_cache = {"keys": data.get("keys", []), "at": now}
    logger.info("IdP JWKS refreshed (%d keys)", len(_idp_jwks_cache["keys"]))
    return _idp_jwks_cache["keys"]


async def _validate_idp_token(token: str) -> bool:
    try:
        from jwt.algorithms import RSAAlgorithm

        # Log unverified claims for debugging
        try:
            unverified = pyjwt.decode(token, options={"verify_signature": False})
            logger.info("Token claims — iss: %s | aud: %s | exp: %s",
                        unverified.get("iss"), unverified.get("aud"), unverified.get("exp"))
        except Exception:
            pass

        keys = await _get_idp_jwks()
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg", "RS256")
        matched = [k for k in keys if k.get("kid") == kid] if kid else keys

        if not matched:
            logger.warning("No JWKS key matched kid=%s", kid)
            return False

        for key_data in matched:
            try:
                public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
                # Verify signature + expiry only; skip iss/aud (managed by IdP)
                options = {"verify_aud": False, "verify_iss": False}
                pyjwt.decode(token, public_key, algorithms=[alg], options=options)
                logger.info("IdP token validated OK (kid=%s)", kid)
                return True
            except pyjwt.ExpiredSignatureError:
                logger.warning("IdP token expired")
                return False
            except Exception as e:
                logger.warning("Key %s validation failed: %s", key_data.get("kid"), e)
                continue

        logger.warning("IdP token: all keys failed validation")
        return False
    except Exception as e:
        logger.warning("IdP token validation error: %s", e)
        return False


async def _auth_ok(authorization: str) -> bool:
    """Unified auth check — internal or external IdP."""
    if not OAUTH_ENABLED:
        return True
    if not authorization or not authorization.startswith("Bearer "):
        return False
    token = authorization[7:]
    if USE_EXTERNAL_IDP:
        return await _validate_idp_token(token)
    return _validate_token(authorization)


# In-memory stores (reset on restart)
_registered_clients: dict = {}  # client_id → {client_secret, redirect_uris, ...}
_auth_codes: dict = {}           # code → {client_id, redirect_uri, code_challenge, scope, exp}
_idp_sessions: dict = {}         # opaque_refresh_token → {idp_refresh_token, client_id, scope, exp}
_mcp_sessions: dict = {}         # Mcp-Session-Id → {created, bearer}


def _validate_token(authorization: str) -> bool:
    if not OAUTH_ENABLED:
        return True
    if not authorization or not authorization.startswith("Bearer "):
        return False
    try:
        pyjwt.decode(authorization[7:], _public_pem, algorithms=["RS256"], audience=OAUTH_ISSUER)
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# PVWA HTTP client with automatic session management
# ---------------------------------------------------------------------------

def _parse_saml_response_from_html(html: str) -> Optional[str]:
    """Extract the SAMLResponse value from an IdP HTML auto-submit form.

    IdPs typically return a page like:
      <form ...><input type="hidden" name="SAMLResponse" value="<base64>"/></form>
    Handles both attribute orderings (name before value, value before name).
    """
    patterns = [
        r'name=["\']SAMLResponse["\'][^>]+value=["\']([A-Za-z0-9+/=\s]+)["\']',
        r'value=["\']([A-Za-z0-9+/=\s]+)["\'][^>]+name=["\']SAMLResponse["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).replace("\n", "").replace(" ", "")
    return None


class PVWAClient:
    """Async HTTP client for CyberArk PVWA with automatic token lifecycle.

    Authentication priority (each step falls back to the next if unavailable):
      1. SAML SP-initiated — when PVWA_SAML_ENABLED=true and a Bearer token is present:
         a. SP-initiated: GET PVWA SAML init URL → follow redirect to IdP → parse SAMLResponse.
         b. IdP-initiated: call IdP SAML SSO endpoint directly (needs PVWA_SAML_APP_KEY).
      2. Direct credentials — CYBERARK_USERNAME/PASSWORD env vars.
      3. User-provided — username/password/auth_type passed explicitly to _logon().
         If none of the above is available, raises PermissionError with instructions.
    """

    def __init__(self) -> None:
        self._token: Optional[str] = None
        self._saml_session: bool = False  # True when logged in via SAML
        self._client = httpx.AsyncClient(verify=VERIFY_SSL, timeout=30)

    # ------------------------------------------------------------------
    # SAML helpers
    # ------------------------------------------------------------------

    async def _get_saml_assertion(self, bearer_token: str) -> Optional[str]:
        """Obtain a SAML assertion for PVWA using SP-initiated or IdP-initiated flow.

        Tries in order:
          a. SP-initiated: PVWA redirects to IdP → IdP issues SAMLResponse.
          b. IdP-initiated: call IdP SAML SSO endpoint directly (needs PVWA_SAML_APP_KEY).
        Returns the base64-encoded SAMLResponse string ready for PVWA, or None.
        """
        saml = await self._saml_sp_initiated(bearer_token)
        if saml:
            return saml
        if PVWA_SAML_SSO_URL or PVWA_SAML_APP_KEY:
            saml = await self._saml_idp_initiated(bearer_token)
        return saml

    async def _discover_idp_saml_sso_url(self) -> Optional[str]:
        """Fetch IdP SAML metadata XML and extract the SingleSignOnService URL.

        Tries standard metadata endpoint patterns for CyberArk Identity.
        Returns the HTTP-POST (preferred) or HTTP-Redirect SSO URL, or None.
        """
        base = IDP_ISSUER.rstrip("/")
        metadata_candidates = [
            f"{base}/saml/saml2/metadata",
            f"{base}/saml2/metadata",
            f"{base}/SAML20/saml2/metadata",
        ]
        NS = "urn:oasis:names:tc:SAML:2.0:metadata"
        for meta_url in metadata_candidates:
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.get(meta_url, follow_redirects=True)
                if r.status_code != 200:
                    continue
                root = ET.fromstring(r.text)
                post_url = redirect_url = None
                for sso in root.iter(f"{{{NS}}}SingleSignOnService"):
                    binding = sso.get("Binding", "")
                    loc = sso.get("Location", "")
                    if "HTTP-POST" in binding:
                        post_url = loc
                    elif "HTTP-Redirect" in binding:
                        redirect_url = loc
                sso_url = post_url or redirect_url
                if sso_url:
                    logger.info("SAML metadata (%s): SSO URL = %s", meta_url, sso_url)
                    return sso_url
                logger.debug("SAML metadata (%s): parsed OK but no SSO URL found", meta_url)
            except Exception as e:
                logger.debug("SAML metadata %s: %s: %s", meta_url, type(e).__name__, e)
        return None

    async def _saml_sp_initiated(self, bearer_token: str) -> Optional[str]:
        """SP-initiated SAML flow.

        1. GET PVWA SAML initiation URL — PVWA redirects to IdP SSO with SAMLRequest.
        2. GET IdP SSO URL with Bearer token as Authorization header.
        3. Parse SAMLResponse from IdP's HTML auto-submit form.

        Requires PVWA to be reachable from the MCP server container.
        """
        try:
            pvwa_init = f"{PVWA_URL}/PasswordVault/v10/Logon/SAML"
            async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=10) as c:
                r = await c.get(pvwa_init, follow_redirects=False)

            if r.status_code not in (301, 302):
                logger.debug("SP-initiated: PVWA init returned %s (expected redirect)", r.status_code)
                return None

            idp_sso_url = r.headers.get("location", "")
            if not idp_sso_url:
                logger.debug("SP-initiated: no Location header in PVWA redirect")
                return None

            logger.info("SP-initiated: PVWA → IdP SSO: %.100s", idp_sso_url)

            async with httpx.AsyncClient(timeout=15) as c:
                r2 = await c.get(
                    idp_sso_url,
                    headers={"Authorization": f"Bearer {bearer_token}"},
                    follow_redirects=True,
                )

            if r2.status_code != 200:
                logger.warning("SP-initiated: IdP SSO returned %s", r2.status_code)
                return None

            saml = _parse_saml_response_from_html(r2.text)
            if saml:
                logger.info("SP-initiated: SAMLResponse obtained (%d chars)", len(saml))
            else:
                logger.warning("SP-initiated: IdP returned 200 but no SAMLResponse in HTML")
            return saml
        except Exception as e:
            logger.warning("SP-initiated SAML failed: %s: %s", type(e).__name__, e)
        return None

    async def _saml_idp_initiated(self, bearer_token: str) -> Optional[str]:
        """IdP-initiated SAML via direct call to IdP SAML SSO endpoint.

        Priority:
          1. PVWA_SAML_SSO_URL (explicit config, skips all discovery).
          2. SSO URL discovered from IdP SAML metadata XML.
          3. Known CyberArk Identity URL patterns derived from IDP_ISSUER + PVWA_SAML_APP_KEY.
        All requests carry the OAuth Bearer token as Authorization header.
        """
        base = IDP_ISSUER.rstrip("/")
        candidates: list[str] = []

        # Priority 1: explicit SSO URL
        if PVWA_SAML_SSO_URL:
            candidates.append(PVWA_SAML_SSO_URL)
        else:
            # Priority 2: discover from IdP SAML metadata
            discovered = await self._discover_idp_saml_sso_url()
            if discovered:
                sep = "&" if "?" in discovered else "?"
                if PVWA_SAML_APP_KEY:
                    candidates.append(f"{discovered}{sep}appkey={PVWA_SAML_APP_KEY}")
                candidates.append(discovered)

            # Priority 3: CyberArk Identity known URL patterns
            if PVWA_SAML_APP_KEY:
                candidates += [
                    f"{base}/saml/samlp/{PVWA_SAML_APP_KEY}/login",
                    f"{base}/saml/samlp/{PVWA_SAML_APP_KEY}/idpinit",
                    f"{base}/sso/saml/{PVWA_SAML_APP_KEY}/sso",
                    f"{base}/saml20/sso?appkey={PVWA_SAML_APP_KEY}",
                ]

        for url in candidates:
            try:
                logger.info("IdP-initiated: trying %s", url)
                async with httpx.AsyncClient(timeout=15) as c:
                    r = await c.get(
                        url,
                        headers={"Authorization": f"Bearer {bearer_token}"},
                        follow_redirects=True,
                    )
                if r.status_code == 200:
                    saml = _parse_saml_response_from_html(r.text)
                    if saml:
                        logger.info("IdP-initiated: SAMLResponse obtained from %s (%d chars)", url, len(saml))
                        return saml
                    logger.debug("IdP-initiated: %s → 200 but no SAMLResponse (ct: %s)",
                                 url, r.headers.get("content-type", "?"))
                else:
                    logger.debug("IdP-initiated: %s → %s", url, r.status_code)
            except Exception as e:
                logger.warning("IdP-initiated: %s failed: %s: %s", url, type(e).__name__, e)
        return None

    async def _logon_saml(self, saml_assertion: str) -> None:
        """POST SAMLResponse to PVWA SAML logon endpoint."""
        url = f"{BASE_API}/auth/SAML/Logon"
        try:
            xml = base64.b64decode(saml_assertion.encode()).decode(errors="replace")
            m = re.search(r'\bDestination=["\']([^"\']+)["\']', xml)
            logger.info("SAML Destination: %s | PVWA API URL: %s",
                        m.group(1) if m else "NOT FOUND", url)
        except Exception:
            pass
        resp = await self._client.post(
            url,
            data={"SAMLResponse": saml_assertion, "apiUse": "True", "concurrentSession": "True"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not resp.is_success:
            logger.warning("PVWA SAML logon %s — body: %.500s", resp.status_code, resp.text)
        resp.raise_for_status()
        try:
            self._token = resp.json()
        except Exception:
            self._token = resp.text.strip().strip('"')
        self._saml_session = True
        logger.info("PVWA SAML session established.")

    # ------------------------------------------------------------------
    # Core logon / logoff
    # ------------------------------------------------------------------

    async def _logon(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_type: Optional[str] = None,
    ) -> None:
        """Multi-strategy logon.

        Priority: SAML (OAuth Bearer) → env-var credentials → tool-provided credentials.
        Raises PermissionError with guidance when no credentials are available.
        """
        # Strategy 1: SAML via IdP token exchange (2 attempts — PVWA can be slow on first call)
        if PVWA_SAML_ENABLED and USE_EXTERNAL_IDP:
            bearer = _bearer_ctx.get()
            if bearer:
                for _attempt in range(2):
                    saml = await self._get_saml_assertion(bearer)
                    if saml:
                        try:
                            await self._logon_saml(saml)
                            return
                        except Exception as e:
                            if _attempt == 0:
                                logger.warning("SAML logon attempt 1 failed (%s) — retrying in 3s.", e)
                                await asyncio.sleep(3)
                            else:
                                logger.warning("SAML logon failed after 2 attempts (%s) — falling back to direct auth.", e)
                    elif _attempt == 0:
                        logger.warning("SAML assertion not obtained on attempt 1 — retrying in 3s.")
                        await asyncio.sleep(3)

        # Strategy 2 + 3: Direct credentials (env vars, then tool-provided args)
        _username = username or USERNAME
        _password = password or PASSWORD
        _auth_type = auth_type or AUTH_TYPE

        if not _username or not _password:
            raise PermissionError(
                "No PVWA credentials available. "
                "Set CYBERARK_USERNAME and CYBERARK_PASSWORD environment variables, "
                "or call cyberark_logon(username=..., password=..., auth_type=...) directly. "
                "Supported auth_type values: CyberArk (default), LDAP, Windows, RADIUS."
            )

        url = f"{BASE_API}/auth/{_auth_type}/Logon"
        payload = {"username": _username, "password": _password, "concurrentSession": True}
        resp = await self._client.post(url, json=payload)
        resp.raise_for_status()
        try:
            self._token = resp.json()
        except Exception:
            self._token = resp.text.strip().strip('"')
        self._saml_session = False
        logger.info("PVWA session established (auth_type=%s).", _auth_type)

    async def _logoff(self) -> None:
        if not self._token:
            return
        logoff_path = "/auth/SAML/Logoff" if self._saml_session else "/Auth/Logoff/"
        await self._client.post(f"{BASE_API}{logoff_path}", headers=self._auth_headers())
        self._token = None
        self._saml_session = False
        logger.info("PVWA session terminated.")

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": self._token or "", "Content-Type": "application/json"}

    async def request(self, method: str, path: str, *, params: Optional[dict] = None, json: Optional[Any] = None) -> Any:
        if not self._token:
            await self._logon()

        url = f"{BASE_API}{path}"
        resp = await self._client.request(method, url, headers=self._auth_headers(), params=params, json=json)

        if resp.status_code == 401:
            logger.info("Session expired — re-authenticating.")
            self._token = None
            await self._logon()
            resp = await self._client.request(method, url, headers=self._auth_headers(), params=params, json=json)

        resp.raise_for_status()
        return resp.json() if resp.content else {"status": "ok"}


client = PVWAClient()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text(data: Any) -> dict:
    """Wrap a result value into the MCP content array format."""
    text = data if isinstance(data, str) else json.dumps(data, indent=2, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}]}

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    # ── Authentication ──────────────────────────────────────────────────────
    {
        "name": "cyberark_logon",
        "description": (
            "OPTIONAL — Do NOT call this before other tools. "
            "All CyberArk tools authenticate automatically (via SAML or env-var credentials) "
            "before executing; you do not need to log in first. "
            "If the user asks to log in or you need to verify credentials, "
            "first call cyberark_get_logged_on_user to check if a session is already active; "
            "only proceed with this tool if that returns an error or shows no active session. "
            "Only call this tool explicitly when the user specifically asks to log in, "
            "or to authenticate as a different user with custom credentials. "
            "Authentication priority used by all tools: "
            "(1) SAML via IdP when PVWA_SAML_ENABLED=true; "
            "(2) CYBERARK_USERNAME/PASSWORD environment variables; "
            "(3) username/password/auth_type supplied here."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "PVWA username. Overrides CYBERARK_USERNAME env var.",
                },
                "password": {
                    "type": "string",
                    "description": "PVWA password. Overrides CYBERARK_PASSWORD env var.",
                },
                "auth_type": {
                    "type": "string",
                    "description": (
                        "Authentication method. Overrides CYBERARK_AUTH_TYPE env var. "
                        "Allowed values: CyberArk (default), LDAP, Windows, RADIUS."
                    ),
                },
            },
        },
    },
    {
        "name": "cyberark_logoff",
        "description": "OPTIONAL — Do NOT call this after other tools. The server manages session lifecycle automatically. Only call explicitly when the user specifically asks to log out.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cyberark_get_logged_on_user",
        "description": (
            "Returns details about the currently authenticated PVWA user (whoami). "
            "Call this first to verify whether a PVWA session is already active "
            "before asking the user for credentials or calling cyberark_logon. "
            "If this returns user details, the session is valid and no logon is needed."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    # ── System Health ───────────────────────────────────────────────────────
    {
        "name": "cyberark_get_health_summary",
        "description": "Retrieve a summary of the health status for all CyberArk PAM components (PVWA, CPM, PSM, AIM, PTA).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cyberark_get_health_details",
        "description": "Retrieve detailed health information for a specific CyberArk PAM component.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "component_id": {
                    "type": "string",
                    "description": "Component to query: PVWA | SessionManagement | CPM | PSM | AIM",
                }
            },
            "required": ["component_id"],
        },
    },
    # ── Accounts ────────────────────────────────────────────────────────────
    {
        "name": "cyberark_list_accounts",
        "description": "List privileged accounts stored in the CyberArk Vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Free-text keyword search across account properties."},
                "search_type": {"type": "string", "description": "Search mode: contains (default) or startswith."},
                "safe_name": {"type": "string", "description": "Filter results to a specific Safe."},
                "offset": {"type": "integer", "description": "Pagination start index (default 0)."},
                "limit": {"type": "integer", "description": "Maximum accounts to return (default 50, max 1000)."},
                "sort": {"type": "string", "description": "Sort expression, e.g. 'userName asc'."},
            },
        },
    },
    {
        "name": "cyberark_get_account",
        "description": "Retrieve full details for a single privileged account by its Vault ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "The unique account ID (e.g. '12_34')."}
            },
            "required": ["account_id"],
        },
    },
    {
        "name": "cyberark_add_account",
        "description": "Add a new privileged account to the CyberArk Vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Display name for the account (unique within Safe)."},
                "address": {"type": "string", "description": "Target machine address (IP or hostname)."},
                "user_name": {"type": "string", "description": "Privileged username on the target machine."},
                "platform_id": {"type": "string", "description": "Platform ID managing the account (e.g. WinServerLocal)."},
                "safe_name": {"type": "string", "description": "Name of the Safe where the account will be stored."},
                "secret": {"type": "string", "description": "The account secret (password or private key content)."},
                "secret_type": {"type": "string", "description": "password (default) or key (SSH private key)."},
                "automatic_management_enabled": {"type": "boolean", "description": "Whether CPM manages the password (default true)."},
                "manual_management_reason": {"type": "string", "description": "Required reason text if automatic management is disabled."},
                "remote_machines": {"type": "string", "description": "Semicolon-separated list of machines for PSM connections."},
                "access_restricted_to_remote_machines": {"type": "boolean", "description": "Restrict PSM connections to remote_machines list only."},
            },
            "required": ["name", "address", "user_name", "platform_id", "safe_name", "secret"],
        },
    },
    {
        "name": "cyberark_update_account",
        "description": "Update one or more properties of an existing privileged account. Only provided fields are modified.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "The unique account ID to update (e.g. '12_34')."},
                "address": {"type": "string", "description": "New target machine address."},
                "user_name": {"type": "string", "description": "New privileged username."},
                "platform_id": {"type": "string", "description": "New platform ID."},
                "name": {"type": "string", "description": "New display name for the account."},
                "automatic_management_enabled": {"type": "boolean", "description": "Enable or disable CPM password management."},
                "manual_management_reason": {"type": "string", "description": "Reason text (required when disabling CPM)."},
                "remote_machines": {"type": "string", "description": "New semicolon-separated list of remote machines."},
                "access_restricted_to_remote_machines": {"type": "boolean", "description": "Update PSM access restriction flag."},
            },
            "required": ["account_id"],
        },
    },
    {
        "name": "cyberark_delete_account",
        "description": "Permanently delete a privileged account from the CyberArk Vault. This action is irreversible.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "The unique account ID to delete (e.g. '12_34')."}
            },
            "required": ["account_id"],
        },
    },
    # ── Safes ────────────────────────────────────────────────────────────────
    {
        "name": "cyberark_list_safes",
        "description": "List all Safes accessible to the authenticated user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Search string to filter Safes by name."},
                "offset": {"type": "integer", "description": "Pagination start index (default 0)."},
                "limit": {"type": "integer", "description": "Maximum Safes to return (default 25)."},
                "sort": {"type": "string", "description": "Sort expression, e.g. 'safeName desc'."},
                "include_accounts": {"type": "boolean", "description": "Include account details in each Safe (default false)."},
                "extended_details": {"type": "boolean", "description": "Return extended Safe metadata (default false)."},
            },
        },
    },
    {
        "name": "cyberark_get_safe",
        "description": "Retrieve details for a specific Safe by its name or numeric ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "safe_id": {"type": "string", "description": "Safe name or numeric Safe ID."},
                "include_accounts": {"type": "boolean", "description": "Include account list in response (default false)."},
            },
            "required": ["safe_id"],
        },
    },
    {
        "name": "cyberark_add_safe",
        "description": "Create a new Safe in the CyberArk Vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "safe_name": {"type": "string", "description": "Unique name for the new Safe."},
                "description": {"type": "string", "description": "Optional description."},
                "managing_cpm": {"type": "string", "description": "Name of the CPM that will manage accounts in this Safe."},
                "number_of_days_retention": {"type": "integer", "description": "Days to retain password versions (default 7)."},
                "number_of_versions_retention": {"type": "integer", "description": "Number of password versions to retain. Mutually exclusive with days retention."},
                "olac_enabled": {"type": "boolean", "description": "Enable Object Level Access Control (default false)."},
                "auto_purge_enabled": {"type": "boolean", "description": "Auto-delete expired accounts (default false)."},
                "location": {"type": "string", "description": "Vault folder location for the Safe (default root)."},
            },
            "required": ["safe_name"],
        },
    },
    {
        "name": "cyberark_delete_safe",
        "description": "Permanently delete a Safe and all accounts within it. This action is irreversible.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "safe_id": {"type": "string", "description": "Safe name or numeric Safe ID to delete."}
            },
            "required": ["safe_id"],
        },
    },
    {
        "name": "cyberark_list_safe_members",
        "description": "List all members of a Safe and their permissions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "safe_id": {"type": "string", "description": "Safe name or numeric Safe ID."},
                "search": {"type": "string", "description": "Filter members by name."},
                "offset": {"type": "integer", "description": "Pagination start index (default 0)."},
                "limit": {"type": "integer", "description": "Maximum members to return (default 25)."},
                "member_type_filter": {"type": "string", "description": "Filter by type: user, group, or role."},
            },
            "required": ["safe_id"],
        },
    },
    {
        "name": "cyberark_add_safe_member",
        "description": "Add a user or group as a member of a Safe with specific permissions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "safe_id": {"type": "string", "description": "Target Safe name or numeric ID."},
                "member_name": {"type": "string", "description": "Username or group name to add."},
                "member_type": {"type": "string", "description": "User (default), Group, or Role."},
                "search_in": {"type": "string", "description": "Where to search: Vault (default) or a directory name."},
                "membership_expiration_date": {"type": "integer", "description": "Unix timestamp for membership expiry."},
                "use_accounts": {"type": "boolean"}, "retrieve_accounts": {"type": "boolean"},
                "list_accounts": {"type": "boolean"}, "add_accounts": {"type": "boolean"},
                "update_account_content": {"type": "boolean"}, "update_account_properties": {"type": "boolean"},
                "initiate_cpm_management": {"type": "boolean"}, "specify_next_account_content": {"type": "boolean"},
                "rename_accounts": {"type": "boolean"}, "delete_accounts": {"type": "boolean"},
                "unlock_accounts": {"type": "boolean"}, "manage_safe": {"type": "boolean"},
                "manage_safe_members": {"type": "boolean"}, "backup_safe": {"type": "boolean"},
                "view_audit_log": {"type": "boolean"}, "view_safe_members": {"type": "boolean"},
                "access_without_confirmation": {"type": "boolean"}, "create_folders": {"type": "boolean"},
                "delete_folders": {"type": "boolean"}, "move_accounts_and_folders": {"type": "boolean"},
                "requests_authorization_level1": {"type": "boolean"}, "requests_authorization_level2": {"type": "boolean"},
            },
            "required": ["safe_id", "member_name"],
        },
    },
    # ── Users ────────────────────────────────────────────────────────────────
    {
        "name": "cyberark_list_users",
        "description": "List Vault users with optional filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Free-text search across username and description."},
                "filter": {"type": "string", "description": "Filter expression, e.g. 'componentUser eq false'."},
                "extended_details": {"type": "boolean", "description": "Return extended user metadata (default false)."},
                "sort": {"type": "string", "description": "Sort expression, e.g. 'username asc'."},
                "page_offset": {"type": "integer", "description": "Pagination offset (default 0)."},
                "page_size": {"type": "integer", "description": "Results per page (default 25)."},
            },
        },
    },
    {
        "name": "cyberark_get_user",
        "description": "Get full details of a single Vault user by their numeric user ID. Call cyberark_list_users first to obtain the numeric ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "Numeric Vault user ID."},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "cyberark_add_user",
        "description": "Create a new Vault user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Unique login name for the new user."},
                "user_type": {"type": "string", "description": "User type, e.g. EPVUser, BasicUser, or BizUser."},
                "initial_password": {"type": "string", "description": "Initial password (required for CyberArk-authenticated users)."},
                "authentication_method": {"type": "array", "items": {"type": "string"}, "description": "Authentication methods, e.g. [\"CyberArk\"] or [\"LDAP\"]."},
                "location": {"type": "string", "description": "Vault folder location (default root '\\\\')."},
                "description": {"type": "string", "description": "Free-text description."},
                "enable_user": {"type": "boolean", "description": "Whether the account is enabled on creation (default true)."},
                "change_pass_on_next_logon": {"type": "boolean", "description": "Force password change on first login."},
                "password_never_expires": {"type": "boolean", "description": "Disable password expiry."},
                "expiry_date": {"type": "integer", "description": "Account expiry as Unix timestamp (0 = never)."},
            },
            "required": ["username", "initial_password"],
        },
    },
    {
        "name": "cyberark_update_user",
        "description": "Update properties of an existing Vault user. Only provided fields are modified.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "Numeric Vault user ID to update."},
                "enable_user": {"type": "boolean"},
                "change_pass_on_next_logon": {"type": "boolean"},
                "password_never_expires": {"type": "boolean"},
                "expiry_date": {"type": "integer", "description": "Account expiry as Unix timestamp (0 = never)."},
                "description": {"type": "string"},
                "location": {"type": "string"},
                "authentication_method": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "cyberark_delete_user",
        "description": "Permanently delete a Vault user. This action is irreversible.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "Numeric Vault user ID to delete."},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "cyberark_activate_user",
        "description": "Activate a suspended Vault user account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "Numeric Vault user ID to activate."},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "cyberark_enable_user",
        "description": "Enable a disabled Vault user account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "Numeric Vault user ID to enable."},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "cyberark_disable_user",
        "description": "Disable a Vault user account (user cannot log in).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "Numeric Vault user ID to disable."},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "cyberark_reset_user_password",
        "description": "Reset the password of a Vault user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "Numeric Vault user ID."},
                "new_password": {"type": "string", "description": "New password to set for the user."},
            },
            "required": ["user_id", "new_password"],
        },
    },
    # ── User Groups ──────────────────────────────────────────────────────────
    {
        "name": "cyberark_list_groups",
        "description": "List Vault user groups with optional filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Search groups by name."},
                "filter": {"type": "string", "description": "Filter expression, e.g. 'groupType eq Vault'."},
                "sort": {"type": "string", "description": "Sort expression, e.g. 'groupName asc'."},
                "include_members": {"type": "boolean", "description": "Include member list in each group (default false)."},
            },
        },
    },
    {
        "name": "cyberark_get_group",
        "description": "Get details of a Vault user group by its numeric group ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "integer", "description": "Numeric Vault group ID."},
                "include_members": {"type": "boolean", "description": "Include member list (default false)."},
            },
            "required": ["group_id"],
        },
    },
    {
        "name": "cyberark_create_group",
        "description": "Create a new Vault user group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_name": {"type": "string", "description": "Unique name for the new group."},
                "description": {"type": "string", "description": "Optional description."},
                "location": {"type": "string", "description": "Vault folder location (default root '\\\\')."},
            },
            "required": ["group_name"],
        },
    },
    {
        "name": "cyberark_update_group",
        "description": "Rename a Vault user group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "integer", "description": "Numeric Vault group ID."},
                "group_name": {"type": "string", "description": "New name for the group."},
            },
            "required": ["group_id", "group_name"],
        },
    },
    {
        "name": "cyberark_delete_group",
        "description": "Delete a Vault user group. This action is irreversible.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "integer", "description": "Numeric Vault group ID to delete."},
            },
            "required": ["group_id"],
        },
    },
    {
        "name": "cyberark_add_group_member",
        "description": "Add a user to a Vault group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "integer", "description": "Numeric Vault group ID."},
                "member_id": {"type": "integer", "description": "Numeric Vault user ID to add."},
                "member_type": {"type": "string", "description": "Member type: vault (default) or domain."},
                "domain_name": {"type": "string", "description": "Domain name (required for domain member type)."},
            },
            "required": ["group_id", "member_id"],
        },
    },
    {
        "name": "cyberark_remove_group_member",
        "description": "Remove a user from a Vault group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "integer", "description": "Numeric Vault group ID."},
                "member_name": {"type": "string", "description": "Username of the member to remove."},
            },
            "required": ["group_id", "member_name"],
        },
    },
    # ── Live Sessions ────────────────────────────────────────────────────────
    {
        "name": "cyberark_list_live_sessions",
        "description": "List currently active PSM sessions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Search across session properties."},
                "safe": {"type": "string", "description": "Filter sessions by Safe name."},
                "from_time": {"type": "integer", "description": "Start of time range as Unix timestamp."},
                "to_time": {"type": "integer", "description": "End of time range as Unix timestamp."},
                "limit": {"type": "integer", "description": "Maximum sessions to return (default 25)."},
                "offset": {"type": "integer", "description": "Pagination start index (default 0)."},
                "sort": {"type": "string", "description": "Sort expression, e.g. 'StartTime desc'."},
            },
        },
    },
    {
        "name": "cyberark_get_live_session",
        "description": "Get details of a specific active PSM session by its session ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Live session ID (GUID)."},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "cyberark_get_session_activities",
        "description": "Get the activity log of a specific active PSM session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Live session ID (GUID)."},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "cyberark_monitor_session",
        "description": "Get the monitoring connection details for a live PSM session (returns a monitoring URL or token).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Live session ID (GUID)."},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "cyberark_suspend_session",
        "description": "Suspend an active PSM session, temporarily blocking user input.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Live session ID (GUID) to suspend."},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "cyberark_resume_session",
        "description": "Resume a previously suspended PSM session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Live session ID (GUID) to resume."},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "cyberark_terminate_session",
        "description": "Forcefully terminate an active PSM session. This immediately disconnects the user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Live session ID (GUID) to terminate."},
            },
            "required": ["session_id"],
        },
    },
    # ── Recordings ───────────────────────────────────────────────────────────
    {
        "name": "cyberark_list_recordings",
        "description": "List PSM session recordings stored in the Vault. The numeric SessionId field in each result is the ID to pass to cyberark_get_recording and cyberark_get_recording_activities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Search across recording properties."},
                "safe": {"type": "string", "description": "Filter recordings by Safe name."},
                "from_time": {"type": "integer", "description": "Start of time range as Unix timestamp."},
                "to_time": {"type": "integer", "description": "End of time range as Unix timestamp."},
                "limit": {"type": "integer", "description": "Maximum recordings to return (default 25)."},
                "offset": {"type": "integer", "description": "Pagination start index (default 0)."},
            },
        },
    },
    {
        "name": "cyberark_get_recording",
        "description": "Get details of a specific PSM session recording. Use the SessionID string from cyberark_list_recordings (e.g. '32_515'). Do not use SessionGuid.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "recording_id": {"type": "string", "description": "SessionID string from cyberark_list_recordings results, e.g. '32_515'. Do NOT use SessionGuid."},
            },
            "required": ["recording_id"],
        },
    },
    {
        "name": "cyberark_get_recording_activities",
        "description": "Get the activity log of a specific PSM session recording. Use the SessionID string from cyberark_list_recordings (e.g. '32_515'). Do not use SessionGuid.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "recording_id": {"type": "string", "description": "SessionID string from cyberark_list_recordings results, e.g. '32_515'. Do NOT use SessionGuid."},
            },
            "required": ["recording_id"],
        },
    },
]

# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

async def tool_cyberark_logon(args: dict) -> dict:
    username = args.get("username") or None
    password = args.get("password") or None
    auth_type = args.get("auth_type") or None
    await client._logon(username=username, password=password, auth_type=auth_type)
    method = "SAML" if client._saml_session else (auth_type or AUTH_TYPE)
    return _text(f"Successfully authenticated to PVWA (method: {method}).")


async def tool_cyberark_logoff(args: dict) -> dict:
    await client._logoff()
    return _text("PVWA session terminated.")


async def tool_cyberark_get_logged_on_user(args: dict) -> dict:
    if not client._token:
        await client._logon()
    url = f"{PVWA_URL}/PasswordVault/WebServices/PIMServices.svc/User"
    resp = await client._client.get(url, headers=client._auth_headers())
    resp.raise_for_status()
    return _text(resp.json() if resp.content else {"status": "ok"})


async def tool_cyberark_get_health_summary(args: dict) -> dict:
    return _text(await client.request("GET", "/ComponentsMonitoringSummary/"))


async def tool_cyberark_get_health_details(args: dict) -> dict:
    cid = args.get("component_id", "").strip()
    if not cid:
        return _text("component_id is required. Valid values: PVWA, SessionManagement, CPM, PSM, AIM")
    return _text(await client.request("GET", f"/ComponentsMonitoringDetails/{cid}"))


async def tool_cyberark_list_accounts(args: dict) -> dict:
    params: dict[str, Any] = {"offset": args.get("offset", 0), "limit": args.get("limit", 50)}
    if args.get("search"):
        params["search"] = args["search"]
    if args.get("search_type"):
        params["searchType"] = args["search_type"]
    if args.get("safe_name"):
        params["filter"] = f"safeName eq {args['safe_name']}"
    if args.get("sort"):
        params["sort"] = args["sort"]
    return _text(await client.request("GET", "/Accounts/", params=params))


async def tool_cyberark_get_account(args: dict) -> dict:
    return _text(await client.request("GET", f"/Accounts/{args['account_id']}/"))


async def tool_cyberark_add_account(args: dict) -> dict:
    payload: dict[str, Any] = {
        "name": args["name"],
        "address": args["address"],
        "userName": args["user_name"],
        "platformId": args["platform_id"],
        "safeName": args["safe_name"],
        "secretType": args.get("secret_type", "password"),
        "secret": args["secret"],
        "secretManagement": {"automaticManagementEnabled": args.get("automatic_management_enabled", True)},
    }
    if args.get("manual_management_reason"):
        payload["secretManagement"]["manualManagementReason"] = args["manual_management_reason"]
    if args.get("remote_machines") or args.get("access_restricted_to_remote_machines"):
        payload["remoteMachinesAccess"] = {
            "remoteMachines": args.get("remote_machines", ""),
            "accessRestrictedToRemoteMachines": args.get("access_restricted_to_remote_machines", False),
        }
    return _text(await client.request("POST", "/Accounts", json=payload))


async def tool_cyberark_update_account(args: dict) -> dict:
    account_id = args["account_id"]
    field_map = {
        "address": "/address", "user_name": "/userName", "platform_id": "/platformId",
        "name": "/name",
        "automatic_management_enabled": "/secretManagement/automaticManagementEnabled",
        "manual_management_reason": "/secretManagement/manualManagementReason",
        "remote_machines": "/remoteMachinesAccess/remoteMachines",
        "access_restricted_to_remote_machines": "/remoteMachinesAccess/accessRestrictedToRemoteMachines",
    }
    ops = [
        {"op": "replace", "path": path, "value": args[key]}
        for key, path in field_map.items()
        if key in args and args[key] is not None
    ]
    if not ops:
        return _text("No fields to update.")
    return _text(await client.request("PATCH", f"/Accounts/{account_id}/", json=ops))


async def tool_cyberark_delete_account(args: dict) -> dict:
    await client.request("DELETE", f"/Accounts/{args['account_id']}/")
    return _text(f"Account {args['account_id']} deleted.")


async def tool_cyberark_list_safes(args: dict) -> dict:
    params: dict[str, Any] = {
        "offset": args.get("offset", 0),
        "limit": args.get("limit", 25),
        "includeAccounts": args.get("include_accounts", False),
        "extendedDetails": args.get("extended_details", False),
    }
    if args.get("search"):
        params["search"] = args["search"]
    if args.get("sort"):
        params["sort"] = args["sort"]
    return _text(await client.request("GET", "/Safes/", params=params))


async def tool_cyberark_get_safe(args: dict) -> dict:
    params: dict[str, Any] = {}
    if args.get("include_accounts"):
        params["includeAccounts"] = True
    return _text(await client.request("GET", f"/Safes/{args['safe_id']}/", params=params or None))


async def tool_cyberark_add_safe(args: dict) -> dict:
    payload: dict[str, Any] = {
        "safeName": args["safe_name"],
        "numberOfDaysRetention": args.get("number_of_days_retention", 7),
        "oLACEnabled": args.get("olac_enabled", False),
        "autoPurgeEnabled": args.get("auto_purge_enabled", False),
        "location": args.get("location", ""),
    }
    if args.get("description"):
        payload["description"] = args["description"]
    if args.get("managing_cpm"):
        payload["managingCPM"] = args["managing_cpm"]
    if args.get("number_of_versions_retention") is not None:
        payload["numberOfVersionsRetention"] = args["number_of_versions_retention"]
        payload.pop("numberOfDaysRetention", None)
    return _text(await client.request("POST", "/Safes/", json=payload))


async def tool_cyberark_delete_safe(args: dict) -> dict:
    await client.request("DELETE", f"/Safes/{args['safe_id']}/")
    return _text(f"Safe {args['safe_id']} deleted.")


async def tool_cyberark_list_safe_members(args: dict) -> dict:
    params: dict[str, Any] = {"offset": args.get("offset", 0), "limit": args.get("limit", 25)}
    if args.get("search"):
        params["search"] = args["search"]
    if args.get("member_type_filter"):
        params["filter"] = f"memberType eq {args['member_type_filter']}"
    return _text(await client.request("GET", f"/Safes/{args['safe_id']}/Members/", params=params))


async def tool_cyberark_add_safe_member(args: dict) -> dict:
    perm_keys = [
        "use_accounts", "retrieve_accounts", "list_accounts", "add_accounts",
        "update_account_content", "update_account_properties", "initiate_cpm_management",
        "specify_next_account_content", "rename_accounts", "delete_accounts", "unlock_accounts",
        "manage_safe", "manage_safe_members", "backup_safe", "view_audit_log", "view_safe_members",
        "access_without_confirmation", "create_folders", "delete_folders", "move_accounts_and_folders",
        "requests_authorization_level1", "requests_authorization_level2",
    ]

    def to_camel(s: str) -> str:
        parts = s.split("_")
        return parts[0] + "".join(p.capitalize() for p in parts[1:])

    payload: dict[str, Any] = {
        "memberName": args["member_name"],
        "MemberType": args.get("member_type", "User"),
        "searchIn": args.get("search_in", "Vault"),
        "permissions": {to_camel(k): args.get(k, False) for k in perm_keys},
    }
    if args.get("membership_expiration_date"):
        payload["membershipExpirationDate"] = args["membership_expiration_date"]
    return _text(await client.request("POST", f"/Safes/{args['safe_id']}/Members/", json=payload))


# ── User handlers ────────────────────────────────────────────────────────────

async def tool_cyberark_list_users(args: dict) -> dict:
    params: dict[str, Any] = {}
    if args.get("search"):
        params["search"] = args["search"]
    if args.get("filter"):
        params["filter"] = args["filter"]
    if args.get("extended_details"):
        params["ExtendedDetails"] = args["extended_details"]
    if args.get("sort"):
        params["sort"] = args["sort"]
    if args.get("page_offset") is not None:
        params["pageOffset"] = args["page_offset"]
    if args.get("page_size") is not None:
        params["pageSize"] = args["page_size"]
    return _text(await client.request("GET", "/Users/", params=params or None))


async def tool_cyberark_get_user(args: dict) -> dict:
    uid = int(args.get("user_id") or 0)
    if uid <= 0:
        return _text("user_id must be a positive integer. Call cyberark_list_users first to obtain valid user IDs.")
    return _text(await client.request("GET", f"/Users/{uid}/"))


async def tool_cyberark_add_user(args: dict) -> dict:
    payload: dict[str, Any] = {
        "username": args["username"],
        "initialPassword": args["initial_password"],
    }
    if args.get("user_type"):
        payload["userType"] = args["user_type"]
    if args.get("authentication_method"):
        payload["authenticationMethod"] = args["authentication_method"]
    if args.get("location"):
        payload["location"] = args["location"]
    if args.get("description"):
        payload["description"] = args["description"]
    if args.get("enable_user") is not None:
        payload["enableUser"] = args["enable_user"]
    if args.get("change_pass_on_next_logon") is not None:
        payload["changePassOnNextLogon"] = args["change_pass_on_next_logon"]
    if args.get("password_never_expires") is not None:
        payload["passwordNeverExpires"] = args["password_never_expires"]
    if args.get("expiry_date") is not None:
        payload["expiryDate"] = args["expiry_date"]
    return _text(await client.request("POST", "/Users/", json=payload))


async def tool_cyberark_update_user(args: dict) -> dict:
    user_id = int(args.get("user_id") or 0)
    if user_id <= 0:
        return _text("user_id must be a positive integer. Call cyberark_list_users first to obtain valid user IDs.")
    payload: dict[str, Any] = {}
    for src, dst in [
        ("enable_user", "enableUser"),
        ("change_pass_on_next_logon", "changePassOnNextLogon"),
        ("password_never_expires", "passwordNeverExpires"),
        ("expiry_date", "expiryDate"),
        ("description", "description"),
        ("location", "location"),
        ("authentication_method", "authenticationMethod"),
    ]:
        if args.get(src) is not None:
            payload[dst] = args[src]
    if not payload:
        return _text("No fields to update.")
    return _text(await client.request("PUT", f"/Users/{user_id}/", json=payload))


def _require_user_id(args: dict) -> Optional[int]:
    uid = int(args.get("user_id") or 0)
    return uid if uid > 0 else None


def _require_group_id(args: dict) -> Optional[int]:
    gid = int(args.get("group_id") or 0)
    return gid if gid > 0 else None


_USER_ID_HINT = "user_id must be a positive integer. Call cyberark_list_users first to obtain valid user IDs."
_GROUP_ID_HINT = "group_id must be a positive integer. Call cyberark_list_groups first to obtain valid group IDs."


async def tool_cyberark_delete_user(args: dict) -> dict:
    uid = _require_user_id(args)
    if not uid:
        return _text(_USER_ID_HINT)
    await client.request("DELETE", f"/Users/{uid}/")
    return _text(f"User {uid} deleted.")


async def tool_cyberark_activate_user(args: dict) -> dict:
    uid = _require_user_id(args)
    if not uid:
        return _text(_USER_ID_HINT)
    await client.request("POST", f"/Users/{uid}/activate/")
    return _text(f"User {uid} activated.")


async def tool_cyberark_enable_user(args: dict) -> dict:
    uid = _require_user_id(args)
    if not uid:
        return _text(_USER_ID_HINT)
    await client.request("POST", f"/Users/{uid}/enable/")
    return _text(f"User {uid} enabled.")


async def tool_cyberark_disable_user(args: dict) -> dict:
    uid = _require_user_id(args)
    if not uid:
        return _text(_USER_ID_HINT)
    await client.request("POST", f"/Users/{uid}/disable/")
    return _text(f"User {uid} disabled.")


async def tool_cyberark_reset_user_password(args: dict) -> dict:
    uid = _require_user_id(args)
    if not uid:
        return _text(_USER_ID_HINT)
    payload = {"id": uid, "newPassword": args["new_password"]}
    await client.request("POST", f"/Users/{uid}/ResetPassword/", json=payload)
    return _text(f"Password reset for user {uid}.")


# ── Group handlers ───────────────────────────────────────────────────────────

async def tool_cyberark_list_groups(args: dict) -> dict:
    params: dict[str, Any] = {}
    if args.get("search"):
        params["search"] = args["search"]
    if args.get("filter"):
        params["filter"] = args["filter"]
    if args.get("sort"):
        params["sort"] = args["sort"]
    if args.get("include_members"):
        params["includeMembers"] = args["include_members"]
    return _text(await client.request("GET", "/UserGroups/", params=params or None))


async def tool_cyberark_get_group(args: dict) -> dict:
    gid = _require_group_id(args)
    if not gid:
        return _text(_GROUP_ID_HINT)
    params = {}
    if args.get("include_members"):
        params["includeMembers"] = True
    return _text(await client.request("GET", f"/UserGroups/{gid}/", params=params or None))


async def tool_cyberark_create_group(args: dict) -> dict:
    payload: dict[str, Any] = {"groupName": args["group_name"]}
    if args.get("description"):
        payload["description"] = args["description"]
    if args.get("location"):
        payload["location"] = args["location"]
    return _text(await client.request("POST", "/UserGroups/", json=payload))


async def tool_cyberark_update_group(args: dict) -> dict:
    gid = _require_group_id(args)
    if not gid:
        return _text(_GROUP_ID_HINT)
    payload = {"groupName": args["group_name"]}
    return _text(await client.request("PUT", f"/UserGroups/{gid}/", json=payload))


async def tool_cyberark_delete_group(args: dict) -> dict:
    gid = _require_group_id(args)
    if not gid:
        return _text(_GROUP_ID_HINT)
    await client.request("DELETE", f"/UserGroups/{gid}/")
    return _text(f"Group {gid} deleted.")


async def tool_cyberark_add_group_member(args: dict) -> dict:
    gid = _require_group_id(args)
    if not gid:
        return _text(_GROUP_ID_HINT)
    payload: dict[str, Any] = {
        "memberId": args["member_id"],
        "memberType": args.get("member_type", "vault"),
    }
    if args.get("domain_name"):
        payload["domainName"] = args["domain_name"]
    return _text(await client.request("POST", f"/UserGroups/{gid}/Members/", json=payload))


async def tool_cyberark_remove_group_member(args: dict) -> dict:
    gid = _require_group_id(args)
    if not gid:
        return _text(_GROUP_ID_HINT)
    await client.request("DELETE", f"/UserGroups/{gid}/Members/{args['member_name']}/")
    return _text(f"Member {args['member_name']} removed from group {gid}.")


# ── Live Session handlers ────────────────────────────────────────────────────

async def tool_cyberark_list_live_sessions(args: dict) -> dict:
    params: dict[str, Any] = {
        "Limit": args.get("limit", 25),
        "Offset": args.get("offset", 0),
    }
    if args.get("search"):
        params["Search"] = args["search"]
    if args.get("safe"):
        params["Safe"] = args["safe"]
    if args.get("from_time"):
        params["FromTime"] = args["from_time"]
    if args.get("to_time"):
        params["ToTime"] = args["to_time"]
    if args.get("sort"):
        params["Sort"] = args["sort"]
    return _text(await client.request("GET", "/LiveSessions/", params=params))


async def tool_cyberark_get_live_session(args: dict) -> dict:
    return _text(await client.request("GET", f"/LiveSessions/{args['session_id']}/"))


async def tool_cyberark_get_session_activities(args: dict) -> dict:
    return _text(await client.request("GET", f"/LiveSessions/{args['session_id']}/activities/"))


async def tool_cyberark_monitor_session(args: dict) -> dict:
    return _text(await client.request("GET", f"/LiveSessions/{args['session_id']}/Monitor/"))


async def tool_cyberark_suspend_session(args: dict) -> dict:
    await client.request("POST", f"/LiveSessions/{args['session_id']}/Suspend/")
    return _text(f"Session {args['session_id']} suspended.")


async def tool_cyberark_resume_session(args: dict) -> dict:
    await client.request("POST", f"/LiveSessions/{args['session_id']}/Resume/")
    return _text(f"Session {args['session_id']} resumed.")


async def tool_cyberark_terminate_session(args: dict) -> dict:
    await client.request("POST", f"/LiveSessions/{args['session_id']}/Terminate/")
    return _text(f"Session {args['session_id']} terminated.")


# ── Recording handlers ───────────────────────────────────────────────────────

async def tool_cyberark_list_recordings(args: dict) -> dict:
    params: dict[str, Any] = {
        "Limit": args.get("limit", 25),
        "Offset": args.get("offset", 0),
    }
    if args.get("search"):
        params["Search"] = args["search"]
    if args.get("safe"):
        params["Safe"] = args["safe"]
    if args.get("from_time"):
        params["FromTime"] = args["from_time"]
    if args.get("to_time"):
        params["ToTime"] = args["to_time"]
    return _text(await client.request("GET", "/Recordings/", params=params))


async def tool_cyberark_get_recording(args: dict) -> dict:
    return _text(await client.request("GET", f"/Recordings/{args['recording_id']}/"))


async def tool_cyberark_get_recording_activities(args: dict) -> dict:
    return _text(await client.request("GET", f"/Recordings/{args['recording_id']}/activities"))


TOOL_HANDLERS: dict[str, Any] = {
    "cyberark_logon": tool_cyberark_logon,
    "cyberark_logoff": tool_cyberark_logoff,
    "cyberark_get_logged_on_user": tool_cyberark_get_logged_on_user,
    "cyberark_get_health_summary": tool_cyberark_get_health_summary,
    "cyberark_get_health_details": tool_cyberark_get_health_details,
    "cyberark_list_accounts": tool_cyberark_list_accounts,
    "cyberark_get_account": tool_cyberark_get_account,
    "cyberark_add_account": tool_cyberark_add_account,
    "cyberark_update_account": tool_cyberark_update_account,
    "cyberark_delete_account": tool_cyberark_delete_account,
    "cyberark_list_safes": tool_cyberark_list_safes,
    "cyberark_get_safe": tool_cyberark_get_safe,
    "cyberark_add_safe": tool_cyberark_add_safe,
    "cyberark_delete_safe": tool_cyberark_delete_safe,
    "cyberark_list_safe_members": tool_cyberark_list_safe_members,
    "cyberark_add_safe_member": tool_cyberark_add_safe_member,
    # Users
    "cyberark_list_users": tool_cyberark_list_users,
    "cyberark_get_user": tool_cyberark_get_user,
    "cyberark_add_user": tool_cyberark_add_user,
    "cyberark_update_user": tool_cyberark_update_user,
    "cyberark_delete_user": tool_cyberark_delete_user,
    "cyberark_activate_user": tool_cyberark_activate_user,
    "cyberark_enable_user": tool_cyberark_enable_user,
    "cyberark_disable_user": tool_cyberark_disable_user,
    "cyberark_reset_user_password": tool_cyberark_reset_user_password,
    # Groups
    "cyberark_list_groups": tool_cyberark_list_groups,
    "cyberark_get_group": tool_cyberark_get_group,
    "cyberark_create_group": tool_cyberark_create_group,
    "cyberark_update_group": tool_cyberark_update_group,
    "cyberark_delete_group": tool_cyberark_delete_group,
    "cyberark_add_group_member": tool_cyberark_add_group_member,
    "cyberark_remove_group_member": tool_cyberark_remove_group_member,
    # Live Sessions
    "cyberark_list_live_sessions": tool_cyberark_list_live_sessions,
    "cyberark_get_live_session": tool_cyberark_get_live_session,
    "cyberark_get_session_activities": tool_cyberark_get_session_activities,
    "cyberark_monitor_session": tool_cyberark_monitor_session,
    "cyberark_suspend_session": tool_cyberark_suspend_session,
    "cyberark_resume_session": tool_cyberark_resume_session,
    "cyberark_terminate_session": tool_cyberark_terminate_session,
    # Recordings
    "cyberark_list_recordings": tool_cyberark_list_recordings,
    "cyberark_get_recording": tool_cyberark_get_recording,
    "cyberark_get_recording_activities": tool_cyberark_get_recording_activities,
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

PROMPTS = [
    {
        "name": "system_status",
        "description": "Show a full health status report for all CyberArk PAM components (PVWA, CPM, PSM, AIM, PTA) with connection counts, versions, and any issues.",
        "arguments": [],
    },
    {
        "name": "safe_list",
        "description": "List all CyberArk Safes accessible to the current user.",
        "arguments": [
            {"name": "search", "description": "Filter safes by name (optional).", "required": False},
        ],
    },
    {
        "name": "account_list",
        "description": "List CyberArk accounts/credentials with platform, safe, and username details.",
        "arguments": [
            {"name": "search", "description": "Free-text search filter (optional).", "required": False},
            {"name": "safe", "description": "Filter by Safe name (optional).", "required": False},
        ],
    },
    {
        "name": "user_list",
        "description": "List all Vault users with username, type, and enabled/suspended status.",
        "arguments": [
            {"name": "search", "description": "Filter by username or description (optional).", "required": False},
        ],
    },
    {
        "name": "group_list",
        "description": "List all Vault groups.",
        "arguments": [
            {"name": "search", "description": "Filter by group name (optional).", "required": False},
        ],
    },
    {
        "name": "session_list",
        "description": "List active PSM/PSMP privileged sessions showing user, target account, and start time.",
        "arguments": [],
    },
    {
        "name": "highlight_alerts",
        "description": "Analyze the CyberArk PAM environment and highlight any alerts, disconnected components, offline AIM providers, or other issues requiring attention.",
        "arguments": [],
    },
]

PROMPT_MESSAGES: dict[str, str] = {
    "system_status": (
        "Use cyberark_get_health_summary and cyberark_get_health_details for each component "
        "(PVWA, CPM, SessionManagement, AIM) in parallel. "
        "Present the results as a clear status table showing: component name, connected/total count, "
        "version, last logon, and overall status (OK / WARNING / ERROR). "
        "Highlight any component that is offline or has count < total."
    ),
    "safe_list": (
        "Use cyberark_list_safes{search_clause} to retrieve the Safe list. "
        "Display results in a table with columns: Safe Name, number of members (if available). "
        "Show total count at the end."
    ),
    "account_list": (
        "Use cyberark_list_accounts{search_clause}{safe_clause} to retrieve accounts. "
        "Display results in a table with columns: Account Name, Username, Platform, Safe. "
        "Show total count at the end."
    ),
    "user_list": (
        "Use cyberark_list_users{search_clause} to retrieve Vault users. "
        "Display results in a table with columns: Username, Type, Source, Status (Enabled/Disabled/Suspended). "
        "Show total count at the end."
    ),
    "group_list": (
        "Use cyberark_list_groups{search_clause} to retrieve Vault groups. "
        "Display results in a table with columns: Group Name, Type, Directory. "
        "Show total count at the end."
    ),
    "session_list": (
        "Use cyberark_list_live_sessions to retrieve active privileged sessions. "
        "Display results in a table with columns: Session ID, User, Target Account, Target Address, "
        "Protocol, Start Time, Duration. "
        "If no active sessions, state that clearly. Show total count."
    ),
    "highlight_alerts": (
        "Perform a full health check: call cyberark_get_health_summary and "
        "cyberark_get_health_details for PVWA, CPM, SessionManagement, and AIM. "
        "Then analyze the results and produce a prioritized alert summary: "
        "- CRITICAL: components where connected count = 0 "
        "- WARNING: components where connected < total, or version mismatch "
        "- INFO: components fully healthy "
        "Finish with a one-line overall health verdict."
    ),
}


def _build_prompt_messages(name: str, arguments: dict) -> list[dict]:
    template = PROMPT_MESSAGES.get(name, "")
    search = arguments.get("search", "")
    safe = arguments.get("safe", "")
    text = template.format(
        search_clause=f" with search='{search}'" if search else "",
        safe_clause=f" filtered to safe='{safe}'" if safe else "",
    )
    return [{"role": "user", "content": {"type": "text", "text": text}}]


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="CyberArk PVWA MCP Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def health_check():
    return {"status": "online", "message": "CyberArk PVWA MCP Server is running"}


# ---------------------------------------------------------------------------
# Discovery endpoints
# ---------------------------------------------------------------------------

@app.get("/.well-known/mcp.json")
async def mcp_discovery():
    if OAUTH_ENABLED:
        auth_meta = {
            "method": "OAuth2.1",
            "authorizationServer": OAUTH_ISSUER,
            "tokenEndpoint": f"{OAUTH_ISSUER}/oauth/token",
            "scopes": ["mcp:read", "mcp:write"],
        }
    else:
        auth_meta = {"method": "None"}
    return JSONResponse(content={
        "mcpVersion": "1.0.0",
        "authentication": auth_meta,
        "tools": [{"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]} for t in TOOLS],
    })


# OAuth / OpenID well-known endpoints (required by MCPGateway & mcp-remote)

@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
async def oauth_protected_resource():
    if OAUTH_ENABLED:
        return JSONResponse(content={
            "resource": OAUTH_ISSUER,
            "authorization_servers": [OAUTH_ISSUER],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp:read", "mcp:write"],
        })
    return JSONResponse(content={"protected": False})


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server():
    if USE_EXTERNAL_IDP:
        meta = await _get_idp_meta()
        return JSONResponse(content={
            "issuer": meta.get("issuer", IDP_ISSUER),
            # Point to our proxy so scope override works correctly
            "authorization_endpoint": f"{OAUTH_ISSUER}/oauth/authorize",
            "token_endpoint": f"{OAUTH_ISSUER}/oauth/token",
            "jwks_uri": meta.get("jwks_uri", ""),
            "registration_endpoint": f"{OAUTH_ISSUER}/oauth/register",
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": IDP_SCOPE.split(),
        })
    if OAUTH_ENABLED:
        return JSONResponse(content={
            "issuer": OAUTH_ISSUER,
            "authorization_endpoint": f"{OAUTH_ISSUER}/oauth/authorize",
            "token_endpoint": f"{OAUTH_ISSUER}/oauth/token",
            "registration_endpoint": f"{OAUTH_ISSUER}/oauth/register",
            "jwks_uri": f"{OAUTH_ISSUER}/.well-known/jwks.json",
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["mcp:read", "mcp:write"],
        })
    return JSONResponse(content={"issuer": "none", "authorization_endpoint": "none"})


@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    return JSONResponse(content=_jwks())


@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    if USE_EXTERNAL_IDP:
        meta = await _get_idp_meta()
        return JSONResponse(content={
            **meta,
            "authorization_endpoint": f"{OAUTH_ISSUER}/oauth/authorize",
            "token_endpoint": f"{OAUTH_ISSUER}/oauth/token",
            "registration_endpoint": f"{OAUTH_ISSUER}/oauth/register",
        })
    if OAUTH_ENABLED:
        return JSONResponse(content={
            "issuer": OAUTH_ISSUER,
            "authorization_endpoint": f"{OAUTH_ISSUER}/oauth/authorize",
            "token_endpoint": f"{OAUTH_ISSUER}/oauth/token",
            "registration_endpoint": f"{OAUTH_ISSUER}/oauth/register",
            "jwks_uri": f"{OAUTH_ISSUER}/.well-known/jwks.json",
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["mcp:read", "mcp:write"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })
    return JSONResponse(content={
        "issuer": "none",
        "authorization_endpoint": "none",
        "token_endpoint": "none",
        "jwks_uri": "none",
        "response_types_supported": [],
    })


@app.post("/oauth/register")
async def register_client(request: Request):
    """Dynamic Client Registration — RFC 7591."""
    body = await request.json()
    client_id = str(uuid.uuid4())
    client_secret = secrets.token_urlsafe(32)
    _registered_clients[client_id] = {
        "client_secret": client_secret,
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", ""),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "client_secret_basic"),
        "scope": body.get("scope", "mcp:read mcp:write"),
    }
    logger.info("Client registered: %s (%s)", client_id, body.get("client_name", ""))
    return JSONResponse(status_code=201, content={
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,
        "redirect_uris": _registered_clients[client_id]["redirect_uris"],
        "grant_types": _registered_clients[client_id]["grant_types"],
        "token_endpoint_auth_method": _registered_clients[client_id]["token_endpoint_auth_method"],
        "registration_client_uri": f"{OAUTH_ISSUER}/oauth/register/{client_id}",
        "registration_access_token": secrets.token_urlsafe(16),
    })


@app.get("/oauth/authorize")
async def authorize(request: Request):
    """Authorization endpoint — proxy to IdP or issue code internally."""
    params = dict(request.query_params)
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")

    if not client_id or not redirect_uri:
        return JSONResponse(status_code=400, content={"error": "invalid_request"})

    if USE_EXTERNAL_IDP:
        meta = await _get_idp_meta()
        idp_auth_url = meta.get("authorization_endpoint", "")
        fwd = {
            **params,
            "client_id": IDP_CLIENT_ID or client_id,
            "scope": IDP_SCOPE,  # override with IdP-supported scope
        }
        qs = urllib.parse.urlencode(fwd)
        return RedirectResponse(url=f"{idp_auth_url}?{qs}", status_code=302)

    # Internal: auto-grant authorization code
    is_static = (client_id == OAUTH_CLIENT_ID)
    is_registered = client_id in _registered_clients
    if not is_static and not is_registered:
        return JSONResponse(status_code=400, content={"error": "invalid_client"})

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id, "redirect_uri": redirect_uri,
        "code_challenge": params.get("code_challenge", ""),
        "code_challenge_method": params.get("code_challenge_method", "S256"),
        "scope": params.get("scope", "mcp:read mcp:write"),
        "exp": int(time.time()) + 300,
    }
    logger.info("Auth code issued for client: %s", client_id)
    sep = "&" if "?" in redirect_uri else "?"
    url = f"{redirect_uri}{sep}code={code}"
    if params.get("state"):
        url += f"&state={params['state']}"
    return RedirectResponse(url=url, status_code=302)


@app.post("/oauth/token")
async def token_endpoint(request: Request):
    body = await request.form()
    grant_type = body.get("grant_type", "")

    # ── External IdP: proxy token request ─────────────────────────────────
    if USE_EXTERNAL_IDP:
        if not grant_type:
            return JSONResponse(status_code=400,
                                content={"error": "invalid_request", "error_description": "grant_type is required"})

        meta = await _get_idp_meta()
        idp_token_url = meta.get("token_endpoint", "")

        # Handle refresh_token grant: look up cached IdP refresh token
        if grant_type == "refresh_token":
            our_token = body.get("refresh_token", "")
            if not our_token:
                return JSONResponse(status_code=400, content={
                    "error": "invalid_request",
                    "error_description": "refresh_token parameter is required",
                })
            session = _idp_sessions.get(our_token)
            if not session or session.get("exp", 0) < int(time.time()):
                _idp_sessions.pop(our_token, None)
                return JSONResponse(status_code=400, content={
                    "error": "invalid_grant",
                    "error_description": "Refresh token is invalid or expired. Please re-authenticate.",
                })
            refresh_form: dict[str, str] = {
                "grant_type": "refresh_token",
                "refresh_token": session["idp_refresh_token"],
                "client_id": IDP_CLIENT_ID,
            }
            if IDP_CLIENT_SECRET:
                refresh_form["client_secret"] = IDP_CLIENT_SECRET
            logger.info("Proxy refresh_token to IdP for client: %s", session.get("client_id"))
            async with httpx.AsyncClient() as c:
                r = await c.post(idp_token_url, data=refresh_form,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp_data = r.json() if r.content else {}
            if r.status_code == 200:
                # Rotate IdP refresh token if returned, keep our opaque token stable
                if resp_data.get("refresh_token"):
                    session["idp_refresh_token"] = resp_data["refresh_token"]
                resp_data["refresh_token"] = our_token
                _idp_sessions[our_token] = session
            else:
                _idp_sessions.pop(our_token, None)
            logger.info("IdP refresh response: %s %s", r.status_code, resp_data.get("error", "ok"))
            return JSONResponse(status_code=r.status_code, content=resp_data)

        # Build clean form_data — send only what the IdP requires
        form_data: dict[str, str] = {
            "grant_type": grant_type,
            "client_id": IDP_CLIENT_ID,
        }
        if IDP_CLIENT_SECRET:
            form_data["client_secret"] = IDP_CLIENT_SECRET

        if grant_type == "authorization_code":
            # Do not send scope here — IdP uses the scope from the authorization request
            form_data["code"] = body.get("code", "")
            form_data["redirect_uri"] = body.get("redirect_uri", "")
            if body.get("code_verifier"):
                form_data["code_verifier"] = body.get("code_verifier")
        elif grant_type == "client_credentials":
            form_data["scope"] = IDP_SCOPE
        else:
            return JSONResponse(status_code=400, content={
                "error": "unsupported_grant_type",
                "error_description": f"grant_type '{grant_type}' is not supported",
            })

        logger.info("Proxy token to IdP: %s (grant_type=%s)", idp_token_url, grant_type)
        async with httpx.AsyncClient() as c:
            r = await c.post(idp_token_url, data=form_data,
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp_data = r.json() if r.content else {}

        # Cache IdP refresh_token and issue our own opaque one
        if r.status_code == 200 and resp_data.get("refresh_token"):
            idp_refresh = resp_data["refresh_token"]
            our_refresh = secrets.token_urlsafe(32)
            _idp_sessions[our_refresh] = {
                "idp_refresh_token": idp_refresh,
                "client_id": body.get("client_id", IDP_CLIENT_ID),
                "scope": resp_data.get("scope", IDP_SCOPE),
                "exp": int(time.time()) + 86400 * 30,
            }
            resp_data["refresh_token"] = our_refresh
            logger.info("IdP refresh_token cached, opaque token issued")

        logger.info("IdP token response: %s %s", r.status_code, resp_data.get("error", "ok"))
        return JSONResponse(status_code=r.status_code, content=resp_data)


    # Extract client credentials (Basic auth or form params)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        decoded = base64.b64decode(auth_header[6:] + "==").decode(errors="replace")
        client_id, _, client_secret = decoded.partition(":")
    else:
        client_id = body.get("client_id", "")
        client_secret = body.get("client_secret", "")

    # ── Authorization Code + PKCE ──────────────────────────────────────────
    if grant_type == "authorization_code":
        code = body.get("code", "")
        code_verifier = body.get("code_verifier", "")
        redirect_uri = body.get("redirect_uri", "")

        code_data = _auth_codes.pop(code, None)
        if not code_data or code_data["exp"] < int(time.time()):
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})

        if code_data["client_id"] != client_id:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})

        if code_data["redirect_uri"] != redirect_uri:
            return JSONResponse(status_code=400, content={"error": "invalid_grant", "message": "redirect_uri mismatch"})

        # PKCE verification (S256)
        if code_data.get("code_challenge"):
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()
            if challenge != code_data["code_challenge"]:
                return JSONResponse(status_code=400, content={"error": "invalid_grant", "message": "PKCE verification failed"})

        scope = code_data.get("scope", "mcp:read mcp:write")
        token = _issue_token(client_id, scope)
        logger.info("Token issued (authorization_code) for client: %s", client_id)
        return JSONResponse(content={
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": OAUTH_TOKEN_EXPIRY,
            "scope": scope,
        })

    # ── Client Credentials ─────────────────────────────────────────────────
    if grant_type == "client_credentials":
        is_static = (client_id == OAUTH_CLIENT_ID and client_secret == OAUTH_CLIENT_SECRET)
        registered = _registered_clients.get(client_id)
        is_registered = registered and registered["client_secret"] == client_secret

        if not is_static and not is_registered:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})

        scope = body.get("scope", "mcp:read mcp:write")
        token = _issue_token(client_id, scope)
        logger.info("Token issued (client_credentials) for client: %s", client_id)
        return JSONResponse(content={
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": OAUTH_TOKEN_EXPIRY,
            "scope": scope,
        })

    return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})


@app.get("/mcp")
async def mcp_sse_channel(request: Request):
    """SSE channel for server-to-client messages (required by mcp-remote / streamable-http spec)."""
    async def event_stream():
        while True:
            if await request.is_disconnected():
                break
            yield ": heartbeat\n\n"
            await asyncio.sleep(15)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.post("/mcp")
async def mcp_endpoint(payload: dict, request: Request):
    authorization = request.headers.get("Authorization", "")
    if not await _auth_ok(authorization):
        return JSONResponse(
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="{IDP_ISSUER or OAUTH_ISSUER}"'},
            content={"error": "Unauthorized", "message": "Valid Bearer token required"},
        )

    # Make the caller's Bearer token available to PVWAClient for SAML logon
    if authorization.startswith("Bearer "):
        _bearer_ctx.set(authorization[7:])

    method = payload.get("method")
    req_id = payload.get("id", 1)

    if method == "initialize":
        session_id = str(uuid.uuid4())
        _mcp_sessions[session_id] = {"created": int(time.time()), "bearer": authorization[7:] if authorization.startswith("Bearer ") else ""}
        return JSONResponse(
            headers={"Mcp-Session-Id": session_id},
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": payload.get("params", {}).get("protocolVersion", "2024-11-05"),
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "prompts": {"listChanged": False},
                        "resources": {"listChanged": False},
                    },
                    "serverInfo": {"name": "cyberark-pvwa", "version": "2.0.0"},
                },
            },
        )

    session_id = request.headers.get("Mcp-Session-Id") or request.headers.get("mcp-session-id")
    if session_id and session_id not in _mcp_sessions:
        return JSONResponse(status_code=404, content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001, "message": "Session not found"}})

    if method in ("tools/list", "list_tools"):
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

    if method == "resources/list":
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}})

    if method == "resources/templates/list":
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": []}})

    if method == "prompts/list":
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"prompts": PROMPTS}})

    if method == "prompts/get":
        params = payload.get("params", {})
        prompt_name = params.get("name")
        arguments = params.get("arguments") or {}
        prompt = next((p for p in PROMPTS if p["name"] == prompt_name), None)
        if not prompt:
            return JSONResponse(content={
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32602, "message": f"Prompt '{prompt_name}' not found"},
            })
        return JSONResponse(content={
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "description": prompt["description"],
                "messages": _build_prompt_messages(prompt_name, arguments),
            },
        })

    if method == "tools/call":
        params = payload.get("params", {})
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return JSONResponse(content={
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
            })

        try:
            result = await handler(tool_args)
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": result})
        except Exception as e:
            logger.exception("Tool %s failed", tool_name)
            return JSONResponse(content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True},
            })

    return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {}})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not PVWA_URL:
        logger.error("Missing required environment variable: CYBERARK_PVWA_URL")
        raise SystemExit(1)
    if not USERNAME or not PASSWORD:
        logger.warning(
            "CYBERARK_USERNAME / CYBERARK_PASSWORD not set — "
            "credentials will be requested at runtime via the cyberark_logon tool."
        )
    uvicorn.run(app, host="0.0.0.0", port=8000)
