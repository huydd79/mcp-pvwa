"""
CyberArk PVWA MCP Server

Manages privileged accounts via CyberArk Self-Hosted PAM REST API.
Configuration via environment variables:
  CYBERARK_PVWA_URL       - Base URL, e.g. https://my.pvwa.com
  CYBERARK_AUTH_TYPE      - CyberArk | Windows | LDAP | RADIUS
  CYBERARK_USERNAME       - PVWA username
  CYBERARK_PASSWORD       - PVWA password
  CYBERARK_VERIFY_SSL     - true (default) | false (for lab environments)

  OAUTH_ENABLED           - true | false (default false)
  OAUTH_ISSUER            - Public base URL, e.g. https://testmcp.home.huydo.net
  OAUTH_CLIENT_ID         - OAuth client ID
  OAUTH_CLIENT_SECRET     - OAuth client secret
  OAUTH_TOKEN_EXPIRY      - Token TTL in seconds (default 3600)
  OAUTH_PRIVATE_KEY_PEM   - RSA private key in PEM format (auto-generated if absent)
"""

import os
import json
import base64
import uuid
import time
import logging
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
from fastapi.responses import JSONResponse, StreamingResponse

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

BASE_API = f"{PVWA_URL}/PasswordVault/API"

# ---------------------------------------------------------------------------
# OAuth 2.1 Configuration
# ---------------------------------------------------------------------------

OAUTH_ENABLED = os.environ.get("OAUTH_ENABLED", "false").lower() == "true"
OAUTH_ISSUER = os.environ.get("OAUTH_ISSUER", "http://localhost:8000").rstrip("/")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "mcp-client")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
OAUTH_TOKEN_EXPIRY = int(os.environ.get("OAUTH_TOKEN_EXPIRY", "3600"))

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

class PVWAClient:
    """Async HTTP client for CyberArk PVWA with automatic token lifecycle."""

    def __init__(self) -> None:
        self._token: Optional[str] = None
        self._client = httpx.AsyncClient(verify=VERIFY_SSL)

    async def _logon(self) -> None:
        url = f"{BASE_API}/auth/{AUTH_TYPE}/Logon"
        payload = {"username": USERNAME, "password": PASSWORD, "concurrentSession": True}
        resp = await self._client.post(url, json=payload)
        resp.raise_for_status()
        self._token = resp.json()
        logger.info("PVWA session established.")

    async def _logoff(self) -> None:
        if not self._token:
            return
        await self._client.post(f"{BASE_API}/Auth/Logoff/", headers=self._auth_headers())
        self._token = None
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
        "description": "Authenticate to CyberArk PVWA and obtain a session token. Uses credentials from server environment variables. Call this only to manually re-establish a session.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cyberark_logoff",
        "description": "Terminate the current CyberArk PVWA session and invalidate the token.",
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
]

# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

async def tool_cyberark_logon(args: dict) -> dict:
    await client._logon()
    return _text("Successfully authenticated to PVWA.")


async def tool_cyberark_logoff(args: dict) -> dict:
    await client._logoff()
    return _text("PVWA session terminated.")


async def tool_cyberark_get_health_summary(args: dict) -> dict:
    return _text(await client.request("GET", "/ComponentsMonitoringSummary/"))


async def tool_cyberark_get_health_details(args: dict) -> dict:
    return _text(await client.request("GET", f"/ComponentsMonitoringDetails/{args['component_id']}"))


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


TOOL_HANDLERS: dict[str, Any] = {
    "cyberark_logon": tool_cyberark_logon,
    "cyberark_logoff": tool_cyberark_logoff,
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
}

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
    if OAUTH_ENABLED:
        return JSONResponse(content={
            "issuer": OAUTH_ISSUER,
            "authorization_endpoint": f"{OAUTH_ISSUER}/oauth/authorize",
            "token_endpoint": f"{OAUTH_ISSUER}/oauth/token",
            "jwks_uri": f"{OAUTH_ISSUER}/.well-known/jwks.json",
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "scopes_supported": ["mcp:read", "mcp:write"],
            "response_types_supported": ["token"],
            "code_challenge_methods_supported": ["S256"],
        })
    return JSONResponse(content={"issuer": "none", "authorization_endpoint": "none"})


@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    return JSONResponse(content=_jwks())


@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    if OAUTH_ENABLED:
        return JSONResponse(content={
            "issuer": OAUTH_ISSUER,
            "authorization_endpoint": f"{OAUTH_ISSUER}/oauth/authorize",
            "token_endpoint": f"{OAUTH_ISSUER}/oauth/token",
            "jwks_uri": f"{OAUTH_ISSUER}/.well-known/jwks.json",
            "grant_types_supported": ["client_credentials"],
            "response_types_supported": ["token"],
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


@app.post("/oauth/token")
async def token_endpoint(request: Request):
    body = await request.form()
    grant_type = body.get("grant_type", "")

    if grant_type != "client_credentials":
        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})

    # Support Basic auth or form params
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        decoded = base64.b64decode(auth_header[6:] + "==").decode(errors="replace")
        client_id, _, client_secret = decoded.partition(":")
    else:
        client_id = body.get("client_id", "")
        client_secret = body.get("client_secret", "")

    if client_id != OAUTH_CLIENT_ID or client_secret != OAUTH_CLIENT_SECRET:
        return JSONResponse(status_code=401, content={"error": "invalid_client"})

    scope = body.get("scope", "mcp:read mcp:write")
    token = _issue_token(client_id, scope)
    logger.info("Token issued for client: %s", client_id)
    return JSONResponse(content={
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": OAUTH_TOKEN_EXPIRY,
        "scope": scope,
    })


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
    if not _validate_token(request.headers.get("Authorization", "")):
        return JSONResponse(
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="{OAUTH_ISSUER}"'},
            content={"error": "Unauthorized", "message": "Valid Bearer token required"},
        )

    method = payload.get("method")
    req_id = payload.get("id", 1)

    if method == "initialize":
        return JSONResponse(content={
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
        })

    if method in ("tools/list", "list_tools"):
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

    if method == "resources/list":
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}})

    if method == "resources/templates/list":
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": []}})

    if method == "prompts/list":
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}})

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
    if not PVWA_URL or not USERNAME or not PASSWORD:
        logger.error(
            "Missing required environment variables: "
            "CYBERARK_PVWA_URL, CYBERARK_USERNAME, CYBERARK_PASSWORD"
        )
        raise SystemExit(1)
    uvicorn.run(app, host="0.0.0.0", port=8000)
