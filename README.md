# CyberArk PVWA MCP Server

A **Model Context Protocol (MCP) Server** that exposes the CyberArk Self-Hosted PAM REST API as AI-callable tools. Allows AI assistants (Claude, Cline, MCPGateway, etc.) to manage privileged accounts, safes, and system health via natural language.

## Features

- **15 MCP tools** — Authentication, System Health, Accounts, Safe management
- **SAML SSO into PVWA** — uses the caller's active IdP session (no separate PVWA credentials needed)
- **OAuth 2.1 protection** — MCP endpoint secured via CyberArk Identity, Okta, or Azure AD
- **Credential fallback** — direct PVWA login if SAML is unavailable; credentials can also be supplied at runtime
- **Auto session management** — lazy logon, automatic token refresh on 401
- **Docker-ready** — `docker compose up` and it runs

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  MCP Client (Claude Desktop / Cline / MCPGateway)        │
│                                                          │
│  1. Authenticate via OAuth 2.1 → CyberArk Identity       │
│  2. Call MCP tools with Bearer token                      │
└───────────────────────┬──────────────────────────────────┘
                        │  Bearer token (OIDC JWT)
                        ▼
┌──────────────────────────────────────────────────────────┐
│  CyberArk PVWA MCP Server  (this project)                │
│                                                          │
│  POST /mcp  ──► validate token via IdP JWKS              │
│                                                          │
│  On first tool call:                                     │
│    3. GET IdP SAML SSO URL (Bearer token as auth)        │
│    4. Parse SAMLResponse from IdP HTML response          │
│    5. POST SAMLResponse → PVWA /auth/SAML/Logon          │
│    6. Store PVWA session token                           │
└───────────────────────┬──────────────────────────────────┘
                        │  PVWA Session Token
                        ▼
┌──────────────────────────────────────────────────────────┐
│  CyberArk PVWA REST API  (Self-Hosted PAM)               │
└──────────────────────────────────────────────────────────┘
```

**Key benefit:** The user authenticates **once** via CyberArk Identity. The MCP server reuses that session to log into PVWA via SAML — no separate PVWA credentials stored or prompted.

---

## Tools

| Group | Tool | Description |
|---|---|---|
| Auth | `cyberark_logon` | Authenticate to PVWA (SAML, env vars, or explicit credentials) |
| Auth | `cyberark_logoff` | Terminate the current PVWA session |
| Health | `cyberark_get_health_summary` | Health status of all PAM components |
| Health | `cyberark_get_health_details` | Detailed metrics for PVWA / CPM / PSM / AIM |
| Accounts | `cyberark_list_accounts` | List accounts with search/filter/pagination |
| Accounts | `cyberark_get_account` | Get full details of an account by ID |
| Accounts | `cyberark_add_account` | Add a new privileged account |
| Accounts | `cyberark_update_account` | Update account properties (JSON Patch) |
| Accounts | `cyberark_delete_account` | Permanently delete an account |
| Safes | `cyberark_list_safes` | List accessible Safes |
| Safes | `cyberark_get_safe` | Get Safe details by name or ID |
| Safes | `cyberark_add_safe` | Create a new Safe |
| Safes | `cyberark_delete_safe` | Permanently delete a Safe |
| Safes | `cyberark_list_safe_members` | List members and their permissions |
| Safes | `cyberark_add_safe_member` | Add a user/group to a Safe with permissions |

---

## Setup Options

### Option A — Simple (direct credentials, no SSO)

Suitable for lab environments or quick testing.

**1. Configure `.env`:**

```env
CYBERARK_PVWA_URL=https://your.pvwa.com
CYBERARK_AUTH_TYPE=CyberArk        # or LDAP, Windows, RADIUS
CYBERARK_USERNAME=Administrator
CYBERARK_PASSWORD=your_password
CYBERARK_VERIFY_SSL=false          # set true in production
```

**2. Start:**

```bash
docker compose up mcp-server -d
```

MCP endpoint (no auth): `http://localhost:8000/mcp`

---

### Option B — Full SSO (CyberArk Identity + SAML)

Users authenticate once via CyberArk Identity. The server handles PVWA login automatically via SAML. Requires two apps to be configured in CyberArk Identity (see [CyberArk Identity Setup](#cyberark-identity-setup) below).

**`.env` for SSO mode:**

```env
# PVWA — use FQDN, not IP (must match SAML ACS URL)
CYBERARK_PVWA_URL=https://pvwa.your-domain.com
CYBERARK_VERIFY_SSL=false

# PVWA SAML authentication
PVWA_SAML_ENABLED=true
PVWA_SAML_SSO_URL=https://<tenant>.my.idaptive.app/applogin/appKey/<app-key>/customerId/<customer-id>

# MCP OAuth 2.1 — protect the /mcp endpoint
OAUTH_ENABLED=true
OAUTH_ISSUER=https://mcp.your-domain.com   # public URL of this MCP server

# CyberArk Identity as external IdP
IDP_ISSUER=https://<tenant>.my.idaptive.app/<tenant-id>/
IDP_CLIENT_ID=<oauth-app-client-id>
IDP_CLIENT_SECRET=<oauth-app-client-secret>
IDP_SCOPE=openid profile email
```

**Start:**

```bash
docker compose up mcp-server -d
```

---

## CyberArk Identity Setup

Two applications need to be configured in CyberArk Identity Admin Portal.

### App 1 — OAuth 2.0 / OIDC (for MCP authentication)

This app allows MCP clients to authenticate users via OAuth and receive a JWT that the MCP server validates.

1. Go to **Apps & Widgets → Add Web App → Custom → OAuth2 Client**
2. Configure:
   - **App Name:** `MCP Server` (or similar)
   - **Client ID:** copy this value → `IDP_CLIENT_ID`
   - **Client Secret:** generate → `IDP_CLIENT_SECRET`
   - **Grant Types:** `Authorization Code`, `Client Credentials`
   - **Token Type:** `JWT`
   - **Auth methods:** `Client Secret Post`, `Client Secret Basic`
3. Under **Redirect URIs**, add:
   ```
   http://localhost:8080/oauth/callback
   ```
   *(used by MCP Inspector / mcp-remote for local testing)*
4. Under **Scope**, add: `openid`, `profile`, `email`
5. Under **User Access**, assign the users/groups that can use this MCP server
6. Save. Note the **Issuer URL** from the app settings → `IDP_ISSUER`

### App 2 — SAML (for PVWA authentication)

This app is how the MCP server authenticates to PVWA on behalf of the user.

1. Go to **Apps & Widgets → Add Web App → Custom → SAML**
2. Configure the **Service Provider (SP) settings** — these come from PVWA:
   - **SP Entity ID / Audience:** get from PVWA (`Administration → SAML Authentication → SP Metadata`)
   - **ACS URL (Assertion Consumer Service):**
     ```
     https://pvwa.your-domain.com/PasswordVault/api/auth/saml/logon
     ```
     > **Important:** This must be the PVWA REST API endpoint, not the web UI URL.
     > PVWA URL must use FQDN — the `Destination` attribute in the SAML assertion must match `CYBERARK_PVWA_URL`.
3. Under **Attributes**, add:
   - `Email Address` → user's email (PVWA uses this to map to a Vault user)
4. Save and download the **IdP Metadata XML**
5. From the metadata XML, note:
   - `entityID` → the UUID is your `PVWA_SAML_APP_KEY`
   - `SingleSignOnService Location` → your `PVWA_SAML_SSO_URL`

   ```xml
   <EntityDescriptor entityID="https://<tenant>.my.idaptive.app/<uuid>">
     ...
     <SingleSignOnService Binding="...HTTP-POST"
       Location="https://<tenant>.my.idaptive.app/applogin/appKey/<uuid>/customerId/<cid>" />
   ```
6. Under **User Access**, assign the same users/groups as App 1

### PVWA SAML Configuration

1. In PVWA, go to **Administration → Authentication Methods → SAML**
2. Click **Configure**
3. Upload the IdP Metadata XML downloaded from CyberArk Identity (App 2)
4. Set **NameID format** to match what CyberArk Identity sends (typically `Email Address`)
5. Ensure **LDAP/Directory mapping** is configured so the email in the SAML assertion maps to a Vault user
6. Save and test via web browser first before enabling for API use

---

## Quick Start

```bash
git clone https://github.com/huydd79/mcp-pvwa.git
cd mcp-pvwa
cp .env.example .env
# Edit .env with your settings
docker compose up mcp-server -d
```

**Test connectivity:**

```bash
docker compose run --rm test
```

**Health check:**

```bash
curl http://localhost:8000/
```

---

## MCP Client Configuration

### Cline (VS Code) — no auth

```json
{
  "mcpServers": {
    "cyberark-pvwa": {
      "type": "streamableHttp",
      "url": "http://localhost:8000/mcp",
      "timeout": 60
    }
  }
}
```

### Cline (VS Code) — with OAuth (SSO mode)

```json
{
  "mcpServers": {
    "cyberark-pvwa": {
      "type": "streamableHttp",
      "url": "https://mcp.your-domain.com/mcp",
      "timeout": 60
    }
  }
}
```

Cline will automatically initiate the OAuth flow on first use.

### Claude Desktop — via mcp-remote

```json
{
  "mcpServers": {
    "cyberark-pvwa": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8000/mcp"]
    }
  }
}
```

### MCP Inspector (for testing OAuth flow)

Open MCP Inspector → set server URL → click **Connect**. Inspector will open a browser window for the OAuth/SAML login flow.

---

## Environment Variables

### PVWA Connection

| Variable | Required | Default | Description |
|---|---|---|---|
| `CYBERARK_PVWA_URL` | **Yes** | — | PVWA base URL. Must be FQDN when using SAML. |
| `CYBERARK_VERIFY_SSL` | No | `true` | Set `false` to skip SSL verification (lab only) |
| `CYBERARK_AUTH_TYPE` | No | `CyberArk` | Direct login method: `CyberArk`, `LDAP`, `Windows`, `RADIUS` |
| `CYBERARK_USERNAME` | No | — | PVWA username for direct login. Prompted at runtime if absent. |
| `CYBERARK_PASSWORD` | No | — | PVWA password for direct login. Prompted at runtime if absent. |

### PVWA SAML Authentication

| Variable | Required | Default | Description |
|---|---|---|---|
| `PVWA_SAML_ENABLED` | No | `false` | Enable SAML-first PVWA authentication |
| `PVWA_SAML_SSO_URL` | No* | — | Full IdP SSO URL from SAML metadata. When set, `PVWA_SAML_APP_KEY` is not needed. |
| `PVWA_SAML_APP_KEY` | No* | — | IdP SAML app key/UUID. Used to auto-generate SSO URL candidates when `PVWA_SAML_SSO_URL` is not set. |

*At least one of `PVWA_SAML_SSO_URL` or `PVWA_SAML_APP_KEY` is needed when `PVWA_SAML_ENABLED=true`.

### MCP OAuth 2.1

| Variable | Required | Default | Description |
|---|---|---|---|
| `OAUTH_ENABLED` | No | `false` | Enforce Bearer token on `/mcp` |
| `OAUTH_ISSUER` | No | `http://localhost:8000` | Public URL of this MCP server |
| `OAUTH_CLIENT_ID` | No | `mcp-client` | Static client ID (internal OAuth only) |
| `OAUTH_CLIENT_SECRET` | No | — | Static client secret (internal OAuth only) |
| `OAUTH_TOKEN_EXPIRY` | No | `3600` | Token TTL in seconds |
| `OAUTH_PRIVATE_KEY_PEM` | No | — | RSA private key PEM. Auto-generated if absent. |

### External IdP (CyberArk Identity / Okta / Azure AD)

| Variable | Required | Default | Description |
|---|---|---|---|
| `IDP_ISSUER` | No | — | IdP issuer URL. When set, overrides internal OAuth. |
| `IDP_DISCOVERY_URL` | No | — | Override OIDC discovery URL (if non-standard) |
| `IDP_CLIENT_ID` | No | — | OAuth app Client ID at the IdP |
| `IDP_CLIENT_SECRET` | No | — | OAuth app Client Secret at the IdP |
| `IDP_SCOPE` | No | `openid profile` | Scopes requested at IdP |
| `IDP_AUDIENCE` | No | — | Expected JWT audience claim |

---

## PVWA Authentication Flow (SAML mode)

```
1. MCP client authenticates with CyberArk Identity (OAuth 2.1)
   → receives JWT access token

2. MCP client calls POST /mcp with Authorization: Bearer <token>
   → server validates token via IdP JWKS

3. On first PVWA API call, server initiates SAML login:
   a. GET <PVWA_SAML_SSO_URL> with Authorization: Bearer <token>
   b. CyberArk Identity validates the token, issues SAMLResponse
   c. Server parses SAMLResponse from HTML auto-submit form
   d. POST SAMLResponse to https://<pvwa>/PasswordVault/API/auth/SAML/Logon
   e. PVWA validates SAMLResponse, returns session token

4. Subsequent calls reuse the PVWA session token
   → auto-refresh on 401

5. On logout: POST /PasswordVault/API/auth/SAML/Logoff
```

**Authentication priority** (server tries each in order, stops on first success):

| Priority | Method | Condition |
|---|---|---|
| 1 | SAML via IdP Bearer token | `PVWA_SAML_ENABLED=true` + `IDP_ISSUER` set + Bearer token present |
| 2 | Direct login via env vars | `CYBERARK_USERNAME` + `CYBERARK_PASSWORD` set |
| 3 | Direct login via tool params | `cyberark_logon(username=..., password=..., auth_type=...)` |

---

## Troubleshooting

### SAML 400 `PASWS035E` — Authentication failure

The `Destination` attribute in the SAMLResponse does not match PVWA's expected ACS URL.

**Fix:** Ensure `CYBERARK_PVWA_URL` uses the same FQDN as configured in the SAML app's ACS URL in CyberArk Identity. Do **not** use an IP address.

### SAML 400 — Other errors

Check `PVWA_SAML_SSO_URL` matches the `SingleSignOnService Location` in the IdP metadata XML. Download the metadata from CyberArk Identity (App 2 settings) to verify.

### 401 on `/mcp`

Verify `IDP_ISSUER`, `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET` in `.env`. Ensure the OAuth app in CyberArk Identity has the correct redirect URI and the user has access.

### `PermissionError: No PVWA credentials available`

No SAML session and no credentials configured. Either:
- Enable SAML (`PVWA_SAML_ENABLED=true` with valid `PVWA_SAML_SSO_URL`)
- Or set `CYBERARK_USERNAME` / `CYBERARK_PASSWORD`
- Or call `cyberark_logon(username=..., password=..., auth_type=...)` from the MCP client

### Docker container cannot reach PVWA

On macOS with Docker Desktop, verify the container can reach the PVWA host:

```bash
docker exec mcp-pvwa-mcp-server-1 ping -c 2 pvwa.your-domain.com
```

If unreachable, check DNS resolution and network routing from the Docker VM.

---

## Project Structure

```
mcp-pvwa/
├── main.py              # MCP server (FastAPI + manual MCP JSON-RPC)
├── test_connection.py   # Standalone PVWA connectivity test
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## License

MIT
