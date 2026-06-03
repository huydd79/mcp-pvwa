# CyberArk PVWA MCP Server

A **Model Context Protocol (MCP) Server** that exposes CyberArk Self-Hosted PAM REST API as AI-callable tools. Allows AI assistants (Claude, Cline, etc.) to manage privileged accounts, safes, and monitor system health directly via natural language.

## Features

- **15 MCP tools** covering Authentication, System Health, Accounts, and Safes
- **Plain JSON transport** — compatible with Cline, MCP Inspector, and any standard MCP client
- **Auto session management** — lazy logon, automatic token refresh on 401
- **Docker-ready** — single `docker compose up` to run
- **SSL-skip option** for lab environments

## Tools

| Group | Tool | Description |
|---|---|---|
| Auth | `cyberark_logon` | Manually re-authenticate to PVWA |
| Auth | `cyberark_logoff` | Terminate the current session |
| Health | `cyberark_get_health_summary` | Health status of all PAM components |
| Health | `cyberark_get_health_details` | Detailed metrics for a specific component |
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

## Prerequisites

- Docker & Docker Compose
- Access to a CyberArk Self-Hosted PAM (PVWA) instance

## Quick Start

**1. Clone and configure:**

```bash
git clone https://github.com/<your-username>/mcp-pvwa.git
cd mcp-pvwa
cp .env.example .env
```

Edit `.env` with your PVWA credentials:

```env
CYBERARK_PVWA_URL=https://your.pvwa.com
CYBERARK_AUTH_TYPE=CyberArk
CYBERARK_USERNAME=Administrator
CYBERARK_PASSWORD=your_password
CYBERARK_VERIFY_SSL=false   # set true in production
```

**2. Run connectivity test:**

```bash
docker compose run --rm test
```

**3. Start the MCP server:**

```bash
docker compose up mcp-server -d
```

MCP endpoint: `http://localhost:8000/mcp`

## MCP Client Configuration

### Cline (VS Code)

Add to `cline_mcp_settings.json`:

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

### Claude Desktop

Add to `claude_desktop_config.json`:

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

> Note: Claude Desktop requires `mcp-remote` as a bridge since it does not natively support HTTP MCP servers.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `CYBERARK_PVWA_URL` | Yes | — | PVWA base URL (e.g. `https://my.pvwa.com`) |
| `CYBERARK_AUTH_TYPE` | No | `CyberArk` | Auth type: `CyberArk`, `LDAP`, `Windows`, `RADIUS` |
| `CYBERARK_USERNAME` | Yes | — | PVWA login username |
| `CYBERARK_PASSWORD` | Yes | — | PVWA login password |
| `CYBERARK_VERIFY_SSL` | No | `true` | Set `false` to skip SSL verification (lab only) |

## Development

**Bruno API Collection**

The CyberArk REST API reference collection is not bundled. Clone it separately:

```bash
git clone https://github.com/IAM-Jah/CyberArk-REST-API-Bruno.git
```

**Project Structure**

```
mcp-pvwa/
├── main.py              # MCP server (FastAPI)
├── test_connection.py   # Standalone PVWA connectivity test
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## License

MIT
