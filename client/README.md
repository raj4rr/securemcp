# SecureMCP Python Client & Security Chatbot

This client application provides a **Python 3 / FastAPI** client with an interactive **Chatbot Web UI** and a **CLI terminal chatbot** connected directly to the SecureMCP Server.

---

## Features

- **OAuth 2.0 Client Credentials Authentication**: Retrieves, caches, and automatically refreshes bearer tokens against `http://localhost:8080/oauth2/token`.
- **Streamable HTTP MCP Protocol (`2024-11-05`)**: Connects to the SecureMCP server via `/mcp` with SSE streaming and session management (`mcp-session-id`).
- **Interactive Security Chatbot**:
  - Validates and decodes JWT tokens cryptographically.
  - Queries recent security audit logs.
  - Checks principal permissions and inspects caller OAuth claims.
  - Performs Keycloak OpenID Connect discovery.
  - Calls any registered MCP tool dynamically via natural language or direct syntax.
- **Dual Interface**:
  - **Modern Web UI**: Served on `http://localhost:3000` with real-time status and quick action buttons.
  - **Terminal CLI**: Interactive console chatbot for scripting and command-line use.

---

## Directory Structure

```text
client/
├── app.py              # FastAPI application serving Web UI and /api/chat endpoints
├── chatbot.py          # Security intent parsing & tool invocation logic
├── mcp_client.py       # Low-level OAuth2 & Model Context Protocol (MCP) client SDK
├── cli_chatbot.py      # Terminal-based interactive chatbot script
└── templates/
    └── index.html      # Responsive Dark-Mode Chatbot UI with Markdown and JSON rendering
```

---

## Prerequisites

- Python 3.10+
- Dependencies: `fastapi`, `uvicorn`, `httpx`, `requests`
- Running SecureMCP server at `http://localhost:8080`

Install required packages:
```bash
pip install fastapi uvicorn httpx requests
```

---

## Quick Start

### 1. Ensure SecureMCP Server is Running
```bash
# In the root repository directory
mvn spring-boot:run -Dspring-boot.run.arguments="--REDIS_PASSWORD=securemcp --SECUREMCP_BOOTSTRAP_CLIENT_SECRET=securemcp"
```

### 2. Run the Web Chatbot UI
```bash
python3 -m uvicorn app:app --app-dir client --host 127.0.0.1 --port 3000 --reload
```
Open your browser at:
👉 **[http://localhost:3000](http://localhost:3000)**

### 3. Run the CLI Terminal Chatbot
```bash
python3 client/cli_chatbot.py
```

---

## Example Chatbot Queries

- `"Validate current JWT"` (Cryptographically verifies signature & expiration against server JWKS)
- `"Show recent audit logs"` (Fetches append-only audit events)
- `"Check permission security.read"` (Verifies principal permissions)
- `"Introspect my token"` (Inspects caller claims, tenant, and scopes)
- `"Discover Keycloak OIDC"` (Retrieves OIDC discovery metadata)
- `"List tools"` (Lists all 11 registered MCP tools)
- Direct tool execution: `call <toolName> {"key": "val"}`
