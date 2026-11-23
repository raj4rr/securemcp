# SecureMCP Client — Spring Boot & Spring AI

This is a standalone **Java 21, Spring Boot 3.5.7, and Spring AI 1.1.2** client application and security chatbot designed to connect to the SecureMCP Server.

---

## Features

- **Spring AI MCP Client Integration**: Uses Spring AI Model Context Protocol starter (`spring-ai-starter-mcp-client`) with Streamable HTTP transport (`2024-11-05` protocol version).
- **OAuth 2.0 Client Authentication**: Acquires, caches, and auto-refreshes bearer tokens against the SecureMCP OAuth2 Authorization Server (`/oauth2/token`).
- **MCP Session Management**: Maintains the `mcp-session-id`, auto-reconnects on session expiry, and lists/invokes all 11 registered MCP security and identity tools.
- **Embedded Security AI Chatbot**:
  - Cryptographic validation of JWT tokens (`jwtValidate`) against server JWKS.
  - Token claims inspection and untrusted decode (`jwtDecode`).
  - Principal permission checks (`checkPermission`).
  - Token introspection (`oauthIntrospect`).
  - Security audit events retrieval (`recentSecurityEvents`).
  - Keycloak OpenID Connect discovery (`oidcDiscover`).
  - Dynamic tool invocation syntax (`call <toolName> {"key": "value"}`).
- **Interactive Thymeleaf Web UI**:
  - Served at `http://localhost:8081`.
  - Dark-mode developer console with real-time server connectivity status.
  - Active tool pill explorer and one-click quick actions.

---

## Architecture

```text
Browser / API Caller (Port 8081)
          |
   [ChatController]
          |
   [ChatbotService]  <-- (Intent Parsing & Formatting)
          |
 [SecureMcpConnector] (Spring AI MCP Client + OAuth2 Token Manager)
          |
          +===> OAuth2 Token: POST http://localhost:8080/oauth2/token
          |
          +===> MCP Streamable SSE: POST http://localhost:8080/mcp
```

---

## Prerequisites

- Java 21+
- Apache Maven 3.9+
- Running SecureMCP server at `http://localhost:8080`

---

## Configuration (`src/main/resources/application.yml`)

```yaml
server:
  port: 8081

spring:
  application:
    name: securemcp-client

securemcp:
  server:
    base-url: http://localhost:8080
    token-endpoint: http://localhost:8080/oauth2/token
    mcp-endpoint: http://localhost:8080/mcp
    client-id: securemcp-local-client
    client-secret: securemcp
    scope: security.read identity.read identity.write platform.admin
```

---

## Building and Running

### 1. Compile the Project
```bash
mvn clean compile
```

### 2. Run the Application
```bash
mvn spring-boot:run
```

Once started, access the Web Chatbot UI at:
👉 **[http://localhost:8081](http://localhost:8081)**

---

## REST Endpoints

### 1. Connectivity Status
```bash
curl http://localhost:8081/api/status
```
**Response**:
```json
{
  "connected": true,
  "sessionId": "196ba895-8998-416d-b471-55a31642d131",
  "toolsCount": 11,
  "tools": [
    "checkPermission",
    "oauthIntrospect",
    "listTenantUsers",
    "oauthRevoke",
    "jwtRevoke",
    "recentSecurityEvents",
    "jwtValidate",
    "jwtDecode",
    "assignRole",
    "authorizeResource",
    "oidcDiscover"
  ],
  "serverUrl": "http://localhost:8080"
}
```

### 2. Chat with Chatbot / Invoke MCP Tools
```bash
curl -X POST http://localhost:8081/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Validate current JWT"}'
```
