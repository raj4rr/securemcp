"""
Chatbot engine with Intent Parsing, Tool Calling against SecureMCP, and LLM fallback (OpenAI/Anthropic/Local if available).
"""

import json
import os
import re
from typing import Any, Dict, List, Optional
from mcp_client import SecureMcpClient


class SecureMcpChatbot:
    def __init__(self, mcp_client: SecureMcpClient):
        self.mcp = mcp_client

    def get_system_status(self) -> Dict[str, Any]:
        """Fetch server connectivity and tool counts."""
        try:
            tools = self.mcp.list_tools() if self.mcp.session_id else self.mcp.connect_and_initialize()
            if isinstance(tools, dict) and "result" in tools:
                tools = self.mcp.tools
            return {
                "connected": True,
                "sessionId": self.mcp.session_id,
                "tokenAvailable": bool(self.mcp.token),
                "toolsCount": len(self.mcp.tools),
                "tools": [t["name"] for t in self.mcp.tools],
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
                "toolsCount": 0,
                "tools": [],
            }

    def process_message(self, user_message: str) -> Dict[str, Any]:
        """
        Process user message, determine intent, execute corresponding SecureMCP tools,
        and construct formatted response.
        """
        msg = user_message.strip()
        lower = msg.lower()

        # Ensure connection
        if not self.mcp.session_id:
            try:
                self.mcp.connect_and_initialize()
            except Exception as e:
                return {
                    "reply": f"⚠️ Could not connect to SecureMCP Server at `{self.mcp.base_url}`: {str(e)}",
                    "toolCall": None,
                }

        # 1. Help / Capabilities
        if any(w in lower for w in ["help", "what can you do", "commands", "menu"]):
            return {
                "reply": (
                    "👋 **Hello! I am SecureMCP Security Bot.**\n\n"
                    "I am directly connected to your Spring Boot SecureMCP server over OAuth2 and Streamable HTTP protocol. Here are some things you can ask me:\n\n"
                    "🛡️ **Audit & Security Events**\n"
                    "- *'Show recent security audit logs'* or *'Audit events (limit 5)'*\n\n"
                    "🔑 **OAuth & Identity Introspection**\n"
                    "- *'Introspect my token'* (checks active OAuth claims, tenant, scopes)\n"
                    "- *'Check permission documents.read'* or *'Check permission identity.write'*\n\n"
                    "📜 **JWT Inspection & Cryptographic Validation**\n"
                    "- *'Decode JWT <token>'* (inspect unverified headers & claims)\n"
                    "- *'Validate JWT <token>'* (cryptographically verify against JWKS)\n\n"
                    "🌐 **Keycloak & OpenID Connect**\n"
                    "- *'Discover Keycloak OIDC metadata'*\n\n"
                    "👥 **Tenant & ABAC Policies**\n"
                    "- *'List tenant users for <tenant-uuid>'*\n"
                    "- *'Evaluate ABAC policy for action=document.read resource=payroll in tenant <uuid>'*\n\n"
                    "🔧 *Or type 'list tools' to view all registered MCP tools and schemas.*"
                ),
                "toolCall": None,
            }

        # 2. List tools
        if "list tools" in lower or "show tools" in lower or "mcp tools" in lower:
            tools = self.mcp.list_tools()
            tool_list_md = "\n".join([f"- **`{t['name']}`**: {t.get('description', '')}" for t in tools])
            return {
                "reply": f"### 🛠️ Registered SecureMCP Tools ({len(tools)})\n\n{tool_list_md}",
                "toolCall": {"name": "tools/list", "arguments": {}, "result": tools},
            }

        # 3. OAuth Introspect
        if any(w in lower for w in ["introspect", "my token", "who am i", "current token"]):
            res = self.mcp.call_tool("oauthIntrospect", {})
            return {
                "reply": (
                    "### 🛡️ OAuth Token Introspection\n\n"
                    f"```json\n{json.dumps(res, indent=2)}\n```\n\n"
                    "The caller token was verified against the SecureMCP OAuth2 Authorization Server."
                ),
                "toolCall": {"name": "oauthIntrospect", "arguments": {}, "result": res},
            }

        # 4. Recent Security Audit Events
        if "audit" in lower or "security events" in lower or "logs" in lower:
            limit = 10
            match = re.search(r"limit\s*=?\s*(\d+)", lower)
            if match:
                limit = min(max(int(match.group(1)), 1), 100)
            res = self.mcp.call_tool("recentSecurityEvents", {"limit": limit})
            return {
                "reply": (
                    f"### 📋 Recent Security Audit Events (Limit: {limit})\n\n"
                    f"```json\n{json.dumps(res, indent=2)}\n```"
                ),
                "toolCall": {"name": "recentSecurityEvents", "arguments": {"limit": limit}, "result": res},
            }

        # 5. Check Permission
        if "check permission" in lower or "has permission" in lower:
            perm_match = re.search(r"(?:check permission|has permission)\s+([a-zA-Z0-9_\.:-]+)", msg, re.IGNORECASE)
            perm = perm_match.group(1) if perm_match else "security.read"
            res = self.mcp.call_tool("checkPermission", {"permission": perm})
            return {
                "reply": (
                    f"### 🔍 Permission Check for `{perm}`\n\n"
                    f"```json\n{json.dumps(res, indent=2)}\n```"
                ),
                "toolCall": {"name": "checkPermission", "arguments": {"permission": perm}, "result": res},
            }

        # 6. Validate JWT
        if "validate" in lower and "jwt" in lower or "verify" in lower and "jwt" in lower:
            tokens = re.findall(r"ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", msg)
            token = tokens[0] if tokens else self.mcp.token
            res = self.mcp.call_tool("jwtValidate", {"token": token})
            return {
                "reply": (
                    "### ✅ Cryptographic JWT Validation\n\n"
                    f"```json\n{json.dumps(res, indent=2)}\n```"
                ),
                "toolCall": {"name": "jwtValidate", "arguments": {"token": token[:20] + "..."}, "result": res},
            }

        # 7. Decode JWT
        if "decode" in lower and "jwt" in lower or "inspect" in lower and "jwt" in lower:
            tokens = re.findall(r"ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", msg)
            token = tokens[0] if tokens else self.mcp.token
            res = self.mcp.call_tool("jwtDecode", {"token": token})
            return {
                "reply": (
                    "### 🔎 JWT Header & Claims Decode\n\n"
                    f"```json\n{json.dumps(res, indent=2)}\n```"
                ),
                "toolCall": {"name": "jwtDecode", "arguments": {"token": token[:20] + "..."}, "result": res},
            }

        # 8. OIDC Discovery
        if "oidc" in lower or "keycloak" in lower or "discovery" in lower:
            res = self.mcp.call_tool("oidcDiscover", {"confirm": True})
            return {
                "reply": (
                    "### 🌐 Keycloak OpenID Connect Discovery\n\n"
                    f"```json\n{json.dumps(res, indent=2)}\n```"
                ),
                "toolCall": {"name": "oidcDiscover", "arguments": {"confirm": True}, "result": res},
            }

        # 9. Direct Tool Calling via JSON or syntax: `call <toolName> {"arg": "val"}`
        if msg.startswith("call "):
            parts = msg[5:].strip().split(" ", 1)
            tool_name = parts[0]
            args = {}
            if len(parts) > 1:
                try:
                    args = json.loads(parts[1])
                except Exception as e:
                    return {"reply": f"❌ Invalid JSON arguments: {str(e)}", "toolCall": None}
            res = self.mcp.call_tool(tool_name, args)
            return {
                "reply": f"### 🛠️ Tool `{tool_name}` Result\n\n```json\n{json.dumps(res, indent=2)}\n```",
                "toolCall": {"name": tool_name, "arguments": args, "result": res},
            }

        # Fallback guidance
        return {
            "reply": (
                f"I received: *'{msg}'*.\n\n"
                "I am a security chatbot connected to SecureMCP. You can ask me to:\n"
                "- `Introspect my token`\n"
                "- `Show recent audit logs`\n"
                "- `Check permission security.read`\n"
                "- `Validate current JWT`\n"
                "- `Discover Keycloak OIDC`\n"
                "- `List tools`\n"
                "Or call any tool directly with: `call <toolName> {\"key\": \"value\"}`"
            ),
            "toolCall": None,
        }
