"""
SecureMCP Client SDK & Connector.
Handles OAuth2 token acquisition, Streamable HTTP SSE MCP session lifecycle, and tool invocation.
"""

import json
import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("securemcp_client")


class SecureMcpClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        client_id: str = "securemcp-local-client",
        client_secret: str = "securemcp",
        scopes: str = "security.read identity.read identity.write platform.admin",
    ):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.token: Optional[str] = None
        self.session_id: Optional[str] = None
        self.tools: List[Dict[str, Any]] = []

    def get_token(self, force_refresh: bool = False) -> str:
        """Fetch or return cached OAuth2 Bearer token."""
        if self.token and not force_refresh:
            return self.token

        token_url = f"{self.base_url}/oauth2/token"
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                token_url,
                auth=(self.client_id, self.client_secret),
                data={
                    "grant_type": "client_credentials",
                    "scope": self.scopes,
                },
                headers={"Host": "localhost:8080"},
            )
            resp.raise_for_status()
            data = resp.json()
            self.token = data["access_token"]
            return self.token

    def _headers(self, with_session: bool = True) -> Dict[str, str]:
        token = self.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Host": "localhost:8080",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if with_session and self.session_id:
            headers["mcp-session-id"] = self.session_id
        return headers

    def connect_and_initialize(self) -> Dict[str, Any]:
        """Initialize MCP Streamable session and fetch registered tools."""
        url = f"{self.base_url}/mcp"
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "SecureMcp-Chatbot-Client",
                    "version": "1.0.0",
                },
            },
        }

        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                url,
                json=init_payload,
                headers=self._headers(with_session=False),
            )
            resp.raise_for_status()
            session_id = resp.headers.get("mcp-session-id")
            if not session_id:
                raise RuntimeError("No mcp-session-id received from SecureMCP server")
            self.session_id = session_id
            init_res = resp.json()

            # Refresh tools list
            self.list_tools()
            return init_res

    def _parse_mcp_response(self, text: str) -> Dict[str, Any]:
        """Parse JSON response, handling standard JSON or SSE data frames."""
        text = text.strip()
        if not text:
            return {}
        for line in text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        return json.loads(text)

    def list_tools(self) -> List[Dict[str, Any]]:
        """Query MCP server for available security and identity tools."""
        if not self.session_id:
            self.connect_and_initialize()

        url = f"{self.base_url}/mcp"
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                url,
                json=payload,
                headers=self._headers(with_session=True),
            )
            resp.raise_for_status()
            data = self._parse_mcp_response(resp.text)
            self.tools = data.get("result", {}).get("tools", [])
            return self.tools

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Invoke a tool on the SecureMCP server."""
        if not self.session_id:
            self.connect_and_initialize()

        url = f"{self.base_url}/mcp"
        payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
        }
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                url,
                json=payload,
                headers=self._headers(with_session=True),
            )
            # If session expired or invalid, reconnect once
            if resp.status_code == 400 and "Session ID" in resp.text:
                self.connect_and_initialize()
                resp = client.post(
                    url,
                    json=payload,
                    headers=self._headers(with_session=True),
                )

            resp.raise_for_status()
            data = self._parse_mcp_response(resp.text)
            if "error" in data:
                return {"error": data["error"]}
            return data.get("result", {})
