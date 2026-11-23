package com.securemcp.client.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securemcp.client.model.ChatResponse;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ChatbotService {

    private final SecureMcpConnector connector;
    private final ObjectMapper objectMapper;

    public ChatbotService(SecureMcpConnector connector, ObjectMapper objectMapper) {
        this.connector = connector;
        this.objectMapper = objectMapper;
    }

    public Map<String, Object> getSystemStatus() {
        try {
            List<Map<String, Object>> tools = connector.listTools();
            List<String> toolNames = tools.stream()
                    .map(t -> (String) t.get("name"))
                    .filter(Objects::nonNull)
                    .toList();
            return Map.of(
                    "connected", true,
                    "sessionId", connector.getSessionId() != null ? connector.getSessionId() : "none",
                    "toolsCount", toolNames.size(),
                    "tools", toolNames,
                    "serverUrl", connector.getBaseUrl()
            );
        } catch (Exception e) {
            return Map.of(
                    "connected", false,
                    "error", e.getMessage(),
                    "toolsCount", 0,
                    "tools", List.of(),
                    "serverUrl", connector.getBaseUrl()
            );
        }
    }

    public ChatResponse processMessage(String rawInput) {
        if (rawInput == null || rawInput.isBlank()) {
            return new ChatResponse("Please provide a question or command.", null);
        }

        String msg = rawInput.trim();
        String lower = msg.toLowerCase();

        // 1. Help / Info
        if (lower.contains("help") || lower.contains("what can you do") || lower.contains("commands")) {
            String helpText = """
                👋 **Hello! I am the SecureMCP Java Security Assistant.**
                
                Connected directly via **Spring AI MCP** & OAuth2 to your SecureMCP server on port 8080.
                
                Here are examples of what I can do:
                
                🛡️ **Token & Cryptographic Verification**
                - `Validate current JWT` *(validates RSA signature and expiration against JWKS)*
                - `Decode JWT <token>` *(inspect unverified claims and headers)*
                - `Introspect my token` *(inspects OAuth2 grant, scopes, and subject identity)*
                
                🔒 **Permission & Security Audits**
                - `Check permission security.read`
                - `Show recent audit logs` or `Audit logs limit 5`
                
                🌐 **Keycloak & Identity Federation**
                - `Discover Keycloak OIDC` *(retrieves OIDC discovery metadata)*
                
                👥 **Tenant & ABAC Rules**
                - `List tenant users for <tenant-id>`
                - `Evaluate ABAC policy for action=document.read resource=payroll in tenant <uuid>`
                
                🔧 **Direct Tool Invocation**
                - `List tools`
                - `call <toolName> {"key": "val"}`
                """;
            return new ChatResponse(helpText, null);
        }

        // 2. List tools
        if (lower.contains("list tools") || lower.contains("show tools") || lower.contains("available tools")) {
            List<Map<String, Object>> tools = connector.listTools();
            StringBuilder sb = new StringBuilder();
            sb.append("### 🛠️ Registered SecureMCP Tools (").append(tools.size()).append(")\n\n");
            for (Map<String, Object> tool : tools) {
                sb.append("- **`").append(tool.get("name")).append("`**: ")
                  .append(tool.getOrDefault("description", "No description")).append("\n");
            }
            return new ChatResponse(sb.toString(), Map.of("name", "tools/list", "arguments", Map.of(), "result", tools));
        }

        // 3. Introspect token
        if (lower.contains("introspect") || lower.contains("my token") || lower.contains("who am i")) {
            Map<String, Object> result = connector.callTool("oauthIntrospect", Map.of());
            return new ChatResponse("### 🛡️ OAuth Token Introspection\n\n```json\n" + toJson(result) + "\n```",
                    Map.of("name", "oauthIntrospect", "arguments", Map.of(), "result", result));
        }

        // 4. Audit events
        if (lower.contains("audit") || lower.contains("security events") || lower.contains("logs")) {
            int limit = 10;
            Matcher m = Pattern.compile("limit\\s*=?\\s*(\\d+)").matcher(lower);
            if (m.find()) {
                limit = Math.min(Math.max(Integer.parseInt(m.group(1)), 1), 100);
            }
            Map<String, Object> result = connector.callTool("recentSecurityEvents", Map.of("limit", limit));
            return new ChatResponse("### 📋 Recent Security Audit Events (Limit: " + limit + ")\n\n```json\n" + toJson(result) + "\n```",
                    Map.of("name", "recentSecurityEvents", "arguments", Map.of("limit", limit), "result", result));
        }

        // 5. Check permission
        if (lower.contains("check permission") || lower.contains("has permission")) {
            Matcher m = Pattern.compile("(?:check permission|has permission)\\s+([a-zA-Z0-9_.:-]+)", Pattern.CASE_INSENSITIVE).matcher(msg);
            String perm = m.find() ? m.group(1) : "security.read";
            Map<String, Object> result = connector.callTool("checkPermission", Map.of("permission", perm));
            return new ChatResponse("### 🔍 Permission Check for `" + perm + "`\n\n```json\n" + toJson(result) + "\n```",
                    Map.of("name", "checkPermission", "arguments", Map.of("permission", perm), "result", result));
        }

        // 6. Validate JWT
        if (lower.contains("validate") && lower.contains("jwt") || lower.contains("verify") && lower.contains("jwt")) {
            String token = extractJwt(msg);
            if (token == null) {
                token = connector.getAccessToken();
            }
            Map<String, Object> result = connector.callTool("jwtValidate", Map.of("token", token));
            return new ChatResponse("### ✅ Cryptographic JWT Validation\n\n```json\n" + toJson(result) + "\n```",
                    Map.of("name", "jwtValidate", "arguments", Map.of("token", token.substring(0, Math.min(20, token.length())) + "..."), "result", result));
        }

        // 7. Decode JWT
        if (lower.contains("decode") && lower.contains("jwt") || lower.contains("inspect") && lower.contains("jwt")) {
            String token = extractJwt(msg);
            if (token == null) {
                token = connector.getAccessToken();
            }
            Map<String, Object> result = connector.callTool("jwtDecode", Map.of("token", token));
            return new ChatResponse("### 🔎 JWT Header & Claims Decode\n\n```json\n" + toJson(result) + "\n```",
                    Map.of("name", "jwtDecode", "arguments", Map.of("token", token.substring(0, Math.min(20, token.length())) + "..."), "result", result));
        }

        // 8. OIDC Discovery
        if (lower.contains("oidc") || lower.contains("keycloak") || lower.contains("discovery")) {
            Map<String, Object> result = connector.callTool("oidcDiscover", Map.of("confirm", true));
            return new ChatResponse("### 🌐 Keycloak OpenID Connect Discovery\n\n```json\n" + toJson(result) + "\n```",
                    Map.of("name", "oidcDiscover", "arguments", Map.of("confirm", true), "result", result));
        }

        // 9. Generic tool invocation: call <toolName> {JSON}
        if (msg.startsWith("call ")) {
            String remainder = msg.substring(5).trim();
            int firstSpace = remainder.indexOf(' ');
            String toolName = firstSpace > 0 ? remainder.substring(0, firstSpace) : remainder;
            Map<String, Object> args = Map.of();
            if (firstSpace > 0) {
                try {
                    args = objectMapper.readValue(remainder.substring(firstSpace).trim(), Map.class);
                } catch (Exception e) {
                    return new ChatResponse("❌ Invalid JSON arguments: " + e.getMessage(), null);
                }
            }
            Map<String, Object> result = connector.callTool(toolName, args);
            return new ChatResponse("### 🛠️ Tool `" + toolName + "` Result\n\n```json\n" + toJson(result) + "\n```",
                    Map.of("name", toolName, "arguments", args, "result", result));
        }

        // Fallback
        return new ChatResponse(
                "I received: *\"" + msg + "\"*.\n\n" +
                "Try asking me:\n" +
                "- `Validate current JWT`\n" +
                "- `Show recent audit logs`\n" +
                "- `Check permission security.read`\n" +
                "- `Introspect my token`\n" +
                "- `Discover Keycloak OIDC`\n" +
                "- `List tools`\n\n" +
                "Or run any tool directly with `call <toolName> {\"key\": \"value\"}`",
                null
        );
    }

    private String extractJwt(String text) {
        Matcher matcher = Pattern.compile("ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+").matcher(text);
        return matcher.find() ? matcher.group(0) : null;
    }

    private String toJson(Object obj) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (Exception e) {
            return String.valueOf(obj);
        }
    }
}
