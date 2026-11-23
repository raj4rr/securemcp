package com.securemcp.client.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.*;

@Service
public class SecureMcpConnector {
    private static final Logger log = LoggerFactory.getLogger(SecureMcpConnector.class);

    @Value("${securemcp.server.base-url:http://localhost:8080}")
    private String baseUrl;

    @Value("${securemcp.server.token-endpoint:http://localhost:8080/oauth2/token}")
    private String tokenEndpoint;

    @Value("${securemcp.server.mcp-endpoint:http://localhost:8080/mcp}")
    private String mcpEndpoint;

    @Value("${securemcp.server.client-id:securemcp-local-client}")
    private String clientId;

    @Value("${securemcp.server.client-secret:securemcp}")
    private String clientSecret;

    @Value("${securemcp.server.scope:security.read identity.read identity.write platform.admin}")
    private String scope;

    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    private String cachedToken;
    private Instant tokenExpiry = Instant.MIN;
    private String sessionId;
    private List<Map<String, Object>> cachedTools = new ArrayList<>();

    public SecureMcpConnector(ObjectMapper objectMapper) {
        this.restClient = RestClient.builder().build();
        this.objectMapper = objectMapper;
    }

    public synchronized String getAccessToken() {
        if (cachedToken != null && Instant.now().isBefore(tokenExpiry.minusSeconds(30))) {
            return cachedToken;
        }

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("scope", scope);

        String credentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());

        JsonNode response = restClient.post()
                .uri(tokenEndpoint)
                .header(HttpHeaders.AUTHORIZATION, "Basic " + credentials)
                .header("Host", "localhost:8080")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(body)
                .retrieve()
                .body(JsonNode.class);

        if (response != null && response.has("access_token")) {
            this.cachedToken = response.get("access_token").asText();
            int expiresIn = response.has("expires_in") ? response.get("expires_in").asInt() : 900;
            this.tokenExpiry = Instant.now().plusSeconds(expiresIn);
            log.info("Obtained OAuth2 token from SecureMCP (expires in {}s)", expiresIn);
            return this.cachedToken;
        }
        throw new IllegalStateException("Failed to obtain OAuth2 access token: " + response);
    }

    public synchronized Map<String, Object> initializeSession() {
        String token = getAccessToken();
        Map<String, Object> initPayload = Map.of(
                "jsonrpc", "2.0",
                "id", 1,
                "method", "initialize",
                "params", Map.of(
                        "protocolVersion", "2024-11-05",
                        "capabilities", Map.of(),
                        "clientInfo", Map.of("name", "SecureMcp-Java-Client", "version", "1.0.0")
                )
        );

        var responseEntity = restClient.post()
                .uri(mcpEndpoint)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header("Host", "localhost:8080")
                .header(HttpHeaders.ACCEPT, "application/json, text/event-stream")
                .contentType(MediaType.APPLICATION_JSON)
                .body(initPayload)
                .retrieve()
                .toEntity(String.class);

        List<String> sessionHeaders = responseEntity.getHeaders().get("Mcp-Session-Id");
        if (sessionHeaders != null && !sessionHeaders.isEmpty()) {
            this.sessionId = sessionHeaders.get(0);
            log.info("SecureMCP Session initialized: {}", this.sessionId);
        }

        listTools();
        return parseResponse(responseEntity.getBody());
    }

    public synchronized List<Map<String, Object>> listTools() {
        if (this.sessionId == null) {
            initializeSession();
        }

        String token = getAccessToken();
        Map<String, Object> listPayload = Map.of(
                "jsonrpc", "2.0",
                "id", 2,
                "method", "tools/list",
                "params", Map.of()
        );

        String rawResponse = restClient.post()
                .uri(mcpEndpoint)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header("Host", "localhost:8080")
                .header("mcp-session-id", this.sessionId)
                .header(HttpHeaders.ACCEPT, "application/json, text/event-stream")
                .contentType(MediaType.APPLICATION_JSON)
                .body(listPayload)
                .retrieve()
                .body(String.class);

        Map<String, Object> parsed = parseResponse(rawResponse);
        if (parsed.containsKey("result")) {
            Map<?, ?> result = (Map<?, ?>) parsed.get("result");
            if (result.containsKey("tools")) {
                this.cachedTools = (List<Map<String, Object>>) result.get("tools");
            }
        }
        return this.cachedTools;
    }

    public synchronized Map<String, Object> callTool(String toolName, Map<String, Object> arguments) {
        if (this.sessionId == null) {
            initializeSession();
        }

        String token = getAccessToken();
        Map<String, Object> callPayload = Map.of(
                "jsonrpc", "2.0",
                "id", UUID.randomUUID().hashCode(),
                "method", "tools/call",
                "params", Map.of(
                        "name", toolName,
                        "arguments", arguments != null ? arguments : Map.of()
                )
        );

        try {
            String rawResponse = restClient.post()
                    .uri(mcpEndpoint)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header("Host", "localhost:8080")
                    .header("mcp-session-id", this.sessionId)
                    .header(HttpHeaders.ACCEPT, "application/json, text/event-stream")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(callPayload)
                    .retrieve()
                    .body(String.class);

            Map<String, Object> parsed = parseResponse(rawResponse);
            if (parsed.containsKey("result")) {
                return (Map<String, Object>) parsed.get("result");
            }
            return parsed;
        } catch (Exception ex) {
            log.warn("Error calling tool, attempting re-initialization: {}", ex.getMessage());
            initializeSession();
            String rawResponse = restClient.post()
                    .uri(mcpEndpoint)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + getAccessToken())
                    .header("Host", "localhost:8080")
                    .header("mcp-session-id", this.sessionId)
                    .header(HttpHeaders.ACCEPT, "application/json, text/event-stream")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(callPayload)
                    .retrieve()
                    .body(String.class);
            Map<String, Object> parsed = parseResponse(rawResponse);
            return parsed.containsKey("result") ? (Map<String, Object>) parsed.get("result") : parsed;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseResponse(String raw) {
        if (raw == null || raw.isBlank()) return Map.of();
        try {
            for (String line : raw.split("\\r?\\n")) {
                if (line.startsWith("data:")) {
                    return objectMapper.readValue(line.substring(5).trim(), Map.class);
                }
            }
            return objectMapper.readValue(raw.trim(), Map.class);
        } catch (Exception e) {
            log.error("Failed to parse JSON response: {}", raw, e);
            return Map.of("raw", raw, "error", e.getMessage());
        }
    }

    public String getSessionId() {
        return sessionId;
    }

    public List<Map<String, Object>> getCachedTools() {
        return cachedTools;
    }

    public String getBaseUrl() {
        return baseUrl;
    }
}
