package com.securemcp.mcp;
import java.util.Map; import org.springframework.beans.factory.annotation.Value; import org.springframework.web.client.RestClient; import org.springframework.stereotype.Component;
import org.springframework.ai.tool.annotation.Tool; import org.springframework.ai.tool.annotation.ToolParam; import org.springframework.security.access.prepost.PreAuthorize;
@Component public class KeycloakMcpTools {
 private final RestClient client; private final boolean enabled;
 public KeycloakMcpTools(@Value("${securemcp.keycloak.discovery-uri}") String discoveryUri,@Value("${securemcp.keycloak.enabled:false}") boolean enabled){this.client=RestClient.builder().baseUrl(discoveryUri).build();this.enabled=enabled;}
 @Tool(description="Retrieve configured Keycloak OpenID Connect discovery metadata. Does not retrieve secrets or tokens.")
 @PreAuthorize("hasAuthority('SCOPE_security.read')") public Map<?,?> oidcDiscover(@ToolParam(description="Set true to confirm discovery request") boolean confirm){McpSecurity.requireScope("security.read");if(!confirm)return Map.of("executed",false,"reason","confirmation_required");if(!enabled)return Map.of("enabled",false,"reason","KEYCLOAK_ENABLED is false");return client.get().retrieve().body(Map.class);}
}
