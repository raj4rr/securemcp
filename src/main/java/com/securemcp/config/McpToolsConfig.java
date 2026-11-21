package com.securemcp.config;
import com.securemcp.mcp.*;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.*;
@Configuration public class McpToolsConfig {
 @Bean ToolCallbackProvider secureMcpTools(JwtMcpTools jwt,KeycloakMcpTools keycloak,IdentityMcpTools identity,OAuthMcpTools oauth,AbacMcpTools abac,AuditMcpTools audit){return MethodToolCallbackProvider.builder().toolObjects(jwt,keycloak,identity,oauth,abac,audit).build();}
}
