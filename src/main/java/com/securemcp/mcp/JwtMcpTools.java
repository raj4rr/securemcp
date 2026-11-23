package com.securemcp.mcp;

import java.util.Map;

import com.securemcp.jwt.JwtInspectionService;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;
import org.springframework.security.access.prepost.PreAuthorize;

@Component
public class JwtMcpTools {
    private final JwtInspectionService jwt;

    public JwtMcpTools(JwtInspectionService jwt) {
        this.jwt = jwt;
    }

    @Tool(description = "Decode a compact JWT without trusting it. Never treat this output as authenticated claims.")
    @PreAuthorize("hasAuthority('SCOPE_security.read')")
    public Map<String, Object> jwtDecode(@ToolParam(description = "Compact JWT string") String token) {
        McpSecurity.requireScope("security.read");
        return jwt.decodeUntrusted(token);
    }

    @Tool(description = "Cryptographically validate a JWT using the configured issuer/JWKS decoder and check revocation status.")
    @PreAuthorize("hasAuthority('SCOPE_security.read')")
    public Map<String, Object> jwtValidate(@ToolParam(description = "Compact JWT string") String token) {
        McpSecurity.requireScope("security.read");
        return jwt.validate(token);
    }

    @Tool(description = "Revoke a JWT by its jti until its remaining lifetime expires. Requires security.write authorization and explicit confirmation.")
    @PreAuthorize("hasAuthority('SCOPE_security.write')")
    public Map<String, Object> jwtRevoke(@ToolParam(description = "JWT ID claim (jti)") String jti,
                                         @ToolParam(description = "Remaining lifetime in seconds, maximum 604800") long ttlSeconds,
                                         @ToolParam(description = "Must be true to confirm revocation") boolean confirm) {
        McpSecurity.requireScope("security.write");
        if (!confirm) return Map.of("revoked", false, "reason", "confirmation_required");
        return jwt.revoke(jti, ttlSeconds);
    }
}
