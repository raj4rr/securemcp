package com.securemcp.mcp;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

final class McpSecurity {
    private McpSecurity() {
    }

    static void requireScope(String scope) {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null || !a.isAuthenticated() || a.getAuthorities().stream().noneMatch(x -> x.getAuthority().equals("SCOPE_" + scope)))
            throw new AccessDeniedException("Missing required MCP scope: " + scope);
    }
}
