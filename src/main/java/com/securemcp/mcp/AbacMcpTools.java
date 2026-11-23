package com.securemcp.mcp;

import com.securemcp.authorization.AbacService;
import com.securemcp.authorization.TenantContext;
import org.springframework.ai.tool.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class AbacMcpTools {
    private final AbacService abac;
    private final TenantContext tenantContext;

    public AbacMcpTools(AbacService a, TenantContext t) {
        abac = a;
        tenantContext = t;
    }

    @Tool(description = "Evaluate a tenant ABAC policy for the authenticated caller. Attributes are derived from verified token claims and server-side identity context, never from model-supplied assertions. Default decision is deny.")
    @PreAuthorize("hasAuthority('SCOPE_security.read')")
    public Map<String, Object> authorizeResource(@ToolParam(description = "Tenant UUID; must match authenticated tenant") String tenantId, @ToolParam(description = "Action such as document.read") String action, @ToolParam(description = "Resource identifier") String resource) {
        McpSecurity.requireScope("security.read");
        var a = SecurityContextHolder.getContext().getAuthentication();
        UUID tenant = tenantContext.requireTenant(UUID.fromString(tenantId));
        return abac.decide(tenant, a == null ? null : a.getName(), action, resource, tenantContext.trustedAttributes());
    }
}
