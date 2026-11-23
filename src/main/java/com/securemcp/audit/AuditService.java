package com.securemcp.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import com.securemcp.authorization.TenantContext;

import java.util.UUID;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuditService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final TenantContext tenantContext;

    public AuditService(JdbcTemplate jdbc, ObjectMapper mapper, TenantContext tenantContext) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.tenantContext = tenantContext;
    }

    public java.util.List<java.util.Map<String, Object>> recent(int limit) {
        return recent(limit, 0);
    }

    public java.util.List<java.util.Map<String, Object>> recent(int limit, int page) {
        if (limit < 1 || limit > 200 || page < 0 || page > 100000)
            throw new IllegalArgumentException("Invalid audit pagination");
        int offset = Math.multiplyExact(page, limit);
        if (isPlatformAdmin())
            return jdbc.queryForList("select id,tenant_id,actor,action,resource,outcome,details,created_at from audit_events order by created_at desc limit ? offset ?", limit, offset);
        UUID tenant = tenantContext.currentTenant().orElseThrow(() -> new org.springframework.security.access.AccessDeniedException("Tenant context required"));
        return jdbc.queryForList("select id,tenant_id,actor,action,resource,outcome,details,created_at from audit_events where tenant_id=? order by created_at desc limit ? offset ?", tenant, limit, offset);
    }

    private boolean isPlatformAdmin() {
        var a = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        return a != null && a.getAuthorities().stream().anyMatch(x -> x.getAuthority().equals("SCOPE_platform.admin"));
    }

    public void record(String actor, String action, String resource, String outcome, Map<String, ?> details) {
        try {
            Map<String, ?> safe = details == null ? Map.of() : details;
            var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated() && (actor.equals("system") || actor.equals("authenticated-principal")))
                actor = authentication.getName();
            UUID tenant = tenantContext.currentTenant().orElseGet(() -> {
                Object v = safe.get("tenantId");
                try {
                    return v == null ? null : UUID.fromString(v.toString());
                } catch (Exception ignored) {
                    return null;
                }
            });
            jdbc.update("insert into audit_events(tenant_id,actor,action,resource,outcome,details) values (?,?,?,?,?,?::jsonb)", tenant, actor, action, resource, outcome, mapper.writeValueAsString(safe));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize audit details", e);
        }
    }
}
