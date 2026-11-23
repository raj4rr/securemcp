package com.securemcp.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class TenantContext {
    public Optional<UUID> currentTenant() {
        Authentication a = auth();
        if (a == null || !a.isAuthenticated()) return Optional.empty();
        Object value = null;
        if (a instanceof JwtAuthenticationToken jwt) value = jwt.getToken().getClaim("tenant_id");
        if (value == null && a.getDetails() instanceof Map<?, ?> m) value = m.get("tenantId");
        try {
            return value == null ? Optional.empty() : Optional.of(UUID.fromString(value.toString()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public UUID requireTenant(UUID requested) {
        Authentication a = auth();
        if (a != null && a.getAuthorities().stream().anyMatch(x -> x.getAuthority().equals("SCOPE_platform.admin")))
            return requested;
        UUID actual = currentTenant().orElseThrow(() -> new org.springframework.security.access.AccessDeniedException("Authenticated principal has no tenant context"));
        if (!actual.equals(requested))
            throw new org.springframework.security.access.AccessDeniedException("Cross-tenant access denied");
        return actual;
    }

    public Map<String, Object> trustedAttributes() {
        Authentication a = auth();
        if (a == null) return Map.of();
        Map<String, Object> out = new HashMap<>();
        currentTenant().ifPresent(t -> out.put("tenantId", t.toString()));
        out.put("subject", a.getName());
        if (a instanceof JwtAuthenticationToken jwt) {
            for (String k : List.of("department", "clearance", "groups", "email_verified")) {
                Object v = jwt.getToken().getClaims().get(k);
                if (v != null) out.put(k, v);
            }
        } else if (a.getDetails() instanceof Map<?, ?> m && m.get("label") != null)
            out.put("apiKeyLabel", m.get("label"));
        return Map.copyOf(out);
    }

    private Authentication auth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
