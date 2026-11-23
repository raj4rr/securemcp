package com.securemcp.identity;

import org.springframework.jdbc.core.JdbcTemplate;
import com.securemcp.audit.AuditService;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;

@Service
public class ApiKeyService {
    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final SecureRandom random = new SecureRandom();

    public ApiKeyService(JdbcTemplate j, AuditService a) {
        jdbc = j;
        audit = a;
    }

    @org.springframework.transaction.annotation.Transactional
    public Map<String, Object> create(UUID tenantId, String label, Set<String> scopes, Instant expiresAt) {
        Set<String> allowed = Set.of("security.read", "security.write", "identity.read", "identity.write");
        if (scopes == null || scopes.isEmpty() || !allowed.containsAll(scopes))
            throw new IllegalArgumentException("Unsupported or empty API key scopes");
        if (expiresAt != null && !expiresAt.isAfter(Instant.now()))
            throw new IllegalArgumentException("API key expiry must be in the future");
        byte[] b = new byte[32];
        random.nextBytes(b);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        String raw = "sk_live_" + secret;
        String prefix = raw.substring(0, 16);
        UUID id = UUID.randomUUID();
        jdbc.update("insert into api_keys(id,tenant_id,key_prefix,secret_hash,label,scopes,expires_at) values (?,?,?,?,?,?,?)", id, tenantId, prefix, hash(raw), label, String.join(" ", scopes), expiresAt == null ? null : java.time.OffsetDateTime.ofInstant(expiresAt, java.time.ZoneOffset.UTC));
        audit.record("authenticated-principal", "api_key.create", id.toString(), "SUCCESS", Map.of("tenantId", tenantId, "scopes", scopes));
        return Map.of("id", id, "apiKey", raw, "prefix", prefix, "warning", "The API key is shown once. Store it in a secret manager.");
    }

    public Optional<KeyPrincipal> authenticate(String raw) {
        if (raw == null || !raw.startsWith("sk_live_")) return Optional.empty();
        String hash = hash(raw);
        var rows = jdbc.query("select id,tenant_id,label,scopes from api_keys where secret_hash=? and revoked_at is null and (expires_at is null or expires_at>now())", (rs, n) -> new KeyPrincipal(rs.getString("id"), rs.getString("tenant_id"), rs.getString("label"), Set.of(rs.getString("scopes").split(" "))), hash);
        return rows.stream().findFirst();
    }

    @org.springframework.transaction.annotation.Transactional
    public void revoke(UUID tenantId, UUID id) {
        int changed = jdbc.update("update api_keys set revoked_at=now() where id=? and tenant_id=? and revoked_at is null", id, tenantId);
        if (changed != 1) throw new IllegalArgumentException("API key not found in authenticated tenant");
        audit.record("authenticated-principal", "api_key.revoke", id.toString(), "SUCCESS", Map.of("tenantId", tenantId));
    }

    private String hash(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public record KeyPrincipal(String id, String tenantId, String label, Set<String> scopes) {
    }
}
