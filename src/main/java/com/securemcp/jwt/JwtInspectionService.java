package com.securemcp.jwt;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import com.securemcp.audit.AuditService;

@Service
public class JwtInspectionService {
    private final JwtDecoder decoder;
    private final ObjectMapper mapper;
    private final StringRedisTemplate redis;
    private final AuditService audit;

    public JwtInspectionService(JwtDecoder decoder, ObjectMapper mapper, StringRedisTemplate redis, AuditService audit) {
        this.decoder = decoder;
        this.mapper = mapper;
        this.redis = redis;
        this.audit = audit;
    }

    public Map<String, Object> decodeUntrusted(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Malformed compact JWT");
        try {
            return Map.of("header", mapper.readValue(Base64.getUrlDecoder().decode(parts[0]), Map.class),
                    "payload", mapper.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class),
                    "trusted", false, "warning", "Decoded only; signature and claims have not been verified");
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JWT encoding", e);
        }
    }

    public Map<String, Object> validate(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            String jti = jwt.getId();
            if (jti != null && Boolean.TRUE.equals(redis.hasKey("jwt:revoked:" + jti)))
                return Map.of("valid", false, "reason", "revoked");
            return Map.of("valid", true, "subject", jwt.getSubject(), "issuer", String.valueOf(jwt.getIssuer()),
                    "issuedAt", String.valueOf(jwt.getIssuedAt()), "expiresAt", String.valueOf(jwt.getExpiresAt()),
                    "audiences", jwt.getAudience());
        } catch (JwtException e) {
            return Map.of("valid", false, "reason", "invalid_signature_or_claims");
        }
    }

    public Map<String, Object> revoke(String jti, long ttlSeconds) {
        if (jti == null || jti.isBlank() || ttlSeconds < 1 || ttlSeconds > 604800)
            throw new IllegalArgumentException("jti and TTL (1..604800 seconds) are required");
        redis.opsForValue().set("jwt:revoked:" + jti, Instant.now().toString(), java.time.Duration.ofSeconds(ttlSeconds));
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        audit.record(auth == null ? "unknown" : auth.getName(), "jwt.revoke", jti, "SUCCESS", Map.of("ttlSeconds", ttlSeconds));
        return Map.of("revoked", true, "jti", jti, "ttlSeconds", ttlSeconds);
    }
}
