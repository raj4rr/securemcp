package com.securemcp.api;

import com.securemcp.audit.AuditService;
import com.securemcp.authorization.TenantContext;
import org.springframework.jdbc.core.JdbcTemplate;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.time.Duration;

import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@RestController
@RequestMapping("/api/v1/oauth-clients")
public class OAuthClientController {
    private final RegisteredClientRepository clients;
    private final PasswordEncoder encoder;
    private final AuditService audit;
    private final JdbcTemplate jdbc;
    private final TenantContext tenant;
    private final SecureRandom random = new SecureRandom();

    public OAuthClientController(RegisteredClientRepository c, PasswordEncoder e, AuditService a, JdbcTemplate j, TenantContext t) {
        clients = c;
        encoder = e;
        audit = a;
        jdbc = j;
        tenant = t;
    }

    public record CreateClient(@NotNull UUID tenantId,
                               @NotBlank @jakarta.validation.constraints.Pattern(regexp = "[A-Za-z0-9._-]{3,100}") String clientId,
                               @NotBlank @Size(max = 200) String name, @NotEmpty @Size(max = 10) Set<String> scopes,
                               @Size(max = 10) Set<String> redirectUris, boolean allowClientCredentials,
                               boolean allowAuthorizationCode) {
    }

    @org.springframework.transaction.annotation.Transactional
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> create(@Valid @RequestBody CreateClient r) {
        if (!r.allowClientCredentials() && !r.allowAuthorizationCode())
            throw new IllegalArgumentException("At least one grant must be enabled");
        tenant.requireTenant(r.tenantId());
        Set<String> allowedScopes = Set.of("security.read", "security.write", "identity.read", "identity.write", "platform.admin", "openid", "profile", "email");
        var caller = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        boolean platformCaller = caller != null && caller.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("SCOPE_platform.admin"));
        if (!allowedScopes.containsAll(r.scopes()))
            throw new IllegalArgumentException("Unsupported OAuth scopes requested");
        if (r.scopes().contains("platform.admin") && !platformCaller)
            throw new org.springframework.security.access.AccessDeniedException("Only platform administrators can delegate platform.admin scope");
        if (r.redirectUris() != null && r.redirectUris().stream().anyMatch(u -> u.contains("*") || (!u.startsWith("https://") && !u.startsWith("http://localhost"))))
            throw new IllegalArgumentException("Redirect URIs must be exact HTTPS URLs (HTTP localhost is allowed for development)");
        String secret = generateSecret();
        var b = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(r.clientId()).clientName(r.name()).clientSecret(encoder.encode(secret)).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        if (r.allowClientCredentials()) b.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        if (r.allowAuthorizationCode()) {
            if (r.redirectUris() == null || r.redirectUris().isEmpty())
                throw new IllegalArgumentException("Redirect URIs are required for authorization_code");
            b.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            r.redirectUris().forEach(b::redirectUri);
        }
        r.scopes().forEach(b::scope);
        b.clientSettings(ClientSettings.builder().requireProofKey(r.allowAuthorizationCode()).requireAuthorizationConsent(false).build());
        b.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(15))
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .reuseRefreshTokens(false)
                .build());
        clients.save(b.build());
        jdbc.update("insert into oauth_clients(id,tenant_id,client_id,client_secret_hash,grant_types,scopes,registered_client_id) values (?,?,?,?,?,?,?)", UUID.randomUUID(), r.tenantId(), r.clientId(), encoder.encode(secret), String.join(" ", b.build().getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).toList()), String.join(" ", r.scopes()), b.build().getId());
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        audit.record(auth == null ? "unknown" : auth.getName(), "oauth.client.create", r.clientId(), "SUCCESS", Map.of("tenantId", r.tenantId(), "scopes", r.scopes()));
        return Map.of("clientId", r.clientId(), "clientSecret", secret, "warning", "Store this secret now. It will not be returned again.");
    }

    @org.springframework.transaction.annotation.Transactional
    @DeleteMapping("/{clientId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String clientId, @RequestParam UUID tenantId) {
        tenant.requireTenant(tenantId);
        var rows = jdbc.query("select id from oauth2_registered_client where client_id=?", (rs, n) -> rs.getString(1), clientId);
        if (rows.isEmpty()) throw new IllegalArgumentException("OAuth client not found");
        String registeredId = rows.get(0);
        boolean platform = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("SCOPE_platform.admin"));
        var ownerRows = jdbc.query("select tenant_id from oauth_clients where client_id=?", (rs, n) -> rs.getObject(1, UUID.class), clientId);
        UUID ownerTenant = ownerRows.isEmpty() ? tenantId : ownerRows.get(0);
        if (!platform && !ownerTenant.equals(tenantId))
            throw new org.springframework.security.access.AccessDeniedException("Client does not belong to authenticated tenant");
        jdbc.update("delete from oauth2_authorization where registered_client_id=?", registeredId);
        jdbc.update("delete from oauth2_authorization_consent where registered_client_id=?", registeredId);
        jdbc.update("delete from oauth2_registered_client where id=?", registeredId);
        jdbc.update("delete from oauth_clients where client_id=?", clientId);
        audit.record("authenticated-principal", "oauth.client.delete", clientId, "SUCCESS", Map.of("tenantId", ownerTenant));
    }

    private String generateSecret() {
        byte[] b = new byte[36];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
