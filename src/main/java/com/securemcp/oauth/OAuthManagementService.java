package com.securemcp.oauth;

import com.securemcp.audit.AuditService;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class OAuthManagementService {
    private final OAuth2AuthorizationService authorizations;
    private final RegisteredClientRepository clients;
    private final AuditService audit;

    public OAuthManagementService(OAuth2AuthorizationService a, RegisteredClientRepository c, AuditService audit) {
        authorizations = a;
        clients = c;
        this.audit = audit;
    }


 public Map<String, Object> introspect(String token) {
  var authorization = authorizations.findByToken(
          token, OAuth2TokenType.ACCESS_TOKEN);

  if (authorization == null) {
   return Map.of("active", false);
  }

  var access = authorization.getAccessToken();

  boolean active = access != null
          && !access.isExpired()
          && !access.isInvalidated();

  if (!active) {
   return Map.of("active", false);
  }

  var client = clients.findById(
          authorization.getRegisteredClientId());

  return Map.of(
          "active", true,
          "sub", authorization.getPrincipalName(),
          "client_id", client == null
                  ? "unknown"
                  : client.getClientId(),
          "scope", String.join(
                  " ",
                  access.getToken().getScopes()),
          "expires_at", String.valueOf(
                  access.getToken().getExpiresAt())
  );
 }


    @org.springframework.transaction.annotation.Transactional
    public Map<String, Object> revoke(String token) {
        var authorization = authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) return Map.of("revoked", false, "reason", "not_found");
        authorizations.remove(authorization);
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        audit.record(auth == null ? "unknown" : auth.getName(), "oauth.token.revoke", authorization.getId(), "SUCCESS", Map.of());
        return Map.of("revoked", true);
    }

}


