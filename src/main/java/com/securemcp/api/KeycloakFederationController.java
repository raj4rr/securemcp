package com.securemcp.api;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty; import org.springframework.security.core.annotation.AuthenticationPrincipal; import org.springframework.security.oauth2.jwt.Jwt; import org.springframework.web.bind.annotation.*; import java.util.*;
@RestController @RequestMapping("/api/v1/federation/keycloak") @ConditionalOnProperty(prefix="securemcp.keycloak",name="enabled",havingValue="true")
public class KeycloakFederationController {
 @GetMapping("/me") public Map<String,Object> me(@AuthenticationPrincipal Jwt jwt){Map<String,Object> out=new LinkedHashMap<>();out.put("authenticated",true);out.put("subject",jwt.getSubject());out.put("issuer",String.valueOf(jwt.getIssuer()));out.put("audience",jwt.getAudience());out.put("expiresAt",String.valueOf(jwt.getExpiresAt()));out.put("preferredUsername",jwt.getClaimAsString("preferred_username"));return out;}
}
