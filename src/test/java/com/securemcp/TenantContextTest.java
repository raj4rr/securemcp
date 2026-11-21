package com.securemcp;
import com.securemcp.authorization.TenantContext; import org.junit.jupiter.api.*; import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; import org.springframework.security.core.authority.SimpleGrantedAuthority; import org.springframework.security.core.context.SecurityContextHolder; import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class TenantContextTest {
 private final TenantContext tenant=new TenantContext(); private final UUID tenantA=UUID.randomUUID(),tenantB=UUID.randomUUID();
 @AfterEach void clear(){SecurityContextHolder.clearContext();}
 @Test void tenantScopedPrincipalCannotCrossTenant(){var a=new UsernamePasswordAuthenticationToken("svc",null,List.of(new SimpleGrantedAuthority("SCOPE_identity.write")));a.setDetails(Map.of("tenantId",tenantA.toString()));SecurityContextHolder.getContext().setAuthentication(a);assertEquals(tenantA,tenant.requireTenant(tenantA));assertThrows(org.springframework.security.access.AccessDeniedException.class,()->tenant.requireTenant(tenantB));}
 @Test void platformAdminCanBootstrapTenant(){var a=new UsernamePasswordAuthenticationToken("admin",null,List.of(new SimpleGrantedAuthority("SCOPE_platform.admin")));SecurityContextHolder.getContext().setAuthentication(a);assertEquals(tenantB,tenant.requireTenant(tenantB));}
 @Test void missingTenantFailsClosed(){var a=new UsernamePasswordAuthenticationToken("svc","n/a");SecurityContextHolder.getContext().setAuthentication(a);assertThrows(org.springframework.security.access.AccessDeniedException.class,()->tenant.requireTenant(tenantA));}
}
