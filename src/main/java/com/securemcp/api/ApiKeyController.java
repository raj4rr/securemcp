package com.securemcp.api;
import com.securemcp.identity.ApiKeyService; import com.securemcp.authorization.TenantContext; import jakarta.validation.Valid; import jakarta.validation.constraints.*; import org.springframework.http.HttpStatus; import org.springframework.web.bind.annotation.*; import java.time.Instant; import java.util.*;
@RestController @RequestMapping("/api/v1/api-keys") public class ApiKeyController {
 private final ApiKeyService keys;private final TenantContext tenant;public ApiKeyController(ApiKeyService k,TenantContext t){keys=k;tenant=t;}
 public record CreateRequest(@NotNull UUID tenantId,@NotBlank @jakarta.validation.constraints.Size(max=150) String label,@NotEmpty @jakarta.validation.constraints.Size(max=4) Set<String> scopes,Instant expiresAt){}
 @PostMapping @ResponseStatus(HttpStatus.CREATED) public Map<String,Object> create(@Valid @RequestBody CreateRequest r){return keys.create(tenant.requireTenant(r.tenantId()),r.label(),r.scopes(),r.expiresAt());}
 @DeleteMapping("/{id}") @ResponseStatus(HttpStatus.NO_CONTENT) public void revoke(@PathVariable UUID id,@RequestParam UUID tenantId){keys.revoke(tenant.requireTenant(tenantId),id);}
}
