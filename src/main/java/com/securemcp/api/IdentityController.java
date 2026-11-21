package com.securemcp.api;

import com.securemcp.identity.IdentityService; import com.securemcp.authorization.TenantContext;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController @RequestMapping("/api/v1")
public class IdentityController {
 private final IdentityService service; private final TenantContext tenant; public IdentityController(IdentityService s,TenantContext t){service=s;tenant=t;}
 public record TenantRequest(@NotBlank @Size(max=100) String tenantKey,@NotBlank @Size(max=200) String displayName){}
 public record UserRequest(@NotNull UUID tenantId,@NotBlank @Size(max=190) String username,@NotBlank @Size(min=12,max=72) String password){}
 public record RoleRequest(@NotNull UUID tenantId,@NotBlank @Size(max=100) String name){}
 public record AssignRoleRequest(@NotNull UUID tenantId,@NotNull UUID userId,@NotNull UUID roleId){}
 public record UserStatusRequest(@NotNull UUID tenantId,@NotNull Boolean enabled){}
 public record PermissionRequest(@NotNull UUID tenantId,@NotNull UUID roleId,@NotBlank String permissionKey,@Size(max=500) String description){}
 @PostMapping("/tenants") @ResponseStatus(HttpStatus.CREATED) public Map<String,Object> tenant(@Valid @RequestBody TenantRequest r){return service.createTenant(r.tenantKey(),r.displayName());}
 @PostMapping("/users") @ResponseStatus(HttpStatus.CREATED) public Map<String,Object> user(@Valid @RequestBody UserRequest r){return service.createUser(tenant.requireTenant(r.tenantId()),r.username(),r.password());}
 @PatchMapping("/users/{userId}/status") @ResponseStatus(HttpStatus.NO_CONTENT) public void userStatus(@PathVariable UUID userId,@Valid @RequestBody UserStatusRequest r){service.setUserEnabled(tenant.requireTenant(r.tenantId()),userId,r.enabled());}
 @GetMapping("/tenants/{tenantId}/users") public List<Map<String,Object>> users(@PathVariable UUID tenantId){tenant.requireTenant(tenantId);return service.listUsers(tenantId);}
 @PostMapping("/roles") @ResponseStatus(HttpStatus.CREATED) public Map<String,Object> role(@Valid @RequestBody RoleRequest r){return service.createRole(tenant.requireTenant(r.tenantId()),r.name());}
 @PostMapping("/roles/assign") @ResponseStatus(HttpStatus.NO_CONTENT) public void assign(@Valid @RequestBody AssignRoleRequest r){UUID tenantId=tenant.requireTenant(r.tenantId());service.assignRole(tenantId,r.userId(),r.roleId());}
 @PostMapping("/roles/permissions") @ResponseStatus(HttpStatus.NO_CONTENT) public void permission(@Valid @RequestBody PermissionRequest r){UUID tenantId=tenant.requireTenant(r.tenantId());service.definePermission(r.permissionKey(),r.description());service.grantPermission(tenantId,r.roleId(),r.permissionKey());}
}
