package com.securemcp.identity;

import com.securemcp.audit.AuditService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class IdentityService {
    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;
    private final AuditService audit;

    public IdentityService(JdbcTemplate jdbc, PasswordEncoder encoder, AuditService audit) {
        this.jdbc = jdbc;
        this.encoder = encoder;
        this.audit = audit;
    }

    @Transactional
    public Map<String, Object> createTenant(String key, String name) {
        UUID id = UUID.randomUUID();
        jdbc.update("insert into tenants(id,tenant_key,display_name) values (?,?,?)", id, key, name);
        audit.record("system", "tenant.create", key, "SUCCESS", Map.of("tenantId", id));
        return Map.of("id", id, "tenantKey", key, "displayName", name);
    }

    @Transactional
    public Map<String, Object> createUser(UUID tenantId, String username, String password) {
        if (password == null || password.length() < 12 || password.length() > 72)
            throw new IllegalArgumentException("Password must contain 12 to 72 characters");
        UUID id = UUID.randomUUID();
        jdbc.update("insert into app_users(id,tenant_id,username,password_hash) values (?,?,?,?)", id, tenantId, username, encoder.encode(password));
        audit.record("system", "user.create", id.toString(), "SUCCESS", Map.of("tenantId", tenantId, "username", username));
        return Map.of("id", id, "tenantId", tenantId, "username", username);
    }

    @Transactional
    public Map<String, Object> createRole(UUID tenantId, String name) {
        UUID id = UUID.randomUUID();
        jdbc.update("insert into roles(id,tenant_id,name) values (?,?,?)", id, tenantId, name);
        audit.record("authenticated-principal", "role.create", id.toString(), "SUCCESS", Map.of("tenantId", tenantId, "name", name));
        return Map.of("id", id, "tenantId", tenantId, "name", name);
    }

    @Transactional
    public void assignRole(UUID tenantId, UUID userId, UUID roleId) {
        Integer same = jdbc.queryForObject("select count(*) from app_users u join roles r on r.tenant_id=u.tenant_id where u.id=? and r.id=? and u.tenant_id=?", Integer.class, userId, roleId, tenantId);
        if (same == null || same != 1)
            throw new IllegalArgumentException("User and role must belong to the same tenant");
        jdbc.update("insert into user_roles(user_id,role_id) values (?,?) on conflict do nothing", userId, roleId);
        audit.record("authenticated-principal", "role.assign", userId.toString(), "SUCCESS", Map.of("tenantId", tenantId, "roleId", roleId));
    }

    @Transactional
    public void definePermission(String key, String description) {
        jdbc.update("insert into permissions(permission_key,description) values (?,?) on conflict(permission_key) do nothing", key, description);
    }

    @Transactional
    public void grantPermission(UUID tenantId, UUID roleId, String permission) {
        Integer owned = jdbc.queryForObject("select count(*) from roles where id=? and tenant_id=?", Integer.class, roleId, tenantId);
        if (owned == null || owned != 1)
            throw new IllegalArgumentException("Role does not belong to authenticated tenant");
        jdbc.update("insert into role_permissions(role_id,permission_id) select ?,id from permissions where permission_key=? on conflict do nothing", roleId, permission);
        audit.record("authenticated-principal", "permission.grant", roleId.toString(), "SUCCESS", Map.of("tenantId", tenantId, "permission", permission));
    }

    public boolean hasPermission(String subject, String permission) {
        if (subject == null || permission == null) return false;
        try {
            return jdbc.queryForObject("select exists(select 1 from app_users u join user_roles ur on ur.user_id=u.id join role_permissions rp on rp.role_id=ur.role_id join permissions p on p.id=rp.permission_id where u.username=? and u.enabled=true and p.permission_key=?)", Boolean.class, subject, permission);
        } catch (Exception e) {
            return false;
        }
    }

    @Transactional
    public void setUserEnabled(UUID tenantId, UUID userId, boolean enabled) {
        int changed = jdbc.update("update app_users set enabled=?,updated_at=now() where id=? and tenant_id=?", enabled, userId, tenantId);
        if (changed != 1) throw new IllegalArgumentException("User not found in authenticated tenant");
        audit.record("authenticated-principal", "user.status", userId.toString(), "SUCCESS", Map.of("tenantId", tenantId, "enabled", enabled));
    }

    public List<Map<String, Object>> listUsers(UUID tenantId) {
        return jdbc.queryForList("select id,tenant_id,username,enabled,created_at from app_users where tenant_id=? order by username", tenantId);
    }
}
