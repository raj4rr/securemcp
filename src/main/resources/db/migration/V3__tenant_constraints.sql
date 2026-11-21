-- Usernames are globally unique because the local authentication provider resolves by username.
CREATE UNIQUE INDEX ux_app_users_username_global ON app_users(lower(username));
CREATE INDEX ix_oauth_clients_tenant ON oauth_clients(tenant_id);
