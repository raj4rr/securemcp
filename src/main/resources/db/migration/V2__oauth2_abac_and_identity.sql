-- Spring Authorization Server JDBC schema (PostgreSQL-compatible)
CREATE TABLE oauth2_registered_client (
 id varchar(100) PRIMARY KEY, client_id varchar(100) NOT NULL, client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
 client_secret varchar(200), client_secret_expires_at timestamp, client_name varchar(200) NOT NULL,
 client_authentication_methods varchar(1000) NOT NULL, authorization_grant_types varchar(1000) NOT NULL,
 redirect_uris varchar(1000), post_logout_redirect_uris varchar(1000), scopes varchar(1000) NOT NULL,
 client_settings varchar(2000) NOT NULL, token_settings varchar(2000) NOT NULL
);
CREATE UNIQUE INDEX ux_oauth2_registered_client_client_id ON oauth2_registered_client(client_id);
CREATE TABLE oauth2_authorization (
 id varchar(100) PRIMARY KEY, registered_client_id varchar(100) NOT NULL, principal_name varchar(200) NOT NULL,
 authorization_grant_type varchar(100) NOT NULL, authorized_scopes varchar(1000), attributes text,
 state varchar(500), authorization_code_value text, authorization_code_issued_at timestamp,
 authorization_code_expires_at timestamp, authorization_code_metadata text,
 access_token_value text, access_token_issued_at timestamp, access_token_expires_at timestamp,
 access_token_metadata text, access_token_type varchar(100), access_token_scopes varchar(1000),
 oidc_id_token_value text, oidc_id_token_issued_at timestamp, oidc_id_token_expires_at timestamp, oidc_id_token_metadata text,
 refresh_token_value text, refresh_token_issued_at timestamp, refresh_token_expires_at timestamp, refresh_token_metadata text,
 user_code_value text, user_code_issued_at timestamp, user_code_expires_at timestamp, user_code_metadata text,
 device_code_value text, device_code_issued_at timestamp, device_code_expires_at timestamp, device_code_metadata text
);
CREATE INDEX ix_oauth2_authorization_registered_client ON oauth2_authorization(registered_client_id);
CREATE INDEX ix_oauth2_authorization_principal ON oauth2_authorization(principal_name);
CREATE TABLE oauth2_authorization_consent (
 registered_client_id varchar(100) NOT NULL, principal_name varchar(200) NOT NULL,
 authorities varchar(1000) NOT NULL, PRIMARY KEY(registered_client_id,principal_name)
);
CREATE TABLE abac_policies (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 policy_key varchar(150) NOT NULL, effect varchar(10) NOT NULL CHECK(effect IN ('ALLOW','DENY')),
 subject_match varchar(190), action_match varchar(150) NOT NULL, resource_match varchar(300) NOT NULL,
 required_attributes jsonb NOT NULL DEFAULT '{}'::jsonb, enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,policy_key)
);
CREATE INDEX ix_abac_policy_lookup ON abac_policies(tenant_id,action_match,resource_match) WHERE enabled=true;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS registered_client_id varchar(100);
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS email varchar(320);
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS request_id varchar(100);
CREATE INDEX IF NOT EXISTS ix_audit_action_time ON audit_events(action,created_at DESC);
CREATE TABLE api_keys (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 key_prefix varchar(20) NOT NULL, secret_hash char(64) NOT NULL UNIQUE, label varchar(150) NOT NULL,
 scopes text NOT NULL, expires_at timestamptz, revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_api_keys_prefix ON api_keys(key_prefix) WHERE revoked_at IS NULL;
CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_events are append-only'; END; $$;
CREATE TRIGGER trg_audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
