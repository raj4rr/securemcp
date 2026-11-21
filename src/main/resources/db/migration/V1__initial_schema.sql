CREATE TABLE tenants (
  id UUID PRIMARY KEY,
  tenant_key VARCHAR(100) NOT NULL UNIQUE,
  display_name VARCHAR(200) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE app_users (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  username VARCHAR(190) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, username)
);
CREATE TABLE roles (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  name VARCHAR(100) NOT NULL,
  UNIQUE (tenant_id, name)
);
CREATE TABLE permissions (
  id UUID PRIMARY KEY,
  permission_key VARCHAR(150) NOT NULL UNIQUE,
  description VARCHAR(500)
);
CREATE TABLE user_roles (
  user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, role_id)
);
CREATE TABLE role_permissions (
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY(role_id, permission_id)
);
CREATE TABLE oauth_clients (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  client_id VARCHAR(190) NOT NULL UNIQUE,
  client_secret_hash VARCHAR(255),
  grant_types TEXT NOT NULL,
  scopes TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE signing_keys (
  id UUID PRIMARY KEY,
  key_id VARCHAR(190) NOT NULL UNIQUE,
  algorithm VARCHAR(20) NOT NULL,
  public_jwk JSONB NOT NULL,
  secret_reference VARCHAR(500) NOT NULL,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID REFERENCES tenants(id),
  actor VARCHAR(190),
  action VARCHAR(150) NOT NULL,
  resource VARCHAR(300),
  outcome VARCHAR(30) NOT NULL,
  source_ip INET,
  correlation_id VARCHAR(100),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_events_created_at ON audit_events(created_at DESC);
CREATE INDEX idx_audit_events_actor ON audit_events(actor);
CREATE INDEX idx_users_tenant ON app_users(tenant_id);
