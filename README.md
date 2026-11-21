# SecureMCP — Enterprise Security & Identity Management Platform

SecureMCP is a Java 21 / Spring Boot 3.5 platform that exposes security and identity capabilities through the official Model Context Protocol Java SDK integration provided by Spring AI. It combines an OAuth 2.0 / OpenID Connect authorization server, JWT validation and revocation, tenant-aware identity and RBAC, ABAC policy decisions, API keys, Keycloak federation, audit events, and STDIO + Streamable HTTP MCP transports.

> **Security status:** This is a substantial reference implementation and deployment foundation, not a certified or independently penetration-tested identity product. Run the tests and review the security notes before deployment. Do not use local development secrets, ephemeral keys, Vault dev mode, or the example Kubernetes secret in production.

## 1. Capabilities

| Area | Implementation |
|---|---|
| MCP | Spring AI MCP tool callbacks backed by the official MCP Java SDK; Streamable HTTP and STDIO profiles |
| OAuth 2.0 / OIDC | Spring Authorization Server; JDBC-backed clients, authorizations and consents; client credentials and authorization-code + PKCE |
| JWT | RS256 signing, JWKS publication, issuer/audience/expiry validation, untrusted decode, Redis `jti` revocation |
| Key management | JWK-set file, PKCS#8/X.509 PEM, or Vault KV v2 JWK-set retrieval; one active private key plus previous public keys |
| Identity | PostgreSQL tenants, users, password hashes, roles and permissions; local form login |
| RBAC | Tenant-scoped role assignment and permission checks |
| ABAC | Tenant-scoped policies, explicit deny precedence, default deny, verified-token/server-derived attributes |
| API keys | High-entropy random keys, SHA-256 hashes at rest, scope grants, expiry and revocation |
| Keycloak | Realm import for local development, OIDC discovery and separate Keycloak JWT validation route |
| Audit | Append-only audit events with a PostgreSQL update/delete guard trigger |
| Operations | Redis rate limiting, Actuator health/metrics, Prometheus registry, Docker hardening and Kubernetes examples |

## 2. Architecture

```text
MCP clients / AI agents / Java services
          |
          +---- STDIO (local process trust boundary)
          |
          +---- Streamable HTTP /mcp (Bearer JWT or X-API-Key)
                         |
                SecureMCP tool layer
        JWT | OAuth | RBAC | ABAC | Identity | Audit | OIDC
                         |
        Spring Authorization Server / Spring Security
                         |
          +--------------+----------------+
          |              |                |
      PostgreSQL       Redis          Keycloak / Vault
      identity,        revocation,     OIDC federation,
      OAuth state,     rate limits     signing JWK secrets
      policy, audit
```

HTTP and STDIO are separate launch profiles. Run two application processes if both transports are needed simultaneously. STDIO is not a network authentication mechanism: its trust boundary is the local operating-system process and its configured `SECUREMCP_STDIO_SCOPES`.

## 3. Requirements

- JDK 21
- Maven 3.9+
- Docker Engine + Docker Compose v2
- `curl` and `jq` for the examples
- Optional: Keycloak 26.x, Vault CLI, Kubernetes

## 4. Local setup

```bash
cp .env.example .env
```

Edit `.env` and replace all `replace-with...` values with long random secrets. Start PostgreSQL and Redis:

```bash
docker compose up -d postgres redis
set -a; source .env; set +a
```

Build and test:

```bash
mvn clean verify
```

Run the HTTP server:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=http
```

Or build and run the executable JAR:

```bash
java -jar target/securemcp-1.0.0.jar --spring.profiles.active=http
```

Health checks:

```bash
curl http://localhost:8080/actuator/health
curl http://localhost:8080/actuator/health/readiness
curl http://localhost:8080/api/public/status
```

Flyway applies `V1`, `V2`, and `V3` automatically. Hibernate schema generation is disabled.

## 5. Bootstrap a tenant and first application client

The bootstrap OAuth client is stored in PostgreSQL and seeded on first start. Configure it using `.env`:

- `SECUREMCP_BOOTSTRAP_CLIENT_ID` (default `securemcp-local-client`)
- `SECUREMCP_BOOTSTRAP_CLIENT_SECRET` (must be changed)

Get a bootstrap token. The bootstrap client has platform-admin and tenant-admin scopes for initial setup only:

```bash
source .env
TOKEN=$(curl -fsS -u "$SECUREMCP_BOOTSTRAP_CLIENT_ID:$SECUREMCP_BOOTSTRAP_CLIENT_SECRET" \
  -d 'grant_type=client_credentials&scope=platform.admin%20identity.write%20identity.read%20security.read%20security.write' \
  http://localhost:8080/oauth2/token | jq -r .access_token)
```

Create a tenant:

```bash
TENANT=$(curl -fsS -X POST http://localhost:8080/api/v1/tenants \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"tenantKey":"acme","displayName":"Acme Ltd"}')
TENANT_ID=$(echo "$TENANT" | jq -r .id)
```

Create the first tenant user:

```bash
curl -fsS -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"tenantId\":\"$TENANT_ID\",\"username\":\"admin@acme.example\",\"password\":\"Replace-With-A-Long-Password-2026!\"}"
```

Create a tenant-scoped OAuth client. Its secret is returned once only:

```bash
curl -fsS -X POST http://localhost:8080/api/v1/oauth-clients \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"tenantId\":\"$TENANT_ID\",\"clientId\":\"acme-agent\",\"name\":\"Acme AI Agent\",\"scopes\":[\"security.read\",\"security.write\",\"identity.read\",\"identity.write\"],\"allowClientCredentials\":true,\"allowAuthorizationCode\":false}"
```

Save the returned `clientSecret` in a secret manager. The resulting client-credentials access tokens carry a verified `tenant_id` claim based on the server-side client-to-tenant mapping.

**Important bootstrap cleanup:** create and verify a tenant-scoped admin/client first. Then use the bootstrap token to delete the bootstrap client with `DELETE /api/v1/oauth-clients/securemcp-local-client?tenantId=$TENANT_ID`, set `SECUREMCP_BOOTSTRAP_ENABLED=false`, and restart. In production, keep the bootstrap client disabled after initial provisioning; do not leave `platform.admin` on routine agent credentials.

### OAuth token request

```bash
curl -u 'acme-agent:CLIENT_SECRET_FROM_CREATION' \
  -d 'grant_type=client_credentials&scope=security.read' \
  http://localhost:8080/oauth2/token
```

### Authorization Code + PKCE

Register a client with `allowAuthorizationCode: true` and exact redirect URIs. SecureMCP requires PKCE for these clients. Start the standard authorization request at `/oauth2/authorize` with `response_type=code`, `client_id`, exact `redirect_uri`, `scope=openid profile email`, `state`, `code_challenge`, and `code_challenge_method=S256`. The user authenticates through the local Spring Security login page. Exchange the code at `/oauth2/token` using the matching `code_verifier`. Do not use implicit flow or resource-owner-password credentials.

## 6. REST API overview

All `/api/v1/**` routes require a scoped bearer token or an `X-API-Key` with the appropriate scopes. Tenant operations compare the requested tenant with the verified `tenant_id` claim or API-key tenant. A principal with `platform.admin` can bootstrap tenant resources.

| Method | Endpoint | Required scope | Purpose |
|---|---|---|---|
| POST | `/api/v1/tenants` | `platform.admin` | Create tenant |
| POST | `/api/v1/users` | `identity.write` | Create tenant user |
| GET | `/api/v1/tenants/{tenantId}/users` | `identity.read` | List tenant users |
| PATCH | `/api/v1/users/{userId}/status` | `identity.write` | Enable/disable tenant user |
| POST | `/api/v1/roles` | `identity.write` | Create role |
| POST | `/api/v1/roles/assign` | `identity.write` | Assign tenant role |
| POST | `/api/v1/roles/permissions` | `identity.write` | Grant permission to tenant role |
| POST / DELETE | `/api/v1/oauth-clients` | `identity.write` / `platform.admin` for bootstrap cleanup | Register or delete tenant OAuth client |
| POST / DELETE | `/api/v1/api-keys` | `identity.write` | Create/revoke API key |
| POST | `/api/v1/policies` | `identity.write` | Create ABAC policy |
| POST | `/api/v1/policies/decision` | `security.read` | Evaluate ABAC policy |
| GET | `/api/v1/audit-events` | `security.read` | Read append-only audit events |
| GET | `/api/v1/federation/keycloak/me` | Keycloak JWT | Validate Keycloak JWT and return safe identity claims |

### Create an API key

First obtain a tenant-administration token from the tenant OAuth client:

```bash
TENANT_ADMIN_TOKEN=$(curl -fsS -u "acme-agent:CLIENT_SECRET_FROM_CREATION" \
  -d 'grant_type=client_credentials&scope=identity.write' http://localhost:8080/oauth2/token | jq -r .access_token)
```

Then create the key (the raw value is returned once):

```bash
curl -X POST http://localhost:8080/api/v1/api-keys \
  -H "Authorization: Bearer $TENANT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"tenantId\":\"$TENANT_ID\",\"label\":\"build-agent\",\"scopes\":[\"security.read\"],\"expiresAt\":\"2027-01-01T00:00:00Z\"}"
```

The raw API key is shown once. Store it securely and send it as `X-API-Key`. Only its SHA-256 hash is stored in PostgreSQL.

### Create an ABAC policy

```json
{
  "tenantId": "TENANT_UUID",
  "policyKey": "engineering-documents-read",
  "effect": "ALLOW",
  "subjectMatch": "*",
  "actionMatch": "document.read",
  "resourceMatch": "engineering/*",
  "requiredAttributes": {"department": "engineering"}
}
```

Policies use exact/wildcard action and resource matching. Explicit matching DENY rules are evaluated before ALLOW rules. The default is DENY. Attribute values are taken from verified JWT claims and server-side identity context, not from the model's tool arguments. Resource-specific attributes should be obtained from a trusted resource/attribute service before extending the policy model.

## 7. OAuth / OIDC endpoints

The Spring Authorization Server exposes standard protocol endpoints, including:

- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`
- `GET /oauth2/authorize`
- `POST /oauth2/token`
- `POST /oauth2/introspect`
- `POST /oauth2/revoke`
- OIDC UserInfo and logout endpoints when enabled by the authorization-server configuration

Registered clients, authorization state and consent records use JDBC repositories. Client secrets are stored using BCrypt. Refresh-token reuse is disabled for registered clients. Apply database-at-rest encryption and backups; authorization records contain token material needed by the authorization server.

## 8. MCP tools

Tool method names are exposed by Spring AI's method tool callback provider; inspect the actual published names and schemas with MCP Inspector for the pinned dependency version.

| Tool method | Purpose | Required scope |
|---|---|---|
| `jwtDecode` | Decode header/payload as untrusted data | `security.read` |
| `jwtValidate` | Verify signature, issuer, audience, expiry and revocation | `security.read` |
| `jwtRevoke` | Revoke by `jti` with bounded TTL and confirmation | `security.write` |
| `checkPermission` | Check authenticated principal's RBAC permission | `security.read` |
| `listTenantUsers` | List users in authenticated tenant | `identity.read` |
| `assignRole` | Assign a role with confirmation and tenant checks | `identity.write` |
| `authorizeResource` | Evaluate ABAC using trusted claims/context | `security.read` |
| `oauthIntrospect` | Introspect caller's own access token | `security.read` |
| `oauthRevoke` | Revoke caller's own access token after confirmation | `security.write` |
| `oidcDiscover` | Read Keycloak discovery metadata after confirmation | `security.read` |
| `recentSecurityEvents` | Read recent audit events | `security.read` |

The MCP layer intentionally does not provide a tool that allows an LLM to mint arbitrary JWTs, create client secrets, or retrieve private signing keys. Token issuance is performed through the OAuth protocol endpoints. Never paste production bearer tokens or API keys into an untrusted model conversation.

## 9. Streamable HTTP MCP

Endpoint: `http://localhost:8080/mcp` (use HTTPS outside local development). The HTTP MCP endpoint requires a valid SecureMCP JWT or API key with `security.read`. Tool methods independently enforce scopes for privileged operations.

Example client configuration is in `mcp-client.example.json`. Replace the bearer token placeholder with a short-lived token from the OAuth endpoint. Configure `MCP_ALLOWED_ORIGINS` and `MCP_ALLOWED_HOSTS` for the actual public console and hostnames. The origin/host guard is intentionally strict; set exact values when running behind a reverse proxy.

## 10. STDIO MCP

Build first, then launch as a local process:

```bash
mvn clean package
export SECUREMCP_STDIO_SCOPES=security.read
java -jar target/securemcp-1.0.0.jar --spring.profiles.active=stdio
```

Example client configuration: `mcp-client-stdio.example.json`. STDIO uses a configured local process principal and is trusted only to the extent that the OS user, executable, environment and parent MCP client are trusted. Default local scope is read-only (`security.read`). Grant write scopes only to a dedicated, isolated process after review. STDIO and HTTP can run as separate processes at the same time.

## 11. Key management and rotation

### Development ephemeral key

The default local profile generates a fresh 3072-bit RSA key at startup. Restarting invalidates previously issued tokens. This is development-only.

### Generate a persistent JWK set

```bash
./scripts/generate-jwkset.sh ./secrets/securemcp-jwks.json
```

Protect the file (mode `0600`), exclude it from source control, mount it as a secret and set:

```bash
SECUREMCP_ALLOW_EPHEMERAL_KEYS=false
SECUREMCP_JWK_SET_FILE=/run/secrets/securemcp-jwks.json
```

The JWK set must contain exactly one RSA private signing key. Previous signing keys can remain in the same set as public-only JWKs so verifiers continue to validate unexpired tokens. Rotation procedure: generate a new key, add the old key as public-only, make the new key the sole private key, deploy the new JWK set, verify `/oauth2/jwks`, wait at least the maximum token lifetime plus clock skew, then remove the retired public key.

### Vault KV v2

SecureMCP can read a JWK-set JSON string from Vault KV v2 at `secret/data/securemcp/signing`, field `jwkSet`. Set `VAULT_ENABLED=true`, `VAULT_ADDR`, `VAULT_TOKEN`, and `VAULT_JWK_PATH`. Use a short-lived Vault token with read-only access to that one path. The included Vault Compose profile is dev mode only:

```bash
docker compose --profile vault-dev up -d vault
./scripts/generate-jwkset.sh ./secrets/securemcp-jwks.json
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=local-vault-dev-token \
  JWK_SET_FILE=./secrets/securemcp-jwks.json ./scripts/bootstrap-vault-dev.sh
```

For production use Vault TLS, auth methods (Kubernetes/JWT/AppRole), policy-scoped short-lived tokens, audit devices, HA storage and backups. This implementation retrieves key material from Vault KV; it does not use Vault Transit/HSM-backed remote signing.

## 12. Keycloak development federation

The included realm is imported automatically:

```bash
docker compose --profile keycloak up -d keycloak
```

Set `KEYCLOAK_ENABLED=true` and restart SecureMCP. For local host-run mode, leave `KEYCLOAK_JWKS_URI` and `KEYCLOAK_DISCOVERY_URI` at their localhost defaults; for the Compose application container, Compose sets the internal Keycloak service URLs. The externally visible issuer is `http://localhost:8180/realms/securemcp`; the SecureMCP container fetches signing keys and discovery metadata over the internal `keycloak:8180` service address. The imported realm adds the `securemcp-api` audience mapper. Keep the issuer identical to the `iss` claim in tokens, while configuring an internally reachable JWKS URL for the server. SecureMCP validates Keycloak-issued JWTs on a separate route:

```bash
curl -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" \
  http://localhost:8080/api/v1/federation/keycloak/me
```

This is external token validation and a safe identity-claims endpoint; it does not automatically provision/federate Keycloak users into the SecureMCP user database or make Keycloak the SecureMCP authorization server. Configure production Keycloak TLS, clients, roles, MFA, user federation and claim mapping separately.

## 13. Docker deployment

After editing `.env`:

```bash
docker compose up -d --build
 docker compose logs -f securemcp
```

The Compose application container runs non-root, drops Linux capabilities, uses a read-only root filesystem and binds published ports to loopback by default. Put a TLS reverse proxy in front for remote access. Do not expose PostgreSQL, Redis, Keycloak dev or Vault dev ports publicly.

## 14. Kubernetes deployment

Manifests are in `k8s/`:

- `securemcp.yaml`: ConfigMap, hardened Deployment, Service and HPA
- `securemcp-secrets.example.yaml`: placeholder secret template (never commit real values)
- `ingress.yaml`: TLS ingress example
- `network-policy.yaml`: namespace-based traffic restrictions

Use managed PostgreSQL/Redis with TLS, Vault with Kubernetes authentication, an external secret operator, TLS ingress, a real image registry, image-signature verification, resource limits and a dedicated namespace. Review NetworkPolicy namespace labels and database/cache service placement for your cluster before applying.

```bash
kubectl apply -f k8s/securemcp.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/network-policy.yaml
```

Create `securemcp-secrets` using your cluster secret manager before applying the Deployment.

## 15. Tests and verification

```bash
mvn test
mvn verify
```

Unit tests cover untrusted JWT decoding, JWT validation/revocation decisions and tenant isolation. The environment used to assemble this source did not have Maven available, so compilation and test execution have **not** been verified here. Run the commands above in a Java 21/Maven environment before relying on the build. Add CI integration tests with Testcontainers for PostgreSQL/Redis and protocol tests for OAuth PKCE, refresh-token rotation/reuse, client-secret authentication, API-key expiry/revocation, Keycloak issuer/audience validation, all tenant boundaries, MCP HTTP auth and STDIO scope restrictions.

## 16. Production readiness checklist

- [ ] Build and run the full test suite in CI; pin and scan all dependencies; generate an SBOM.
- [ ] Use HTTPS end-to-end or TLS termination with a trusted proxy; configure exact issuer, host and origin values.
- [ ] Set `SECUREMCP_ALLOW_EPHEMERAL_KEYS=false`; load signing JWKs from Vault/KMS/HSM; test overlap rotation and disaster recovery.
- [ ] Replace Vault KV signing material with Transit/HSM signing if private-key export is prohibited by policy.
- [ ] Configure production Keycloak federation, MFA, account recovery, email verification and lifecycle workflows.
- [ ] Add login failure lockout, per-client/per-subject rate limits, anomaly detection and alerting. Current Redis rate limiting is IP-based (120 requests/minute) on MCP, API, OAuth and login paths.
- [ ] Validate OAuth authorization code state, PKCE, redirect URIs, refresh rotation and reuse detection with conformance tests.
- [ ] Configure DB encryption at rest, backups, restricted database roles and retention policies. OAuth authorization records contain tokens.
- [ ] Add tenant-aware integration tests for every repository, controller and MCP tool. Never trust model-supplied identity or authorization attributes.
- [ ] Review API-key lifecycle, scope issuance, expiry, rotation, and incident revocation.
- [ ] Configure audit export to tamper-resistant external storage/SIEM; the database trigger is not protection against a database administrator.
- [ ] Run independent penetration testing, MCP prompt-injection/tool-confusion testing, threat modeling and operational incident exercises.

## 17. Project layout

```text
securemcp/
├── src/main/java/com/securemcp/
│   ├── api/             REST controllers and exception handling
│   ├── audit/           append-only audit service
│   ├── authorization/   RBAC, ABAC and tenant context
│   ├── config/          OAuth, JWT, Spring Security, filters, MCP profiles
│   ├── identity/        tenant/user/role and API-key services
│   ├── jwt/             JWT inspection, validation and revocation
│   ├── mcp/             MCP tool implementations
│   ├── oauth/           OAuth authorization management
│   └── tools/           JWK bootstrap utility
├── src/main/resources/db/migration/  Flyway schema migrations
├── keycloak/            Keycloak realm import
├── scripts/             JWK and Vault bootstrap scripts
├── k8s/                 Kubernetes deployment examples
├── Dockerfile
└── docker-compose.yml
```

## 18. References

- Spring AI MCP server: https://docs.spring.io/spring-ai/reference/api/mcp/mcp-server-boot-starter-docs.html
- Official MCP Java SDK: https://java.sdk.modelcontextprotocol.io/
- Spring Authorization Server: https://docs.spring.io/spring-authorization-server/reference/
- Spring Security OAuth2 Resource Server: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html
- Keycloak: https://www.keycloak.org/documentation
- HashiCorp Vault: https://developer.hashicorp.com/vault/docs
