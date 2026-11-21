# SecureMCP security model

## Trust boundaries

1. **HTTP transport:** Streamable HTTP requests to `/mcp` require a signed SecureMCP bearer token or a scoped API key. Host and Origin are checked against explicit allowlists. Reverse proxies must preserve the expected host and use TLS.
2. **STDIO transport:** STDIO is a local process boundary, not remote authentication. A local principal is assigned configured `SECUREMCP_STDIO_SCOPES`; default is `security.read`. The process and parent client must run under a dedicated OS identity.
3. **Tool authorization:** MCP tools use method-level scope checks. Destructive actions such as JWT revocation and role assignment require explicit confirmation parameters. The LLM cannot request private keys or mint arbitrary signed JWTs.
4. **JWT validation:** RS256 only; validate signature via configured JWKS, issuer, audience, expiry and not-before using Spring Security's decoder. `jwtDecode` is explicitly untrusted and never suitable for authorization.
5. **Revocation:** Redis stores `jti` deny-list entries with TTL. Callers must provide a bounded remaining lifetime. The OAuth revocation operation removes the corresponding authorization record from the JDBC authorization service.
6. **OAuth persistence:** Registered clients, authorization state and consent use JDBC-backed Spring Authorization Server repositories. Client secrets are BCrypt-encoded. Authorization records persist token material and require database protection.
7. **Signing keys:** JWK source supports one active RSA private key and previous public-only keys, loaded from a JWK-set file, PEM values or Vault KV v2. Ephemeral startup keys are for local development only. Vault KV is not non-exportable Transit/HSM signing.
8. **Identity:** Passwords are BCrypt-encoded. Usernames are globally unique because local form authentication resolves a username without a tenant selector. Account lockout, MFA, password recovery and email verification are not yet implemented.
9. **Tenant isolation:** Tenant-scoped API operations compare the requested tenant with a verified JWT `tenant_id` claim or API-key tenant context. `platform.admin` is a privileged bootstrap scope. ABAC defaults to DENY, checks DENY policies first, and uses verified token/server context attributes only.
10. **API keys:** 256-bit random values are prefixed `sk_live_`; only SHA-256 hashes are stored. Keys are scoped, can expire and can be revoked. Raw values are returned once.
11. **Rate limiting:** Redis applies an IP-based 120-request/minute fixed window to MCP, API, OAuth and login routes. It fails closed when Redis is unavailable. It is not a replacement for per-user/per-client quotas or WAF controls.
12. **Audit:** Security actions are appended to PostgreSQL audit_events. A trigger blocks application-level UPDATE/DELETE; DB owners can still alter data. Export to tamper-resistant storage/SIEM for production.

## Known limitations / production work

- Not independently audited or certified; Maven compilation and tests must be run in CI before deployment.
- Vault integration reads an exported JWK set from KV v2. Use Vault Transit/HSM remote signing where key export is prohibited.
- Keycloak integration validates external JWTs and exposes discovery metadata; automated user provisioning, SSO session federation and role/claim synchronization are not implemented.
- Local Spring form login has no MFA, recovery, email verification, lockout or risk-based authentication.
- Refresh-token rotation is configured for registered clients, but refresh-token family reuse detection and incident response workflows need integration tests and further implementation.
- ABAC supports exact/wildcard action/resource matching and equality-based verified attributes. Complex policy language, external attribute sources and policy simulation are future extensions.
- API-key quotas are IP-windowed at transport level; add per-client/per-key limits and usage reporting.
- Audit records need external immutable retention, privacy review and retention configuration.
- Production must use TLS, managed Postgres/Redis, secrets management, backups, observability, dependency scanning, SBOM, container signing, penetration testing and OAuth/OIDC/MCP conformance testing.
