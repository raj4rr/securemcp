package com.securemcp.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.boot.ApplicationRunner;
import java.security.*;
import java.security.interfaces.*;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {
 @Bean @Order(0) SecurityFilterChain authorizationServerSecurity(HttpSecurity http,RedisRateLimitFilter rateLimit) throws Exception {
   OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
   http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults())
     .tokenIntrospectionEndpoint(Customizer.withDefaults())
     .tokenRevocationEndpoint(Customizer.withDefaults());
   http.exceptionHandling(e->e.authenticationEntryPoint((req,res,ex)->res.sendRedirect("/login")))
     .addFilterBefore(rateLimit,org.springframework.security.web.context.SecurityContextHolderFilter.class);
   return http.build();
 }
 @Bean RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc){return new JdbcRegisteredClientRepository(jdbc);}
 @Bean OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc,RegisteredClientRepository clients){return new JdbcOAuth2AuthorizationService(jdbc,clients);}
 @Bean OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbc,RegisteredClientRepository clients){return new JdbcOAuth2AuthorizationConsentService(jdbc,clients);}
 @Bean ApplicationRunner seedClient(RegisteredClientRepository repo,PasswordEncoder encoder,
    @Value("${SECUREMCP_BOOTSTRAP_CLIENT_ID:securemcp-local-client}") String id,
    @Value("${SECUREMCP_BOOTSTRAP_CLIENT_SECRET:change-this-local-secret-now}") String secret,
    @Value("${SECUREMCP_BOOTSTRAP_ENABLED:true}") boolean enabled){return args->{
      if(!enabled)return;
      if(repo.findByClientId(id)==null){RegisteredClient c=RegisteredClient.withId(UUID.randomUUID().toString()).clientId(id)
        .clientSecret(encoder.encode(secret)).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("security.read").scope("security.write").scope("identity.read").scope("identity.write").scope("platform.admin").scope("openid").scope("profile").scope("email")
        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).reuseRefreshTokens(false).build())
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build()).build(); repo.save(c);}
    };}
 @Bean JWKSource<SecurityContext> jwkSource(@Value("${securemcp.keys.jwk-set-file:}") String jwkSetFile,
     @Value("${securemcp.keys.private-key-pkcs8:}") String privatePem,
     @Value("${securemcp.keys.public-key-x509:}") String publicPem,
     @Value("${SECUREMCP_ALLOW_EPHEMERAL_KEYS:true}") boolean allowEphemeralKeys,
     @Value("${securemcp.vault.enabled:false}") boolean vaultEnabled,
     @Value("${VAULT_ADDR:http://localhost:8200}") String vaultAddress,
     @Value("${VAULT_TOKEN:}") String vaultToken,
     @Value("${VAULT_JWK_PATH:secret/data/securemcp/signing}") String vaultPath) throws Exception {
   JWKSet set;
   if(vaultEnabled) {
     if(vaultToken.isBlank()) throw new IllegalStateException("VAULT_TOKEN is required when Vault signing-key integration is enabled");
     var vault=org.springframework.web.client.RestClient.builder().baseUrl(vaultAddress).defaultHeader("X-Vault-Token",vaultToken).build();
     com.fasterxml.jackson.databind.JsonNode response=vault.get().uri("/v1/"+vaultPath).retrieve().body(com.fasterxml.jackson.databind.JsonNode.class);
     String jwkJson=response.path("data").path("data").path("jwkSet").asText(); if(jwkJson.isBlank())throw new IllegalStateException("Vault KV secret must contain data.jwkSet"); set=JWKSet.parse(jwkJson);
   }
   else if(!jwkSetFile.isBlank()) { set=JWKSet.parse(java.nio.file.Files.readString(java.nio.file.Path.of(jwkSetFile))); }
   else if(!privatePem.isBlank()&&!publicPem.isBlank()) {
     String priv=privatePem.replaceAll("-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\\s","");
     String pub=publicPem.replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s","");
     KeyFactory kf=KeyFactory.getInstance("RSA");
     KeyPair pair=new KeyPair(kf.generatePublic(new java.security.spec.X509EncodedKeySpec(java.util.Base64.getDecoder().decode(pub))),kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(priv))));
     RSAKey key=new RSAKey.Builder((RSAPublicKey)pair.getPublic()).privateKey((RSAPrivateKey)pair.getPrivate()).keyID(UUID.randomUUID().toString()).algorithm(com.nimbusds.jose.JWSAlgorithm.RS256).build();set=new JWKSet(key);
   } else {
     if(!allowEphemeralKeys) throw new IllegalStateException("Persistent signing keys are required; configure Vault or SECUREMCP_JWK_SET_FILE");
     KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(3072);KeyPair pair=g.generateKeyPair();
     RSAKey key=new RSAKey.Builder((RSAPublicKey)pair.getPublic()).privateKey((RSAPrivateKey)pair.getPrivate()).keyID(UUID.randomUUID().toString()).algorithm(com.nimbusds.jose.JWSAlgorithm.RS256).build();set=new JWKSet(key);
   }
   if(set.getKeys().stream().noneMatch(k->k instanceof RSAKey r && r.isPrivate())) throw new IllegalStateException("JWK set must contain one active RSA private signing key");
   if(set.getKeys().stream().filter(k->k instanceof RSAKey r && r.isPrivate()).count()!=1) throw new IllegalStateException("JWK set must contain exactly one active private signing key; keep previous keys public-only");
   return (selector,ctx)->selector.select(set);
 }
 @Bean OAuth2TokenCustomizer<JwtEncodingContext> jwtAudienceCustomizer(@Value("${securemcp.audience}") String audience,JdbcTemplate jdbc){return context->{
   if(!org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) return;
   context.getClaims().audience(java.util.List.of(audience));
   var clientTenants=jdbc.query("select tenant_id from oauth_clients where client_id=?",(rs,n)->rs.getObject(1,java.util.UUID.class),context.getRegisteredClient().getClientId());
   java.util.UUID tenant=clientTenants.isEmpty()?null:clientTenants.get(0);
   if(tenant==null){var userTenants=jdbc.query("select tenant_id from app_users where username=? and enabled=true",(rs,n)->rs.getObject(1,java.util.UUID.class),context.getPrincipal().getName());if(!userTenants.isEmpty())tenant=userTenants.get(0);}
   if(tenant!=null)context.getClaims().claim("tenant_id",tenant.toString());
 };}
 @Bean AuthorizationServerSettings authorizationServerSettings(@Value("${securemcp.issuer}") String issuer){return AuthorizationServerSettings.builder().issuer(issuer).build();}
}
