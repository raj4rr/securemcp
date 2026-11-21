package com.securemcp.config;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty; import org.springframework.context.annotation.*; import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity; import org.springframework.security.config.http.SessionCreationPolicy; import org.springframework.security.oauth2.jwt.JwtDecoder; import org.springframework.security.web.SecurityFilterChain;
@Configuration @ConditionalOnProperty(prefix="securemcp.keycloak",name="enabled",havingValue="true")
public class KeycloakSecurityChain {
 @Bean @Order(1) SecurityFilterChain keycloakFederationSecurity(HttpSecurity http,@org.springframework.beans.factory.annotation.Qualifier("keycloakJwtDecoder") JwtDecoder decoder,RedisRateLimitFilter rateLimit)throws Exception{
  http.securityMatcher("/api/v1/federation/keycloak/**").csrf(c->c.disable()).authorizeHttpRequests(a->a.anyRequest().authenticated()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).oauth2ResourceServer(o->o.jwt(j->j.decoder(decoder))).addFilterBefore(rateLimit,org.springframework.security.web.context.SecurityContextHolderFilter.class);return http.build();
 }
}
