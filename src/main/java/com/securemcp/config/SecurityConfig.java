package com.securemcp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

@Configuration @EnableMethodSecurity
public class SecurityConfig {
 private final ApiKeyAuthenticationFilter apiKeys; private final RedisRateLimitFilter rateLimit;
 public SecurityConfig(ApiKeyAuthenticationFilter apiKeys,RedisRateLimitFilter rateLimit){this.apiKeys=apiKeys;this.rateLimit=rateLimit;}
 @Bean @Order(2) SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
   JwtGrantedAuthoritiesConverter scopes=new JwtGrantedAuthoritiesConverter(); scopes.setAuthorityPrefix("SCOPE_");
   JwtAuthenticationConverter converter=new JwtAuthenticationConverter();converter.setJwtGrantedAuthoritiesConverter(scopes);
   http.securityMatcher("/mcp","/mcp/**","/api/**","/actuator/**")
     .csrf(csrf->csrf.ignoringRequestMatchers("/mcp","/mcp/**","/api/**"))
     .authorizeHttpRequests(auth->auth
       .requestMatchers("/actuator/health","/actuator/health/liveness","/actuator/health/readiness","/api/public/**").permitAll()
       .requestMatchers("/actuator/prometheus","/actuator/metrics/**").hasAuthority("SCOPE_security.read")
       .requestMatchers(org.springframework.http.HttpMethod.GET,"/api/v1/audit-events").hasAnyAuthority("SCOPE_security.read","SCOPE_platform.admin")
       .requestMatchers(org.springframework.http.HttpMethod.POST,"/api/v1/policies/decision").hasAuthority("SCOPE_security.read")
       .requestMatchers(org.springframework.http.HttpMethod.POST,"/api/v1/tenants").hasAuthority("SCOPE_platform.admin")
       .requestMatchers(org.springframework.http.HttpMethod.GET,"/api/v1/tenants/*/users").hasAuthority("SCOPE_identity.read")
       .requestMatchers("/api/v1/**").hasAuthority("SCOPE_identity.write")
       .requestMatchers("/mcp","/mcp/**").hasAuthority("SCOPE_security.read")
       .anyRequest().authenticated())
     .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
     .headers(h->h.frameOptions(f->f.deny()).contentTypeOptions(Customizer.withDefaults()))
     .oauth2ResourceServer(oauth->oauth.jwt(jwt->jwt.jwtAuthenticationConverter(converter)))
     .addFilterBefore(rateLimit,org.springframework.security.web.context.SecurityContextHolderFilter.class)
     .addFilterAfter(apiKeys,BearerTokenAuthenticationFilter.class);
   return http.build();
 }
 @Bean @Order(3) SecurityFilterChain fallback(HttpSecurity http) throws Exception {
   http.authorizeHttpRequests(a->a.anyRequest().authenticated()).formLogin(Customizer.withDefaults())
     .addFilterBefore(rateLimit,org.springframework.security.web.context.SecurityContextHolderFilter.class); return http.build();
 }
}
