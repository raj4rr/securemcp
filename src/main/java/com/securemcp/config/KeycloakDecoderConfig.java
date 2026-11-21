package com.securemcp.config;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty; import org.springframework.beans.factory.annotation.Value; import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
@Configuration @ConditionalOnProperty(prefix="securemcp.keycloak",name="enabled",havingValue="true")
public class KeycloakDecoderConfig {
 @Bean(name="keycloakJwtDecoder") JwtDecoder keycloakJwtDecoder(@Value("${securemcp.keycloak.issuer-uri}") String issuer,@Value("${securemcp.keycloak.jwks-uri}") String jwks,@Value("${securemcp.keycloak.audience}") String audience){
  NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
  OAuth2TokenValidator<Jwt> issuerValidator=JwtValidators.createDefaultWithIssuer(issuer);
  OAuth2TokenValidator<Jwt> audienceValidator=jwt->jwt.getAudience().contains(audience)?OAuth2TokenValidatorResult.success():OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Required Keycloak audience is missing",""));
  decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerValidator,audienceValidator));return decoder;
 }
}
