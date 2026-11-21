package com.securemcp.config;
import org.springframework.beans.factory.annotation.Value; import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.core.*; import org.springframework.security.oauth2.jwt.*;
@Configuration public class JwtDecoderConfig {
 @Bean JwtDecoder jwtDecoder(@Value("${securemcp.issuer}") String issuer,@Value("${securemcp.jwks-uri}") String jwks,@Value("${securemcp.audience}") String audience){
  NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
  OAuth2TokenValidator<Jwt> issuerValidator=JwtValidators.createDefaultWithIssuer(issuer);
  OAuth2TokenValidator<Jwt> audienceValidator=jwt->jwt.getAudience().contains(audience)?OAuth2TokenValidatorResult.success():OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Required audience is missing",""));
  decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerValidator,audienceValidator));return decoder;
 }
}
