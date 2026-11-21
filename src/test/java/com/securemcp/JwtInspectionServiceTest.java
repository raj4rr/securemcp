package com.securemcp;
import com.fasterxml.jackson.databind.ObjectMapper; import com.securemcp.jwt.JwtInspectionService; import com.securemcp.audit.AuditService;
import org.junit.jupiter.api.*; import org.springframework.data.redis.core.StringRedisTemplate; import org.springframework.security.oauth2.jwt.*;
import java.net.URI; import java.time.Instant; import java.util.*;
import static org.junit.jupiter.api.Assertions.*; import static org.mockito.Mockito.*;
class JwtInspectionServiceTest {
 private JwtDecoder decoder; private StringRedisTemplate redis; private JwtInspectionService service;
 @BeforeEach void setUp(){decoder=mock(JwtDecoder.class);redis=mock(StringRedisTemplate.class);service=new JwtInspectionService(decoder,new ObjectMapper(),redis,mock(AuditService.class));}
 @Test void decodeMarksClaimsAsUntrusted(){String h=Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes());String p=Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"alice\"}".getBytes());var result=service.decodeUntrusted(h+"."+p+".signature");assertEquals(false,result.get("trusted"));assertEquals("alice",((Map<?,?>)result.get("payload")).get("sub"));verifyNoInteractions(decoder);}
 @Test void malformedJwtIsRejected(){assertThrows(IllegalArgumentException.class,()->service.decodeUntrusted("not-a-jwt"));}
 @Test void validatesSignatureDecoderAndRevocationStatus(){Jwt jwt=Jwt.withTokenValue("signed-token").header("alg","RS256").subject("alice").issuer("https://issuer.example").issuedAt(Instant.now().minusSeconds(10)).expiresAt(Instant.now().plusSeconds(120)).id("id-1").audience(List.of("securemcp-api")).build();when(decoder.decode("signed-token")).thenReturn(jwt);when(redis.hasKey("jwt:revoked:id-1")).thenReturn(false);assertEquals(true,service.validate("signed-token").get("valid"));}
 @Test void revokedJwtIsNotValid(){Jwt jwt=Jwt.withTokenValue("signed-token").header("alg","RS256").subject("alice").issuer("https://issuer.example").issuedAt(Instant.now().minusSeconds(10)).expiresAt(Instant.now().plusSeconds(120)).id("id-1").audience(List.of("securemcp-api")).build();when(decoder.decode("signed-token")).thenReturn(jwt);when(redis.hasKey("jwt:revoked:id-1")).thenReturn(true);assertEquals(false,service.validate("signed-token").get("valid"));}
}
