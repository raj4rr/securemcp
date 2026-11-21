package com.securemcp.config;
import org.springframework.context.annotation.*; import org.springframework.beans.factory.annotation.Value; import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; import org.springframework.security.core.authority.SimpleGrantedAuthority; import org.springframework.security.core.context.SecurityContextHolder;
import java.util.*;
/** STDIO is a local OS-process trust boundary; grant only explicitly configured local scopes. */
@Configuration @Profile("stdio") public class StdioSecurityConfig {
 @Bean InitializingBean stdioPrincipal(@Value("${SECUREMCP_STDIO_SCOPES:security.read}") String scopes){return ()->{
  SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_GLOBAL);
  var authorities=Arrays.stream(scopes.split(",")).map(String::trim).filter(s->!s.isBlank()).map(s->new SimpleGrantedAuthority("SCOPE_"+s)).toList();
  var auth=new UsernamePasswordAuthenticationToken("stdio-local-process",null,authorities);var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(auth);SecurityContextHolder.setContext(context);
 };}
}
