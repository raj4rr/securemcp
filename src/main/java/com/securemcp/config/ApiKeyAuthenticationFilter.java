package com.securemcp.config;
import com.securemcp.identity.ApiKeyService; import jakarta.servlet.*; import jakarta.servlet.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder; import org.springframework.stereotype.Component; import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException; import java.util.*;
@Component public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {
 private final ApiKeyService keys; public ApiKeyAuthenticationFilter(ApiKeyService k){keys=k;}
 @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
  String raw=req.getHeader("X-API-Key"); if(raw!=null&&SecurityContextHolder.getContext().getAuthentication()==null){var key=keys.authenticate(raw);if(key.isPresent()){var k=key.get();var auths=k.scopes().stream().map(s->new SimpleGrantedAuthority("SCOPE_"+s)).toList();var auth=new UsernamePasswordAuthenticationToken("api-key:"+k.id(),null,auths);auth.setDetails(Map.of("tenantId",k.tenantId(),"label",k.label()));SecurityContextHolder.getContext().setAuthentication(auth);}}
  chain.doFilter(req,res);
 }
}
