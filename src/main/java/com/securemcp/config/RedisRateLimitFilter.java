package com.securemcp.config;
import jakarta.servlet.*; import jakarta.servlet.http.*; import org.springframework.data.redis.core.StringRedisTemplate; import org.springframework.stereotype.Component; import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException; import java.time.Duration;
@Component public class RedisRateLimitFilter extends OncePerRequestFilter {
 private final StringRedisTemplate redis; public RedisRateLimitFilter(StringRedisTemplate r){redis=r;}
 @Override protected boolean shouldNotFilter(HttpServletRequest r){return r.getRequestURI().startsWith("/actuator/health")||! (r.getRequestURI().startsWith("/mcp")||r.getRequestURI().startsWith("/api/")||r.getRequestURI().startsWith("/oauth2/")||r.getRequestURI().equals("/login"));}
 @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
  String ip=req.getRemoteAddr()==null?"unknown":req.getRemoteAddr();long count;
  try{String key="ratelimit:"+ip+":"+(System.currentTimeMillis()/60000);Long n=redis.opsForValue().increment(key);count=n==null?1:n;if(count==1)redis.expire(key,Duration.ofMinutes(2));}
  catch(Exception e){res.sendError(503,"Rate-limit service unavailable");return;}
  if(count>120){res.setHeader("Retry-After","60");res.sendError(429,"Rate limit exceeded");return;}chain.doFilter(req,res);
 }
}
