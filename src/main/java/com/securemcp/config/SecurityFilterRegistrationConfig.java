package com.securemcp.config;
import org.springframework.boot.web.servlet.FilterRegistrationBean; import org.springframework.context.annotation.*;
@Configuration public class SecurityFilterRegistrationConfig {
 @Bean FilterRegistrationBean<ApiKeyAuthenticationFilter> apiKeyFilterRegistration(ApiKeyAuthenticationFilter f){FilterRegistrationBean<ApiKeyAuthenticationFilter> b=new FilterRegistrationBean<>(f);b.setEnabled(false);return b;}
 @Bean FilterRegistrationBean<RedisRateLimitFilter> rateLimitFilterRegistration(RedisRateLimitFilter f){FilterRegistrationBean<RedisRateLimitFilter> b=new FilterRegistrationBean<>(f);b.setEnabled(false);return b;}
}
