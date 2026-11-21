package com.securemcp.config;

import java.io.IOException;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class McpOriginFilter extends OncePerRequestFilter {
    private final List<String> allowedOrigins; private final List<String> allowedHosts;
    public McpOriginFilter(@Value("${securemcp.mcp.allowed-origins:http://localhost:3000}") List<String> allowedOrigins,@Value("${securemcp.mcp.allowed-hosts:localhost:8080,127.0.0.1:8080}") List<String> allowedHosts) {
        this.allowedOrigins = allowedOrigins; this.allowedHosts=allowedHosts;
    }
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().equals("/mcp") && !request.getRequestURI().startsWith("/mcp/");
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String host=request.getHeader("Host");
        if(host==null||!allowedHosts.contains(host)){response.sendError(HttpServletResponse.SC_FORBIDDEN,"Host not allowed");return;}
        String origin = request.getHeader("Origin");
        if (origin != null && !allowedOrigins.contains(origin)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Origin not allowed");
            return;
        }
        chain.doFilter(request, response);
    }
}
