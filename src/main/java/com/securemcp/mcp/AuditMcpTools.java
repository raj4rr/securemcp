package com.securemcp.mcp;
import com.securemcp.audit.AuditService; import org.springframework.ai.tool.annotation.*; import org.springframework.security.access.prepost.PreAuthorize; import org.springframework.stereotype.Component; import java.util.*;
@Component public class AuditMcpTools {
 private final AuditService audit;public AuditMcpTools(AuditService a){audit=a;}
 @Tool(description="Read recent append-only SecureMCP security audit events. Sensitive event details are restricted to authorized security readers.")
 @PreAuthorize("hasAuthority('SCOPE_security.read')") public List<Map<String,Object>> recentSecurityEvents(@ToolParam(description="Maximum events to return, 1 to 100") int limit){McpSecurity.requireScope("security.read");return audit.recent(Math.min(Math.max(limit,1),100));}
}
