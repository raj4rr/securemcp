package com.securemcp.api;

import com.securemcp.audit.AuditService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/audit-events")
public class AuditController {
    private final AuditService audit;

    public AuditController(AuditService a) {
        audit = a;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_security.read') or hasAuthority('SCOPE_platform.admin')")
    public List<Map<String, Object>> list(@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        if (size < 1 || size > 200 || page < 0 || page > 100000)
            throw new IllegalArgumentException("Invalid pagination");
        return audit.recent(size, page);
    }
}
