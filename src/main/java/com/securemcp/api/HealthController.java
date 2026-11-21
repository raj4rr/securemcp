package com.securemcp.api;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
    @GetMapping("/api/public/status")
    public Map<String, Object> status() { return Map.of("service", "SecureMCP", "status", "UP", "securityNote", "This endpoint contains no sensitive information"); }
}
