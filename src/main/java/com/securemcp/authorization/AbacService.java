package com.securemcp.authorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class AbacService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public AbacService(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public Map<String, Object> decide(UUID tenantId, String subject, String action, String resource, Map<String, Object> attributes) {
        var rows = jdbc.query("select policy_key,effect,subject_match,action_match,resource_match,required_attributes from abac_policies where tenant_id=? and enabled=true order by case effect when 'DENY' then 0 else 1 end,created_at", (rs, n) -> {
            Map<String, Object> required;
            try {
                required = mapper.readValue(rs.getString("required_attributes"), new TypeReference<Map<String, Object>>() {
                });
            } catch (Exception e) {
                required = Map.of("__invalid_policy__", true);
            }
            return new Policy(rs.getString("policy_key"), rs.getString("effect"), rs.getString("subject_match"), rs.getString("action_match"), rs.getString("resource_match"), required);
        }, tenantId);
        for (Policy p : rows) {
            if (!pattern(p.action, action) || !pattern(p.resource, resource)) continue;
            if (p.subject != null && !p.subject.equals("*") && !p.subject.equals(subject)) continue;
            if (!matches(p.required, attributes)) continue;
            return Map.of("allowed", p.effect.equals("ALLOW"), "matchedPolicy", p.key, "matchedPolicyEffect", p.effect, "reason", "matching_policy");
        }
        return Map.of("allowed", false, "reason", "default_deny");
    }

    private boolean pattern(String pattern, String value) {
        if (pattern == null || value == null) return false;
        if (pattern.equals("*")) return true;
        if (pattern.endsWith("*")) return value.startsWith(pattern.substring(0, pattern.length() - 1));
        return pattern.equals(value);
    }

    private boolean matches(Map<String, Object> required, Map<String, Object> actual) {
        return required.entrySet().stream().allMatch(e -> Objects.equals(e.getValue(), actual.get(e.getKey())));
    }

    private record Policy(String key, String effect, String subject, String action, String resource,
                          Map<String, Object> required) {
    }
}
