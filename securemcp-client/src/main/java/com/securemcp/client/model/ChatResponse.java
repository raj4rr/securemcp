package com.securemcp.client.model;

import java.util.Map;

public record ChatResponse(String reply, Map<String, Object> toolCall) {}
