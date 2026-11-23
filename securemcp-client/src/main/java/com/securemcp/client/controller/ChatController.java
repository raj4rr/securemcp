package com.securemcp.client.controller;

import com.securemcp.client.model.ChatRequest;
import com.securemcp.client.model.ChatResponse;
import com.securemcp.client.service.ChatbotService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
public class ChatController {

    private final ChatbotService chatbotService;

    public ChatController(ChatbotService chatbotService) {
        this.chatbotService = chatbotService;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/api/status")
    @ResponseBody
    public Map<String, Object> getStatus() {
        return chatbotService.getSystemStatus();
    }

    @PostMapping("/api/chat")
    @ResponseBody
    public ChatResponse chat(@RequestBody ChatRequest request) {
        return chatbotService.processMessage(request.message());
    }
}
