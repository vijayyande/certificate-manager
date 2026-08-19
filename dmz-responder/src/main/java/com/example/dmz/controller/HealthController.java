package com.example.dmz.controller;

import com.example.dmz.service.ResponderService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Liveness probe for the load balancer / orchestrator. Reports cache sizes;
 * the responder never fails this check, even when the backend is down, because
 * it can still serve stale cached data.
 */
@RestController
@RequiredArgsConstructor
public class HealthController {

    private final ResponderService service;

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .body(service.health());
    }
}
