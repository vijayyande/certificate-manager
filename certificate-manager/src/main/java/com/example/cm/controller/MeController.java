package com.example.cm.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/me")
@RequiredArgsConstructor
public class MeController {

    @GetMapping
    public ResponseEntity<Map<String, Object>> me(Authentication authentication) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", authentication.getName());
        body.put("roles", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> authority.startsWith("ROLE_") ? authority.substring(5) : authority)
                .sorted()
                .toList());
        return ResponseEntity.ok(body);
    }
}
