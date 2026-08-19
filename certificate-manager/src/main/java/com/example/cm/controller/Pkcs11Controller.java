package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.model.dto.Pkcs11Preset;
import com.example.cm.model.dto.Pkcs11SettingsRequest;
import com.example.cm.model.entity.Pkcs11Settings;
import com.example.cm.service.Pkcs11Service;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/pkcs11")
@RequiredArgsConstructor
public class Pkcs11Controller {

    private final Pkcs11Service pkcs11Service;

    @GetMapping
    public ResponseEntity<Pkcs11Settings> get() {
        return ResponseEntity.ok(pkcs11Service.getSettings());
    }

    @GetMapping("/presets")
    public ResponseEntity<List<Pkcs11Preset>> presets() {
        return ResponseEntity.ok(pkcs11Service.listPresets());
    }

    @PostMapping
    public ResponseEntity<ApiResponse> update(@Valid @RequestBody Pkcs11SettingsRequest request) {
        Pkcs11Settings settings = pkcs11Service.updateSettings(request);
        return ResponseEntity.ok(ApiResponse.ok("PKCS#11 settings saved", settings));
    }

    @PostMapping("/test")
    public ResponseEntity<ApiResponse> test() {
        Map<String, Object> result = pkcs11Service.testConnection();
        return ResponseEntity.ok(ApiResponse.ok("PKCS#11 connection OK", result));
    }

    @PostMapping("/disconnect")
    public ResponseEntity<ApiResponse> disconnect() {
        pkcs11Service.disconnect();
        return ResponseEntity.ok(ApiResponse.ok("PKCS#11 provider disconnected", null));
    }
}
