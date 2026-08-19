package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.model.dto.CaRequest;
import com.example.cm.model.entity.CaEntity;
import com.example.cm.service.CaService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/ca")
@RequiredArgsConstructor
public class CaController {

    private final CaService caService;

    @PostMapping
    public ResponseEntity<ApiResponse> requestCa(@Valid @RequestBody CaRequest request) {
        CaEntity ca = caService.requestCa(request);
        return ResponseEntity.ok(ApiResponse.ok(
                "CA '" + ca.getName() + "' created and activated", ca));
    }

    @GetMapping
    public ResponseEntity<List<CaEntity>> list() {
        return ResponseEntity.ok(caService.listAll());
    }

    @GetMapping("/active")
    public ResponseEntity<List<CaEntity>> listActive() {
        return ResponseEntity.ok(caService.listActive());
    }

    @GetMapping("/{id}")
    public ResponseEntity<CaEntity> get(@PathVariable Long id) {
        return ResponseEntity.ok(caService.get(id));
    }

    @PostMapping("/{id}/revoke")
    public ResponseEntity<ApiResponse> revoke(@PathVariable Long id,
                                              @RequestBody(required = false) Map<String, String> body) {
        String reason = body != null ? body.getOrDefault("reason", "CA revoked") : "CA revoked";
        String by = body != null ? body.getOrDefault("by", "admin") : "admin";
        CaEntity ca = caService.revoke(id, reason, by);
        return ResponseEntity.ok(ApiResponse.ok("CA revoked", ca));
    }

    @PostMapping("/{id}/suspend")
    public ResponseEntity<ApiResponse> suspend(@PathVariable Long id,
                                               @RequestBody(required = false) Map<String, String> body) {
        String by = body != null ? body.getOrDefault("by", "admin") : "admin";
        CaEntity ca = caService.suspend(id, by);
        return ResponseEntity.ok(ApiResponse.ok("CA suspended", ca));
    }

    @PostMapping("/{id}/resume")
    public ResponseEntity<ApiResponse> resume(@PathVariable Long id,
                                              @RequestBody(required = false) Map<String, String> body) {
        String by = body != null ? body.getOrDefault("by", "admin") : "admin";
        CaEntity ca = caService.resume(id, by);
        return ResponseEntity.ok(ApiResponse.ok("CA resumed", ca));
    }

    @GetMapping("/{id}/certificate.pem")
    public ResponseEntity<String> certificatePem(@PathVariable Long id) {
        CaEntity ca = caService.get(id);
        if (ca.getCertificatePem() == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(ca.getCertificatePem());
    }
}
