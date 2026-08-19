package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.model.entity.CrlEntity;
import com.example.cm.service.CrlService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/crl")
@RequiredArgsConstructor
public class CrlController {

    private final CrlService crlService;

    @PostMapping("/{caId}/generate")
    public ResponseEntity<ApiResponse> generate(@PathVariable Long caId) {
        CrlEntity crl = crlService.generateCrl(caId);
        return ResponseEntity.ok(ApiResponse.ok(
                "CRL #" + crl.getCrlNumber() + " generated for CA " + caId, crl));
    }

    @GetMapping(value = "/{caId}", produces = "application/pkix-crl")
    public ResponseEntity<byte[]> getDer(@PathVariable Long caId) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/pkix-crl"))
                .header("Content-Disposition", "attachment; filename=crl-" + caId + ".der")
                .body(crlService.getCurrentCrlDer(caId));
    }

    @GetMapping(value = "/{caId}/pem", produces = "application/x-pem-file")
    public ResponseEntity<String> getPem(@PathVariable Long caId) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(crlService.getCurrentCrl(caId).getCrlPem());
    }

    @GetMapping("/{caId}/history")
    public ResponseEntity<List<CrlEntity>> history(@PathVariable Long caId) {
        return ResponseEntity.ok(crlService.getCrlHistory(caId));
    }
}
