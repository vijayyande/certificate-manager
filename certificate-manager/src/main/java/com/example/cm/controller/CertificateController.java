package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.model.dto.CsrRequest;
import com.example.cm.model.dto.ManualCertificateRequest;
import com.example.cm.model.dto.RevokeRequest;
import com.example.cm.model.entity.CertificateEntity;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.service.CertificateService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    @PostMapping("/csr")
    public ResponseEntity<ApiResponse> submitCsr(@Valid @RequestBody CsrRequest request) {
        CertificateEntity cert = certificateService.submitCsr(request);
        return ResponseEntity.ok(ApiResponse.ok(
                "CSR for '" + cert.getCommonName() + "' signed and issued", cert));
    }

    @PostMapping("/request")
    public ResponseEntity<ApiResponse> requestCertificate(@Valid @RequestBody ManualCertificateRequest request,
                                                          Authentication authentication) {
        if (request.getRequestedBy() == null || request.getRequestedBy().isBlank()) {
            request.setRequestedBy(authentication.getName());
        }
        boolean adminUser = authentication.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        CertificateEntity cert = certificateService.requestCertificate(request, adminUser);
        return ResponseEntity.ok(ApiResponse.ok(
                "Certificate issued for '" + cert.getCommonName() + "'", cert));
    }

    @GetMapping
    public ResponseEntity<List<CertificateEntity>> list(
            @RequestParam(required = false) String q,
            @RequestParam(required = false) CertificateStatus status,
            @RequestParam(required = false) Long caId) {
        return ResponseEntity.ok(certificateService.search(q, status, caId));
    }

    @GetMapping("/{id}")
    public ResponseEntity<CertificateEntity> get(@PathVariable Long id) {
        return ResponseEntity.ok(certificateService.get(id));
    }

    @GetMapping("/{id}/pem")
    public ResponseEntity<String> getPem(@PathVariable Long id) {
        CertificateEntity cert = certificateService.get(id);
        if (cert.getCertificatePem() == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(cert.getCertificatePem());
    }

    @GetMapping("/{id}/key")
    public ResponseEntity<String> getPrivateKey(@PathVariable Long id, Authentication authentication) {
        CertificateEntity cert = certificateService.get(id);
        if (cert.getKeyStorage() == com.example.cm.model.enums.KeyStorage.PKCS11) {
            return ResponseEntity.badRequest()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"message\":\"The private key is stored on the PKCS#11 device and cannot be exported\"}");
        }
        if (cert.getPrivateKeyPem() == null) {
            return ResponseEntity.notFound().build();
        }
        boolean owner = authentication.getName().equals(cert.getRequestedBy());
        if (!owner) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(cert.getPrivateKeyPem());
    }

    @PostMapping("/{id}/revoke")
    public ResponseEntity<ApiResponse> revoke(@PathVariable Long id, @Valid @RequestBody RevokeRequest request) {
        CertificateEntity cert = certificateService.revoke(id, request);
        return ResponseEntity.ok(ApiResponse.ok("Certificate revoked", cert));
    }

    @PostMapping("/{id}/suspend")
    public ResponseEntity<ApiResponse> suspend(@PathVariable Long id) {
        CertificateEntity cert = certificateService.suspend(id);
        return ResponseEntity.ok(ApiResponse.ok("Certificate suspended", cert));
    }

    @PostMapping("/{id}/resume")
    public ResponseEntity<ApiResponse> resume(@PathVariable Long id) {
        CertificateEntity cert = certificateService.resume(id);
        return ResponseEntity.ok(ApiResponse.ok("Certificate resumed", cert));
    }
}
