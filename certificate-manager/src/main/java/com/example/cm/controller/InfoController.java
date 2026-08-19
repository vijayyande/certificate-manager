package com.example.cm.controller;

import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.repository.CaRepository;
import com.example.cm.repository.CertificateRepository;
import com.example.cm.service.CryptoService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/info")
@RequiredArgsConstructor
public class InfoController {

    private final CaRepository caRepository;
    private final CertificateRepository certificateRepository;
    private final CryptoService cryptoService;

    @GetMapping
    public ResponseEntity<Map<String, Object>> summary() {
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("casTotal", caRepository.count());
        counts.put("casActive", caRepository.findByStatus(CertificateStatus.ISSUED).size());
        counts.put("certificatesTotal", certificateRepository.count());
        counts.put("certificatesIssued", certificateRepository.findByStatus(CertificateStatus.ISSUED).size());
        counts.put("certificatesRevoked", certificateRepository.findByStatus(CertificateStatus.REVOKED).size());
        counts.put("certificatesSuspended", certificateRepository.findByStatus(CertificateStatus.SUSPENDED).size());
        counts.put("certificatesPending", certificateRepository.findByStatus(CertificateStatus.PENDING).size());

        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("crlUrlBase", cryptoService.getCrlUrlBase());
        cfg.put("ocspUrl", cryptoService.getOcspUrl());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("counts", counts);
        response.put("config", cfg);
        return ResponseEntity.ok(response);
    }
}
