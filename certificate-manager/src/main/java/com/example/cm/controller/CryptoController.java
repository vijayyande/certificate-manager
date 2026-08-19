package com.example.cm.controller;

import com.example.cm.model.dto.KeyAlgorithmInfo;
import com.example.cm.model.dto.KeyDeriveRequest;
import com.example.cm.model.dto.KeyDeriveResult;
import com.example.cm.model.dto.OidInfo;
import com.example.cm.service.CryptoService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Discovery and validation helpers for the supported key algorithms and sizes.
 * Any authenticated user can query them; the UI uses the catalog to render its
 * algorithm/size selects data-driven.
 */
@RestController
@RequestMapping("/api/crypto")
@RequiredArgsConstructor
public class CryptoController {

    private final CryptoService cryptoService;

    @GetMapping("/algorithms")
    public ResponseEntity<List<KeyAlgorithmInfo>> algorithms() {
        return ResponseEntity.ok(cryptoService.keyAlgorithmCatalog());
    }

    @GetMapping("/oids")
    public ResponseEntity<List<OidInfo>> oids() {
        return ResponseEntity.ok(cryptoService.oidCatalog());
    }

    @PostMapping("/derive")
    public ResponseEntity<KeyDeriveResult> derive(@RequestBody KeyDeriveRequest request) {
        return ResponseEntity.ok(cryptoService.deriveKeyParameters(
                request.getKeyAlgorithm(), request.getKeySize()));
    }
}
