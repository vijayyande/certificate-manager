package com.example.dmz.controller;

import com.example.dmz.config.ResponderProperties;
import com.example.dmz.service.ResponderService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * CRL distribution point responder. Mirrors the certificate manager's own
 * {@code GET /api/crl/{caRef}} path so certificates issued with the DMZ host in
 * their CRL distribution point resolve here unchanged. {@code caRef} is either
 * the backend CA id, the CA certificate serial number (hex, the form embedded
 * in issued certificates) or the CA name.
 */
@RestController
@RequestMapping("/api/crl")
@RequiredArgsConstructor
public class CrlResponderController {

    private final ResponderService service;
    private final ResponderProperties properties;

    @GetMapping(value = "/{caRef}", produces = "application/pkix-crl")
    public ResponseEntity<byte[]> crl(@PathVariable String caRef) {
        byte[] der = service.crl(caRef);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/pkix-crl"))
                .header("Cache-Control", "public, max-age=" + properties.getCrlCacheSeconds())
                .body(der);
    }
}
